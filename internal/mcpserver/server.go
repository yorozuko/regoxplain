// Package mcpserver exposes the regoxplain evidence engine as MCP tools over
// stdio (design doc Milestone 2). The MCP host's model (Copilot, Claude) is
// the narrator; every tool returns the engine's deterministic claims with
// verdict tiers and evidence labels — the model explains, the engine decides.
package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yorozuko/regoxplain/internal/engine"
)

// Server wraps the engine behind MCP tools. One Engine per repo path, cached:
// the engine's own mutex + hash-based staleness make concurrent tool calls
// safe (design 2A), and repeated calls reuse the in-memory index.
type Server struct {
	defaultRepo string

	mu      sync.Mutex
	engines map[string]*engine.Engine
}

// New builds the MCP server wrapper. defaultRepo is used when a tool call
// does not name a repo (Copilot launches the binary in the workspace, so
// cwd is the natural default).
func New(defaultRepo string) *Server {
	return &Server{defaultRepo: defaultRepo, engines: map[string]*engine.Engine{}}
}

func (s *Server) engineFor(repo string) *engine.Engine {
	if repo == "" {
		repo = s.defaultRepo
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eng, ok := s.engines[repo]
	if !ok {
		eng = engine.New(repo)
		s.engines[repo] = eng
	}
	return eng
}

// MCP returns the configured *mcp.Server ready to run on a transport.
func (s *Server) MCP(version string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "regoxplain", Version: version}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "search_policies",
		Description: "Search a Rego/OPA policy repo for rules governing given terraform resources, " +
			"attributes, or free terms. Optionally evaluate matched rules against a terraform plan " +
			"JSON (`terraform show -json` output) for a verified verdict. Every claim carries a " +
			"verdict tier (covered / probably covered / not proven) and an evidence label " +
			"(verified-by-eval / backed-by-AST). Treat the returned verdict as authoritative — " +
			"narrate it, never override it.",
	}, s.searchPolicies)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "explain_rule",
		Description: "Return the grounded context bundle for one policy rule (e.g. data.terraform.storage.deny) " +
			"or one .rego file: its source, helper dependencies (cross-package), extracted refs, and metadata. " +
			"Use this bundle as the ONLY source when explaining a policy — cite the file:line locations it contains.",
	}, s.explainRule)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "eval_against_plan",
		Description: "Evaluate every deny/violation/warn rule in the policy repo against a terraform plan " +
			"JSON (`terraform show -json` output). Reports which rules fired with file:line body attribution. " +
			"Missing external data documents are a hard error (they can invert rule behavior) — " +
			"pass data_dir, or set allow_missing_data only when the user explicitly accepts a capped verdict.",
	}, s.evalAgainstPlan)

	return srv
}

// --- search_policies ---------------------------------------------------------

type searchIn struct {
	Repo             string   `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace"`
	Terms            []string `json:"terms,omitempty" jsonschema:"free search terms, matched literally against indexed refs, names, and constants"`
	Resources        []string `json:"resources,omitempty" jsonschema:"terraform resource types, e.g. google_storage_bucket"`
	Attrs            []string `json:"attrs,omitempty" jsonschema:"attribute names, e.g. members or source_ranges"`
	PlanPath         string   `json:"plan_path,omitempty" jsonschema:"path to terraform show -json output; when set, matched rules are actually evaluated"`
	DataDir          string   `json:"data_dir,omitempty" jsonschema:"directory of *.json external data documents (exemption lists etc.)"`
	AllowMissingData bool     `json:"allow_missing_data,omitempty" jsonschema:"evaluate even when required data.* documents are unsupplied; verdict is capped"`
}

type searchOut struct {
	Verdict string   `json:"verdict"`
	Capped  string   `json:"capped,omitempty"`
	Claims  []string `json:"claims"`
	Banner  string   `json:"banner,omitempty" jsonschema:"non-empty when the repo has parse/compile problems"`
}

func (s *Server) searchPolicies(ctx context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, searchOut, error) {
	eng := s.engineFor(in.Repo)
	ix, err := eng.Ensure()
	if err != nil {
		return nil, searchOut{}, err
	}
	params := engine.SearchParams{Terms: in.Terms, Resources: in.Resources, Attrs: in.Attrs}
	matches := engine.Search(ix, params)

	var evals map[string]*engine.EvalResult
	var typesInPlan map[string]bool
	var allowedMissing []string
	if in.PlanPath != "" && len(matches) > 0 {
		var paths []string
		for _, m := range matches {
			if m.Rule.Kind != "helper" {
				paths = append(paths, m.Rule.Path)
			}
		}
		if len(paths) > 0 {
			cfg, cfgErr := engine.LoadConfig()
			if cfgErr != nil {
				return nil, searchOut{}, cfgErr
			}
			evals, typesInPlan, err = engine.Evaluate(ctx, ix, eng.Compiler(), engine.EvalOptions{
				PlanPath:         in.PlanPath,
				InputMode:        cfg.InputModeFor(repoOrDefault(in.Repo, s.defaultRepo)),
				DataDir:          in.DataDir,
				AllowMissingData: in.AllowMissingData,
				OnlyRulePaths:    paths,
			})
			if err != nil {
				return nil, searchOut{}, err
			}
			if in.AllowMissingData {
				allowedMissing, _ = engine.MissingData(ix, paths, in.DataDir)
			}
		}
	}

	ans := engine.BuildAnswer(ix, matches, evals, typesInPlan, allowedMissing)
	out := searchOut{Verdict: ans.Verdict, Capped: ans.Capped, Banner: ix.Brokenness()}
	for _, c := range ans.Claims {
		out.Claims = append(out.Claims, fmt.Sprintf("%s   [%s]", c.Text, c.Evidence))
	}
	if len(out.Claims) == 0 {
		out.Claims = []string{"no rule references these paths — not proven covered"}
	}
	return textResult(engine.Render(ans, nil, ix.Brokenness())), out, nil
}

// --- explain_rule ------------------------------------------------------------

type explainIn struct {
	Repo   string `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace"`
	Target string `json:"target" jsonschema:"rule path (data.terraform.storage.deny) or repo-relative .rego file"`
}

type explainOut struct {
	Target   string   `json:"target"`
	Rules    []string `json:"rules" jsonschema:"rule path (kind) — file:line for each matching rule body"`
	DependsOn []string `json:"depends_on,omitempty"`
	Bundle   string   `json:"bundle" jsonschema:"the full grounded context: sources, refs, metadata"`
}

func (s *Server) explainRule(_ context.Context, _ *mcp.CallToolRequest, in explainIn) (*mcp.CallToolResult, explainOut, error) {
	if strings.TrimSpace(in.Target) == "" {
		return nil, explainOut{}, fmt.Errorf("target is required: a rule path like data.terraform.storage.deny, or a .rego file")
	}
	ix, err := s.engineFor(in.Repo).Ensure()
	if err != nil {
		return nil, explainOut{}, err
	}
	b, err := engine.BuildBundle(ix, in.Target)
	if err != nil {
		return nil, explainOut{}, err
	}
	out := explainOut{Target: in.Target, DependsOn: b.DepPaths, Bundle: engine.RenderBundle(b)}
	for _, r := range b.Rules {
		out.Rules = append(out.Rules, fmt.Sprintf("%s (%s) — %s:%d", r.Path, r.Kind, r.File, r.Row))
	}
	return textResult(out.Bundle), out, nil
}

// --- eval_against_plan -------------------------------------------------------

type evalIn struct {
	Repo             string `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace"`
	PlanPath         string `json:"plan_path" jsonschema:"path to terraform show -json output"`
	Query            string `json:"query,omitempty" jsonschema:"narrow to one package: data.<pkg>"`
	DataDir          string `json:"data_dir,omitempty" jsonschema:"directory of *.json external data documents"`
	AllowMissingData bool   `json:"allow_missing_data,omitempty" jsonschema:"evaluate even when required data.* documents are unsupplied"`
}

type evalOut struct {
	Fired []string `json:"fired" jsonschema:"rules that fired, with body file:line attribution and messages"`
	Quiet []string `json:"quiet" jsonschema:"entrypoint rules that evaluated without firing"`
}

func (s *Server) evalAgainstPlan(ctx context.Context, _ *mcp.CallToolRequest, in evalIn) (*mcp.CallToolResult, evalOut, error) {
	if strings.TrimSpace(in.PlanPath) == "" {
		return nil, evalOut{}, fmt.Errorf("plan_path is required: run `terraform show -json <planfile> > plan.json` and pass its path")
	}
	eng := s.engineFor(in.Repo)
	ix, err := eng.Ensure()
	if err != nil {
		return nil, evalOut{}, err
	}
	cfg, err := engine.LoadConfig()
	if err != nil {
		return nil, evalOut{}, err
	}
	evals, _, err := engine.Evaluate(ctx, ix, eng.Compiler(), engine.EvalOptions{
		PlanPath:         in.PlanPath,
		InputMode:        cfg.InputModeFor(repoOrDefault(in.Repo, s.defaultRepo)),
		QueryPrefix:      in.Query,
		DataDir:          in.DataDir,
		AllowMissingData: in.AllowMissingData,
	})
	if err != nil {
		return nil, evalOut{}, err
	}

	var out evalOut
	var text strings.Builder
	for _, path := range sortedPaths(evals) {
		ev := evals[path]
		if ev.Fired {
			line := fmt.Sprintf("FIRED %s", path)
			if ev.FiredLabel != "" {
				line += fmt.Sprintf(" (on %s)", ev.FiredLabel)
			}
			for _, b := range ev.FiredBodies {
				line += fmt.Sprintf(" body=%s:%d", b.File, b.Row)
			}
			for _, m := range ev.Messages {
				line += fmt.Sprintf(" msg=%q", m)
			}
			out.Fired = append(out.Fired, line)
		} else {
			out.Quiet = append(out.Quiet, path)
		}
	}
	fmt.Fprintf(&text, "%d/%d entrypoint rules fired [verified-by-eval]\n", len(out.Fired), len(evals))
	for _, l := range out.Fired {
		fmt.Fprintln(&text, l)
	}
	for _, q := range out.Quiet {
		fmt.Fprintf(&text, "quiet %s\n", q)
	}
	return textResult(text.String()), out, nil
}

// --- helpers -----------------------------------------------------------------

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func repoOrDefault(repo, def string) string {
	if repo != "" {
		return repo
	}
	return def
}

func sortedPaths(m map[string]*engine.EvalResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
