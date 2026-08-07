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
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yorozuko/regoxplain/internal/engine"
)

// maxTimeoutSeconds caps caller-supplied eval timeouts.
const maxTimeoutSeconds = 300

// Server wraps the engine behind MCP tools. One Engine per canonical repo
// path, cached: the engine's own mutex + hash-based staleness make concurrent
// tool calls safe (design 2A), and repeated calls reuse the in-memory index.
type Server struct {
	defaultRepo string
	// allowOverride gates the per-call `repo` parameter. Tool inputs are
	// model-controlled: without the gate, a prompt-injected host model could
	// point explain_rule at ANY directory and exfiltrate its files, or walk
	// arbitrary trees (M2 review finding). Off by default; the operator
	// opts in with --allow-repo-override for multi-repo use.
	allowOverride bool

	mu      sync.Mutex
	engines map[string]*engine.Engine
}

// New builds the MCP server wrapper. defaultRepo is used when a tool call
// does not name a repo (Copilot launches the binary in the workspace, so
// cwd is the natural default).
func New(defaultRepo string, allowOverride bool) *Server {
	return &Server{
		defaultRepo:   engine.CanonicalPath(defaultRepo),
		allowOverride: allowOverride,
		engines:       map[string]*engine.Engine{},
	}
}

// engineFor resolves the repo for a call. Canonicalization keys the cache:
// ".", "/repo/", and a symlinked spelling must share one Engine (one mutex,
// one rebuild at a time) instead of racing on the same disk cache.
func (s *Server) engineFor(repo string) (*engine.Engine, error) {
	target := s.defaultRepo
	if repo != "" {
		canon := engine.CanonicalPath(repo)
		if canon != s.defaultRepo {
			if !s.allowOverride {
				return nil, fmt.Errorf("repo override to %q is disabled — this server is confined to %s (start with --allow-repo-override to permit other repos)", repo, s.defaultRepo)
			}
			target = canon
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eng, ok := s.engines[target]
	if !ok {
		eng = engine.New(target)
		s.engines[target] = eng
	}
	return eng, nil
}

func evalTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 0 // engine default (30s)
	}
	if seconds > maxTimeoutSeconds {
		seconds = maxTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
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
	Repo             string   `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace (override requires --allow-repo-override)"`
	Terms            []string `json:"terms,omitempty" jsonschema:"free search terms, matched literally against indexed refs, names, and constants"`
	Resources        []string `json:"resources,omitempty" jsonschema:"terraform resource types, e.g. google_storage_bucket"`
	Attrs            []string `json:"attrs,omitempty" jsonschema:"attribute names, e.g. members or source_ranges"`
	PlanPath         string   `json:"plan_path,omitempty" jsonschema:"path to terraform show -json output; when set, matched rules are actually evaluated"`
	DataDir          string   `json:"data_dir,omitempty" jsonschema:"directory of *.json external data documents (exemption lists etc.)"`
	AllowMissingData bool     `json:"allow_missing_data,omitempty" jsonschema:"evaluate even when required data.* documents are unsupplied; verdict is capped"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty" jsonschema:"evaluation time bound in seconds (default 30, max 300)"`
	InputMode        string   `json:"input_mode,omitempty" jsonschema:"override input shape: raw | wrapped:<key> | envelope:<key> (policies importing input.<key>) | per-resource"`
}

type claimOut struct {
	Text     string `json:"text"`
	Evidence string `json:"evidence" jsonschema:"verified-by-eval or backed-by-AST"`
}

type searchOut struct {
	Verdict string     `json:"verdict"`
	Capped  string     `json:"capped,omitempty"`
	Claims  []claimOut `json:"claims"`
	Banner  string     `json:"banner,omitempty" jsonschema:"non-empty when the repo has parse/compile problems"`
}

func (s *Server) searchPolicies(ctx context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, searchOut, error) {
	eng, err := s.engineFor(in.Repo)
	if err != nil {
		return nil, searchOut{}, err
	}
	ix, compiler, err := eng.Snapshot()
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
			mode := in.InputMode
			if mode == "" {
				mode = cfg.InputModeFor(eng.RepoPath)
			}
			evals, typesInPlan, err = engine.Evaluate(ctx, ix, compiler, engine.EvalOptions{
				PlanPath:         in.PlanPath,
				InputMode:        mode,
				DataDir:          in.DataDir,
				AllowMissingData: in.AllowMissingData,
				OnlyRulePaths:    paths,
				Timeout:          evalTimeout(in.TimeoutSeconds),
			})
			if err != nil {
				return nil, searchOut{}, err
			}
			if in.AllowMissingData {
				missing, missErr := engine.MissingData(ix, paths, in.DataDir)
				if missErr == nil {
					allowedMissing = missing
				}
			}
		}
	}

	ans := engine.BuildAnswer(ix, matches, evals, typesInPlan, allowedMissing)
	out := searchOut{Verdict: ans.Verdict, Capped: ans.Capped, Banner: ix.Brokenness(), Claims: []claimOut{}}
	for _, c := range ans.Claims {
		out.Claims = append(out.Claims, claimOut{Text: c.Text, Evidence: c.Evidence})
	}
	if len(out.Claims) == 0 {
		out.Claims = append(out.Claims, claimOut{
			Text:     "no rule references these paths — not proven covered",
			Evidence: engine.EvidenceAST,
		})
	}
	return textResult(engine.Render(ans, nil, ix.Brokenness())), out, nil
}

// --- explain_rule ------------------------------------------------------------

type explainIn struct {
	Repo   string `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace (override requires --allow-repo-override)"`
	Target string `json:"target" jsonschema:"rule path (data.terraform.storage.deny) or repo-relative .rego file"`
}

type explainOut struct {
	Target    string   `json:"target"`
	Rules     []string `json:"rules" jsonschema:"rule path (kind) — file:line for each matching rule body"`
	DependsOn []string `json:"depends_on,omitempty"`
	Bundle    string   `json:"bundle" jsonschema:"the full grounded context: sources, refs, metadata"`
}

func (s *Server) explainRule(_ context.Context, _ *mcp.CallToolRequest, in explainIn) (*mcp.CallToolResult, explainOut, error) {
	if strings.TrimSpace(in.Target) == "" {
		return nil, explainOut{}, fmt.Errorf("target is required: a rule path like data.terraform.storage.deny, or a .rego file")
	}
	eng, err := s.engineFor(in.Repo)
	if err != nil {
		return nil, explainOut{}, err
	}
	ix, _, err := eng.Snapshot()
	if err != nil {
		return nil, explainOut{}, err
	}
	b, err := engine.BuildBundle(ix, in.Target)
	if err != nil {
		return nil, explainOut{}, err
	}
	out := explainOut{Target: in.Target, DependsOn: b.DepPaths, Bundle: engine.RenderBundle(b), Rules: []string{}}
	for _, r := range b.Rules {
		out.Rules = append(out.Rules, fmt.Sprintf("%s (%s) — %s:%d", r.Path, r.Kind, r.File, r.Row))
	}
	return textResult(out.Bundle), out, nil
}

// --- eval_against_plan -------------------------------------------------------

type evalIn struct {
	Repo             string `json:"repo,omitempty" jsonschema:"policy repo path; defaults to the server's workspace (override requires --allow-repo-override)"`
	PlanPath         string `json:"plan_path" jsonschema:"path to terraform show -json output"`
	Query            string `json:"query,omitempty" jsonschema:"narrow to one package: data.<pkg>"`
	DataDir          string `json:"data_dir,omitempty" jsonschema:"directory of *.json external data documents"`
	AllowMissingData bool   `json:"allow_missing_data,omitempty" jsonschema:"evaluate even when required data.* documents are unsupplied"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty" jsonschema:"evaluation time bound in seconds (default 30, max 300)"`
	InputMode        string `json:"input_mode,omitempty" jsonschema:"override input shape: raw | wrapped:<key> | envelope:<key> (policies importing input.<key>) | per-resource"`
}

type firedRule struct {
	Path     string   `json:"path"`
	OnInput  string   `json:"on_input,omitempty" jsonschema:"per-resource mode: which resource fired"`
	Bodies   []string `json:"bodies" jsonschema:"file:line of each fired rule body (tracer-attributed)"`
	Messages []string `json:"messages"`
	Evidence string   `json:"evidence"`
}

type evalOut struct {
	FiredCount int         `json:"fired_count"`
	Total      int         `json:"total"`
	Fired      []firedRule `json:"fired"`
	Quiet      []string    `json:"quiet" jsonschema:"entrypoint rules that evaluated without firing"`
}

func (s *Server) evalAgainstPlan(ctx context.Context, _ *mcp.CallToolRequest, in evalIn) (*mcp.CallToolResult, evalOut, error) {
	if strings.TrimSpace(in.PlanPath) == "" {
		return nil, evalOut{}, fmt.Errorf("plan_path is required: run `terraform show -json <planfile> > plan.json` and pass its path")
	}
	eng, err := s.engineFor(in.Repo)
	if err != nil {
		return nil, evalOut{}, err
	}
	ix, compiler, err := eng.Snapshot()
	if err != nil {
		return nil, evalOut{}, err
	}
	cfg, err := engine.LoadConfig()
	if err != nil {
		return nil, evalOut{}, err
	}
	mode := in.InputMode
	if mode == "" {
		mode = cfg.InputModeFor(eng.RepoPath)
	}
	evals, _, err := engine.Evaluate(ctx, ix, compiler, engine.EvalOptions{
		PlanPath:         in.PlanPath,
		InputMode:        mode,
		QueryPrefix:      in.Query,
		DataDir:          in.DataDir,
		AllowMissingData: in.AllowMissingData,
		Timeout:          evalTimeout(in.TimeoutSeconds),
	})
	if err != nil {
		return nil, evalOut{}, err
	}

	out := evalOut{Total: len(evals), Fired: []firedRule{}, Quiet: []string{}}
	var text strings.Builder
	for _, path := range sortedPaths(evals) {
		ev := evals[path]
		if !ev.Fired {
			out.Quiet = append(out.Quiet, path)
			continue
		}
		fr := firedRule{Path: path, OnInput: ev.FiredLabel, Messages: ev.Messages, Evidence: engine.EvidenceEval, Bodies: []string{}}
		for _, b := range ev.FiredBodies {
			fr.Bodies = append(fr.Bodies, fmt.Sprintf("%s:%d", b.File, b.Row))
		}
		out.Fired = append(out.Fired, fr)
	}
	out.FiredCount = len(out.Fired)

	fmt.Fprintf(&text, "%d/%d entrypoint rules fired [%s]\n", out.FiredCount, out.Total, engine.EvidenceEval)
	for _, fr := range out.Fired {
		fmt.Fprintf(&text, "FIRED %s", fr.Path)
		if fr.OnInput != "" {
			fmt.Fprintf(&text, " (on %s)", fr.OnInput)
		}
		for _, b := range fr.Bodies {
			fmt.Fprintf(&text, " body=%s", b)
		}
		for _, m := range fr.Messages {
			fmt.Fprintf(&text, " msg=%q", m)
		}
		fmt.Fprintln(&text)
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

func sortedPaths(m map[string]*engine.EvalResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
