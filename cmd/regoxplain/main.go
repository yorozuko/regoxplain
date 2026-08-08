// regoxplain — grounded Rego policy comprehension for terraform gates.
//
// The engine decides, the LLM (later, via MCP) narrates: every coverage
// claim is backed by AST-index lookup or real policy evaluation, labeled
// with its evidence. See the design doc for the answer model.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/yorozuko/regoxplain/internal/engine"
	"github.com/yorozuko/regoxplain/internal/mcpserver"
	"github.com/yorozuko/regoxplain/internal/tui"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "index":
		err = cmdIndex(args)
	case "search":
		err = cmdSearch(args, nil)
	case "ask":
		err = cmdAsk(args)
	case "eval":
		err = cmdEval(args)
	case "explain":
		err = cmdExplain(args)
	case "mcp":
		err = cmdMCP(args)
	case "tui":
		err = cmdTUI(args)
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "regoxplain: %v\n", err)
		os.Exit(1)
	}
}

// version is stamped by the Makefile / release workflow via
// -ldflags "-X main.version=...". The fallback marks unstamped dev builds
// so `regoxplain version` never contradicts the VERSION file.
var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `regoxplain — grounded Rego policy comprehension for terraform gates

usage:
  regoxplain index   [--repo <path>]
  regoxplain search  [terms...] [--repo] [--resource t1,t2] [--attr a1,a2] [--plan plan.json] [--data dir] [--allow-missing-data]
  regoxplain ask     "<question>" [--repo] [--plan plan.json] [--data dir] [--allow-missing-data]
  regoxplain eval    --plan plan.json [--repo] [--query data.<pkg>] [--data dir] [--allow-missing-data]
  regoxplain explain <rule-path|file.rego> [--repo]
  regoxplain mcp     [--repo <path>]   # MCP stdio server for Copilot/Claude
  regoxplain tui     [--repo] [--plan plan.json] [--input-mode m] [--data dir]
`)
}

type common struct {
	repo             string
	plan             string
	dataDir          string
	query            string
	allowMissingData bool
	evalTimeout      time.Duration
	inputMode        string
}

func commonFlags(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.repo, "repo", ".", "policy repo path")
	fs.StringVar(&c.plan, "plan", "", "terraform show -json plan file")
	fs.StringVar(&c.dataDir, "data", "", "directory of *.json data documents")
	fs.StringVar(&c.query, "query", "", "narrow to a package: data.<pkg>")
	fs.BoolVar(&c.allowMissingData, "allow-missing-data", false, "evaluate even when data.* refs are unsupplied (verdict capped)")
	fs.DurationVar(&c.evalTimeout, "eval-timeout", 30*time.Second, "bound on policy evaluation time")
	fs.StringVar(&c.inputMode, "input-mode", "", "override input shape: raw | wrapped:<key> | envelope:<key> | per-resource")
	return c
}

func cmdIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	c := commonFlags(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	ix, err := engine.New(c.repo).Ensure()
	if err != nil {
		return err
	}
	fmt.Printf("indexed %d rules in %d packages (%d files)\n", len(ix.Rules), len(ix.Packages), len(ix.FileHashes))
	if banner := ix.Brokenness(); banner != "" {
		fmt.Printf("⚠ %s\n", banner)
		for _, e := range ix.Errors {
			fmt.Printf("  parse error: %s: %s\n", e.File, e.Err)
		}
		for _, ce := range ix.CompileErrors {
			fmt.Printf("  compile error: %s\n", ce)
		}
	}
	return nil
}

func cmdSearch(args []string, presetTerms []string) error {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	c := commonFlags(fs)
	resources := fs.String("resource", "", "comma-separated resource types (e.g. google_storage_bucket)")
	attrs := fs.String("attr", "", "comma-separated attribute names (e.g. members)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	terms := append(presetTerms, fs.Args()...)
	params := engine.SearchParams{
		Terms:     terms,
		Resources: splitCSV(*resources),
		Attrs:     splitCSV(*attrs),
	}
	cfg, err := engine.LoadConfig()
	if err != nil {
		return err
	}
	eng := engine.New(c.repo)
	ix, compiler, err := eng.Snapshot()
	if err != nil {
		return err
	}
	return runSearch(c, cfg, ix, compiler, params, nil)
}

func cmdAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ExitOnError)
	c := commonFlags(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf(`usage: regoxplain ask "<question>"`)
	}
	question := strings.Join(fs.Args(), " ")

	cfg, err := engine.LoadConfig()
	if err != nil {
		return err
	}
	eng := engine.New(c.repo)
	ix, compiler, err := eng.Snapshot()
	if err != nil {
		return err
	}
	terms, misses := engine.AskTokens(ix, cfg.Aliases, question)
	if len(terms) == 0 {
		fmt.Printf("Verdict: %s\n  no AST evidence for: %s (try search --resource <type>)\n",
			engine.VerdictNotProven, strings.Join(misses, ", "))
		return nil
	}
	// Reuse the loaded config and index — a second Ensure would re-walk
	// and re-hash the whole repo for nothing.
	return runSearch(c, cfg, ix, compiler, engine.SearchParams{Terms: terms}, misses)
}

func runSearch(c *common, cfg *engine.Config, ix *engine.Index, compiler *ast.Compiler, params engine.SearchParams, misses []string) error {
	matches := engine.Search(ix, params)

	var evals map[string]*engine.EvalResult
	var typesInPlan map[string]bool
	var allowedMissing []string
	if c.plan != "" && len(matches) > 0 {
		var paths []string
		for _, m := range matches {
			if m.Rule.Kind != "helper" {
				paths = append(paths, m.Rule.Path)
			}
		}
		if len(paths) > 0 {
			opts := engine.EvalOptions{
				PlanPath:         c.plan,
				InputMode:        cfg.InputModeFor(c.repo),
				DataDir:          c.dataDir,
				QueryPrefix:      c.query,
				AllowMissingData: c.allowMissingData,
				OnlyRulePaths:    paths,
				Timeout:          c.evalTimeout,
			}
			var err error
			evals, typesInPlan, err = engine.Evaluate(context.Background(), ix, compiler, opts)
			if err != nil {
				return err
			}
			if c.allowMissingData {
				allowedMissing = missingForDisplay(ix, paths, c.dataDir)
			}
		}
	}

	ans := engine.BuildAnswer(ix, matches, evals, typesInPlan, allowedMissing)
	fmt.Print(engine.Render(ans, misses, ix.Brokenness()))
	return nil
}

func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	c := commonFlags(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if c.plan == "" {
		return fmt.Errorf("eval requires --plan <tfplan.json>")
	}
	cfg, err := engine.LoadConfig()
	if err != nil {
		return err
	}
	ix, compiler, err := engine.New(c.repo).Snapshot()
	if err != nil {
		return err
	}
	opts := engine.EvalOptions{
		PlanPath:         c.plan,
		InputMode:        c.modeOr(cfg),
		DataDir:          c.dataDir,
		QueryPrefix:      c.query,
		AllowMissingData: c.allowMissingData,
		Timeout:          c.evalTimeout,
	}
	evals, _, err := engine.Evaluate(context.Background(), ix, compiler, opts)
	if err != nil {
		return err
	}
	fired := 0
	for _, path := range sortedKeys(evals) {
		ev := evals[path]
		if ev.Fired {
			fired++
			label := ""
			if ev.FiredLabel != "" {
				label = fmt.Sprintf(" (on %s)", ev.FiredLabel)
			}
			fmt.Printf("FIRED  %s%s   [%s]\n", path, label, engine.EvidenceEval)
			for _, b := range ev.FiredBodies {
				fmt.Printf("       body %s:%d\n", b.File, b.Row)
			}
			for _, msg := range ev.Messages {
				fmt.Printf("       msg: %s\n", msg)
			}
		} else {
			fmt.Printf("quiet  %s   [%s]\n", path, engine.EvidenceEval)
		}
	}
	fmt.Printf("%d/%d entrypoint rules fired\n", fired, len(evals))
	return nil
}

// cmdMCP runs the Milestone 2 stdio MCP server: the host (Copilot, Claude)
// launches this as a subprocess and narrates over the engine's grounded
// evidence. No port, no daemon — JSON-RPC over stdin/stdout.
func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	repo := fs.String("repo", ".", "policy repo the server is confined to")
	allowOverride := fs.Bool("allow-repo-override", false, "permit tool calls to name other repos (model-controlled — opt in deliberately)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	srv := mcpserver.New(*repo, *allowOverride)
	return srv.MCP(version).Run(context.Background(), &mcp.StdioTransport{})
}

// cmdTUI runs the Milestone 3 terminal interface — the frontend a workplace
// cannot disable. Live AST search; ctrl+e for verified evaluation.
func cmdTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	c := commonFlags(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	m, err := tui.New(tui.Options{
		Repo:             c.repo,
		PlanPath:         c.plan,
		InputMode:        c.inputMode,
		DataDir:          c.dataDir,
		AllowMissingData: c.allowMissingData,
		EvalTimeout:      c.evalTimeout,
	})
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	c := commonFlags(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: regoxplain explain <rule-path|file.rego>")
	}
	ix, err := engine.New(c.repo).Ensure()
	if err != nil {
		return err
	}
	b, err := engine.BuildBundle(ix, fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Print(engine.RenderBundle(b))
	return nil
}

// valueFlags are the flags that consume a following argument. Needed by
// reorderArgs to keep "--repo ." together when hoisting flags.
var valueFlags = map[string]bool{
	"repo": true, "plan": true, "data": true, "query": true,
	"eval-timeout": true, "resource": true, "attr": true, "input-mode": true,
}

// reorderArgs hoists flags in front of positional arguments. Go's stdlib
// flag package stops parsing at the first positional, so the natural
// invocation `explain data.pkg.deny --repo .` would otherwise fail with a
// usage error (and `ask "question" --plan x` would swallow the flags into
// the question text).
func reorderArgs(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // --repo=. carries its value inline
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, pos...)
}

// modeOr resolves the input mode: explicit flag beats per-repo config.
func (c *common) modeOr(cfg *engine.Config) string {
	if c.inputMode != "" {
		return c.inputMode
	}
	return cfg.InputModeFor(c.repo)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys(m map[string]*engine.EvalResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// missingForDisplay re-derives the missing data paths for the capped-verdict
// annotation when --allow-missing-data was used.
func missingForDisplay(ix *engine.Index, paths []string, dataDir string) []string {
	missing, err := engine.MissingData(ix, paths, dataDir)
	if err != nil {
		return nil
	}
	return missing
}
