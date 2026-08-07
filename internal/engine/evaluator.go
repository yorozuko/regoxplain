package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// BodyRef is a rule-body location — the citation target of a fired claim.
type BodyRef struct {
	File string
	Row  int
}

// EvalResult is the outcome of evaluating one entrypoint rule path against
// the plan input(s).
type EvalResult struct {
	RulePath    string
	Fired       bool
	Attributed  bool      // tracer bound the firing to specific bodies
	FiredBodies []BodyRef // which bodies fired (when Attributed)
	Messages    []string  // deny/violation/warn messages produced
	FiredLabel  string    // per-resource mode: which resource fired
}

// EvalOptions configures an evaluation run.
type EvalOptions struct {
	PlanPath         string
	InputMode        string        // raw | wrapped:<key> | per-resource
	DataDir          string        // optional dir of *.json data documents
	QueryPrefix      string        // optional data.<pkg> filter for entrypoints
	AllowMissingData bool          // D9 escape hatch
	OnlyRulePaths    []string      // restrict to these entrypoints (ask --plan)
	Timeout          time.Duration // per-run bound on untrusted Rego (0 = default 30s)
}

// defaultEvalTimeout bounds evaluation of untrusted policies: a pathological
// comprehension over a large plan must not hang the tool indefinitely.
const defaultEvalTimeout = 30 * time.Second

// MissingDataError is the D9 hard error: matched rules reference data.*
// documents that were not supplied, which can invert rule behavior.
type MissingDataError struct{ Paths []string }

func (e *MissingDataError) Error() string {
	return fmt.Sprintf("matched rules reference external data that was not supplied: %s — pass --data <dir> with these documents, or --allow-missing-data to evaluate anyway (verdict will be capped)", strings.Join(e.Paths, ", "))
}

// Evaluate runs entrypoint rules (deny/violation/warn) against a plan.
// Requires a clean whole-set compile (D10): verdicts must describe the same
// policy universe CI enforces. Pass the compiler retained by Engine.Ensure
// (review D2) so no re-parse happens; a nil compiler triggers an internal
// compile that VERIFIES the on-disk repo still matches ix.FileHashes — a
// file changing between index and eval would otherwise make claims cite
// stale rows.
func Evaluate(ctx context.Context, ix *Index, compiler *ast.Compiler, opts EvalOptions) (map[string]*EvalResult, map[string]bool, error) {
	if !ix.CleanCompile() {
		return nil, nil, fmt.Errorf("eval refused: %s", ix.Brokenness())
	}

	if compiler == nil {
		abs, err := filepath.Abs(ix.RepoPath)
		if err != nil {
			return nil, nil, err
		}
		modules, hashes, errs, err := loadModules(abs)
		if err != nil {
			return nil, nil, err
		}
		if len(errs) > 0 {
			return nil, nil, fmt.Errorf("eval refused: repo changed and now has parse errors (%s)", errs[0].File)
		}
		if len(hashes) != len(ix.FileHashes) {
			return nil, nil, fmt.Errorf("eval refused: repo changed since indexing — re-run the command")
		}
		for rel, h := range hashes {
			if ix.FileHashes[rel] != h {
				return nil, nil, fmt.Errorf("eval refused: %s changed since indexing — re-run the command", rel)
			}
		}
		compiler = newCompiler()
		compiler.Compile(modules)
		if compiler.Failed() {
			return nil, nil, fmt.Errorf("eval refused: compile failed: %v", compiler.Errors[0])
		}
	}

	inputs, typesInPlan, err := LoadPlan(opts.PlanPath, opts.InputMode)
	if err != nil {
		return nil, nil, err
	}

	dataDoc, err := loadDataDir(opts.DataDir)
	if err != nil {
		return nil, nil, err
	}

	entrypoints := selectEntrypoints(ix, opts)
	if len(entrypoints) == 0 {
		return nil, nil, fmt.Errorf("no deny/violation/warn entrypoint rules found%s", queryNote(opts.QueryPrefix))
	}

	if missing := missingDataPaths(ix, entrypoints, dataDoc); len(missing) > 0 && !opts.AllowMissingData {
		return nil, nil, &MissingDataError{Paths: missing}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultEvalTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	store := inmem.NewFromObject(dataDoc)
	results := map[string]*EvalResult{}
	for _, path := range entrypoints {
		res := &EvalResult{RulePath: path}
		results[path] = res
		// Prepare ONCE per entrypoint (review D2): per-resource mode
		// multiplies inputs by the thousands; re-preparing the query for
		// each was pure waste.
		pq, prepErr := rego.New(
			rego.Query(path),
			rego.Compiler(compiler),
			rego.Store(store),
		).PrepareForEval(ctx)
		if prepErr != nil {
			return nil, nil, fmt.Errorf("preparing %s: %w", path, prepErr)
		}
		unattributedFired := false
		for _, in := range inputs {
			// Untraced first — tracing disables evaluator fast paths and
			// buffers every step; firing is the rare case, so pay tracing
			// cost only on a re-run of fired pairs.
			rs, evalErr := pq.Eval(ctx, rego.EvalInput(in.Value))
			if evalErr != nil {
				if ctx.Err() != nil {
					return nil, nil, fmt.Errorf("evaluation exceeded %s (raise with --eval-timeout): %w", timeout, ctx.Err())
				}
				return nil, nil, fmt.Errorf("evaluating %s: %w", path, evalErr)
			}
			fired, msgs := firedAndMessages(rs)
			if !fired {
				continue
			}
			res.Fired = true
			res.Messages = append(res.Messages, msgs...)
			if in.Label != "" && res.FiredLabel == "" {
				res.FiredLabel = in.Label
			}
			buf := topdown.NewBufferTracer()
			if _, traceErr := pq.Eval(ctx, rego.EvalInput(in.Value), rego.EvalQueryTracer(buf)); traceErr != nil {
				unattributedFired = true
				continue
			}
			if bodies := attributeBodies(buf, path); len(bodies) > 0 {
				res.FiredBodies = append(res.FiredBodies, bodies...)
			} else {
				unattributedFired = true
			}
		}
		// Attribution is honest only if EVERY fired input was attributed:
		// one unattributed firing could be the matched body, so the verdict
		// layer must degrade rather than claim "a different body fired".
		res.Attributed = len(res.FiredBodies) > 0 && !unattributedFired
		res.FiredBodies = dedupeBodies(res.FiredBodies)
		res.Messages = dedupe(res.Messages)
	}
	return results, typesInPlan, nil
}

func queryNote(prefix string) string {
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf(" under %s", prefix)
}

// selectEntrypoints picks deny/violation/warn rule paths (conftest
// convention), narrowed by --query and/or an explicit rule-path list.
func selectEntrypoints(ix *Index, opts EvalOptions) []string {
	only := map[string]bool{}
	for _, p := range opts.OnlyRulePaths {
		only[p] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range ix.Rules {
		if r.Kind == "helper" {
			continue
		}
		if opts.QueryPrefix != "" && r.Path != opts.QueryPrefix &&
			!strings.HasPrefix(r.Path, opts.QueryPrefix+".") {
			continue // segment boundary: --query data.iam must not select data.iam2.*
		}
		if len(only) > 0 && !only[r.Path] {
			continue
		}
		if !seen[r.Path] {
			seen[r.Path] = true
			out = append(out, r.Path)
		}
	}
	sort.Strings(out)
	return out
}

// firedAndMessages interprets a ResultSet for a deny/violation/warn query:
// a non-empty set/array value means the rule fired.
func firedAndMessages(rs rego.ResultSet) (bool, []string) {
	var msgs []string
	fired := false
	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case []any:
				for _, item := range v {
					fired = true
					msgs = append(msgs, fmt.Sprintf("%v", item))
				}
			case map[string]any:
				if len(v) > 0 {
					fired = true
					for k := range v {
						msgs = append(msgs, k)
					}
				}
			case bool:
				if v {
					fired = true
				}
			case nil:
				// undefined — not fired
			default:
				// Complete rules can produce scalars (deny := "msg", numeric
				// severities). Any defined non-false value means the rule
				// evaluated to something — treating it as quiet would be a
				// silent false negative.
				fired = true
				msgs = append(msgs, fmt.Sprintf("%v", v))
			}
		}
	}
	sort.Strings(msgs)
	return fired, msgs
}

// attributeBodies walks tracer events and returns locations of rule bodies
// that completed (Exit) for the queried rule name — the D8 tracer-only
// attribution. An empty return with a fired result means attribution was
// ambiguous; the verdict layer degrades honestly.
func attributeBodies(buf *topdown.BufferTracer, rulePath string) []BodyRef {
	if buf == nil {
		return nil
	}
	wantName := rulePath[strings.LastIndex(rulePath, ".")+1:]
	var out []BodyRef
	for _, ev := range *buf {
		if ev.Op != topdown.ExitOp {
			continue
		}
		rule, ok := ev.Node.(*ast.Rule)
		if !ok || rule.Head == nil {
			continue
		}
		name := string(rule.Head.Name)
		if name == "" && len(rule.Head.Reference) > 0 {
			name = rule.Head.Reference[0].Value.String()
		}
		if name != wantName {
			continue
		}
		// Match the FULL path, not just the head name: an aggregator rule
		// referencing another package's deny would otherwise attribute
		// foreign bodies to this entrypoint's claims.
		if rule.Module != nil {
			full := rule.Module.Package.Path.String() + "." + name
			if full != rulePath {
				continue
			}
		}
		loc := rule.Loc()
		if loc == nil {
			continue
		}
		out = append(out, BodyRef{File: loc.File, Row: loc.Row})
	}
	return out
}

func dedupeBodies(in []BodyRef) []BodyRef {
	seen := map[BodyRef]bool{}
	var out []BodyRef
	for _, b := range in {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Row < out[j].Row
	})
	return out
}

// loadDataDir merges every *.json file in dir into one data document
// (each file's top-level keys merge at the root, OPA convention).
func loadDataDir(dir string) (map[string]any, error) {
	out := map[string]any{}
	if dir == "" {
		return out, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading --data dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for k, v := range doc {
			// Silent last-wins on a shared key ("exemptions" in two files)
			// can drop an allowlist and invert verdicts — fail loudly, same
			// philosophy as plan-input validation.
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("--data conflict: top-level key %q defined in more than one file (last seen in %s) — merge them into one document", k, e.Name())
			}
			out[k] = v
		}
	}
	return out, nil
}

// MissingData exposes the D9 missing-data computation (used by the CLI to
// annotate capped verdicts when --allow-missing-data is set).
func MissingData(ix *Index, entrypoints []string, dataDir string) ([]string, error) {
	dataDoc, err := loadDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	return missingDataPaths(ix, entrypoints, dataDoc), nil
}

// missingDataPaths finds data.* refs of the selected entrypoint rules that
// are neither rules in the policy set (code) nor present in the supplied
// data document (D9).
func missingDataPaths(ix *Index, entrypoints []string, dataDoc map[string]any) []string {
	rulePaths := map[string]bool{}
	pkgPrefixes := map[string]bool{}
	for _, r := range ix.Rules {
		rulePaths[r.Path] = true
		pkgPrefixes[r.Package] = true
	}
	selected := map[string]bool{}
	for _, p := range entrypoints {
		selected[p] = true
	}
	missing := map[string]bool{}
	for _, r := range ix.Rules {
		if !selected[r.Path] {
			continue
		}
		for _, ref := range r.Refs {
			s := ref.Ref
			if !strings.HasPrefix(s, "data.") {
				continue
			}
			if rulePaths[s] || refIntoPolicy(s, rulePaths, pkgPrefixes) {
				continue
			}
			if dataPathResolves(dataDoc, strings.TrimPrefix(s, "data.")) {
				continue
			}
			missing[s] = true
		}
	}
	out := make([]string, 0, len(missing))
	for s := range missing {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// dataPathResolves walks the FULL ref path into the merged data document.
// Checking only the first segment would let a partial data file ("exemptions"
// present but "exemptions.members" absent) suppress the hard error while
// negation-as-failure quietly inverts the rule — the exact D9 failure mode.
func dataPathResolves(doc map[string]any, path string) bool {
	cur := any(doc)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			// Reached a non-object (array/scalar) before the path ended:
			// the document provides this subtree; deeper access is data
			// shape, not absence.
			return true
		}
		cur, ok = m[seg]
		if !ok {
			return false
		}
	}
	return true
}

// refIntoPolicy reports whether a data.* ref points into the policy set
// itself (a package or a rule, possibly with further path segments).
func refIntoPolicy(ref string, rulePaths, pkgPrefixes map[string]bool) bool {
	for p := range pkgPrefixes {
		if ref == p || strings.HasPrefix(ref, p+".") {
			return true
		}
	}
	for p := range rulePaths {
		if strings.HasPrefix(ref, p+".") {
			return true
		}
	}
	return false
}
