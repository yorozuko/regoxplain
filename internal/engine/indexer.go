package engine

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// BuildIndex parses every .rego file under repoPath (per-file tolerant),
// compiles the parseable set as a whole (Rego compiles module-set-wide),
// extracts rules, refs, one-level deps, and the repo-derived vocabulary.
func BuildIndex(repoPath string) (*Index, error) {
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}
	ix := &Index{
		Version:    IndexVersion,
		RepoPath:   abs,
		FileHashes: map[string]string{},
	}

	modules, hashes, errs, err := loadModules(abs)
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", abs, err)
	}
	ix.FileHashes = hashes
	ix.Errors = errs
	if len(modules) == 0 && len(ix.Errors) == 0 {
		return nil, fmt.Errorf("no .rego files found under %s", abs)
	}

	compiler := ast.NewCompiler().WithEnablePrintStatements(true)
	compiler.Compile(modules)
	if compiler.Failed() {
		for _, cerr := range compiler.Errors {
			ix.CompileErrors = append(ix.CompileErrors, cerr.Error())
		}
	}

	// Literals come from the PARSED rules (compiled refs turn path segments
	// into string terms, which would pollute the literal set). Refs come
	// from the COMPILED rules, where imports are resolved to full data.*
	// paths — without that, `import data.lib` callers would never link to
	// their helpers. Correlate by file:row (locations survive compilation).
	litByLoc := map[string][]string{}
	attrsByLoc := map[string][]string{}
	for rel, mod := range modules {
		for _, rule := range mod.Rules {
			litByLoc[locKey(rel, rule.Loc().Row)] = collectLiterals(rule)
			attrsByLoc[locKey(rel, rule.Loc().Row)] = collectAttrs(rule)
		}
	}
	refSource := modules
	if !compiler.Failed() {
		refSource = compiler.Modules
	}

	pkgSet := map[string]bool{}
	for rel, mod := range refSource {
		pkg := mod.Package.Path.String()
		pkgSet[pkg] = true
		doc := annotationDoc(mod)
		for _, rule := range mod.Rules {
			name := string(rule.Head.Name)
			if name == "" && len(rule.Head.Reference) > 0 {
				name = rule.Head.Reference[0].Value.String()
			}
			ri := RuleInfo{
				Path:    pkg + "." + name,
				Package: pkg,
				Name:    name,
				Kind:    ruleKind(name),
				File:    rel,
				Row:     rule.Loc().Row,
				Doc:     doc,
			}
			for _, ref := range collectRefs(rule) {
				ri.Refs = append(ri.Refs, RefInfo{Ref: ref})
			}
			ri.Literals = litByLoc[locKey(rel, ri.Row)]
			ri.Attrs = attrsByLoc[locKey(rel, ri.Row)]
			ix.Rules = append(ix.Rules, ri)
		}
	}
	for p := range pkgSet {
		ix.Packages = append(ix.Packages, p)
	}

	propagateHelperRefs(ix)
	ix.Vocab = buildVocab(ix)
	ix.sortForDeterminism()
	return ix, nil
}

func locKey(file string, row int) string {
	return fmt.Sprintf("%s:%d", file, row)
}

func ruleKind(name string) string {
	switch name {
	case "deny", "violation":
		return name
	case "warn":
		return "warn"
	default:
		return "helper"
	}
}

func annotationDoc(mod *ast.Module) string {
	for _, a := range mod.Annotations {
		if a.Title != "" || a.Description != "" {
			return strings.TrimSpace(a.Title + " " + a.Description)
		}
	}
	return ""
}

// collectRefs walks a rule and gathers every input.* and data.* reference
// string. Extraction is best-effort by design: helpers reached through
// walk()/comprehensions can hide refs — which is exactly why the empty
// search answer must stay honest ("no AST evidence").
func collectRefs(rule *ast.Rule) []string {
	seen := map[string]bool{}
	ast.WalkRefs(rule, func(r ast.Ref) bool {
		// Truncate at the first non-constant segment: compiled rules carry
		// rewritten locals (input.resource_changes[__local11__]) — the
		// constant prefix is the meaningful path.
		s := r.ConstantPrefix().String()
		if strings.HasPrefix(s, "input.") || strings.HasPrefix(s, "data.") || s == "input" {
			seen[s] = true
		}
		return false
	})
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// collectAttrs gathers attribute path segments from every ref in a rule,
// including local-var-rooted refs whose constant prefix is empty. This is
// how rc.change.after.public_access_prevention becomes searchable.
func collectAttrs(rule *ast.Rule) []string {
	seen := map[string]bool{}
	ast.WalkRefs(rule, func(r ast.Ref) bool {
		for i, t := range r {
			if i == 0 {
				continue
			}
			s, ok := t.Value.(ast.String)
			if !ok {
				continue
			}
			v := string(s)
			if len(v) >= 2 && len(v) <= 80 && !strings.ContainsAny(v, " %\n\t") && !strings.HasPrefix(v, "__local") {
				seen[v] = true
			}
		}
		return false
	})
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// collectLiterals gathers identifier-like string constants from a rule body:
// resource types (google_storage_bucket), IAM members (allUsers), role names.
// Message strings (spaces, format verbs) are skipped as noise.
func collectLiterals(rule *ast.Rule) []string {
	// Ref path segments parse as ast.String too (input.resource_changes is
	// Ref[input, "resource_changes"]) — exclude them by pointer identity so
	// only genuine comparison constants survive.
	segs := map[*ast.Term]bool{}
	ast.WalkRefs(rule, func(r ast.Ref) bool {
		for i, t := range r {
			if i == 0 {
				continue
			}
			if _, ok := t.Value.(ast.String); ok {
				segs[t] = true
			}
		}
		return false
	})
	seen := map[string]bool{}
	ast.WalkTerms(rule, func(t *ast.Term) bool {
		if segs[t] {
			return false
		}
		s, ok := t.Value.(ast.String)
		if !ok {
			return false
		}
		v := string(s)
		if len(v) < 3 || len(v) > 80 || strings.ContainsAny(v, " %\n\t") {
			return false
		}
		seen[v] = true
		return false
	})
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// propagateHelperRefs attributes helper-rule refs to their callers, one
// dependency level deep, across package boundaries (eng review round 2 /
// D10 lineage: shared data.lib.* helper packages are the dominant pattern).
// If deny calls lib.bucket_is_public, the helper's input refs count for
// deny, labeled indirect.
func propagateHelperRefs(ix *Index) {
	byPath := map[string][]*RuleInfo{}
	for i := range ix.Rules {
		r := &ix.Rules[i]
		byPath[r.Path] = append(byPath[r.Path], r)
	}
	for i := range ix.Rules {
		r := &ix.Rules[i]
		direct := map[string]bool{}
		for _, ref := range r.Refs {
			direct[ref.Ref] = true
		}
		for _, ref := range r.Refs {
			if !strings.HasPrefix(ref.Ref, "data.") {
				continue
			}
			helpers, ok := byPath[ref.Ref]
			if !ok || ref.Ref == r.Path {
				continue
			}
			r.Deps = append(r.Deps, ref.Ref)
			for _, h := range helpers {
				for _, href := range h.Refs {
					if direct[href.Ref] {
						continue
					}
					// Propagate input refs and EXTERNAL data refs (a helper
					// consulting data.exemptions.* makes its caller depend on
					// that document — the D9 missing-data gate must see it).
					isInput := strings.HasPrefix(href.Ref, "input")
					isExternalData := strings.HasPrefix(href.Ref, "data.") && len(byPath[href.Ref]) == 0
					if isInput || isExternalData {
						direct[href.Ref] = true
						r.Refs = append(r.Refs, RefInfo{Ref: href.Ref, Indirect: true})
					}
				}
				r.IndirectLiterals = dedupe(append(r.IndirectLiterals, h.Literals...))
				r.IndirectAttrs = dedupe(append(r.IndirectAttrs, h.Attrs...))
			}
		}
		r.Deps = dedupe(r.Deps)
	}
}

// buildVocab derives the search vocabulary from the repo itself: tokens of
// ref segments, rule names, and package parts. No hardcoded synonym table.
func buildVocab(ix *Index) []string {
	set := map[string]bool{}
	add := func(s string) {
		for _, tok := range tokenize(s) {
			if len(tok) >= 2 {
				set[tok] = true
			}
		}
	}
	for _, r := range ix.Rules {
		add(r.Name)
		add(r.Package)
		for _, ref := range r.Refs {
			add(ref.Ref)
		}
		for _, lit := range r.Literals {
			add(lit)
		}
		for _, a := range r.Attrs {
			add(a)
		}
		for _, lit := range r.IndirectLiterals {
			add(lit)
		}
		for _, a := range r.IndirectAttrs {
			add(a)
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// tokenize lowercases and splits on every non-alphanumeric boundary and on
// underscores, so "google_storage_bucket" yields google, storage, bucket,
// and the full joined token google_storage_bucket.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	})
	var out []string
	for _, f := range fields {
		f = strings.Trim(f, "_")
		if f == "" {
			continue
		}
		out = append(out, f)
		out = append(out, strings.Split(f, "_")...)
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
