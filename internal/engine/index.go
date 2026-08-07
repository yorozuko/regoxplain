package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// IndexVersion is bumped whenever the cache format changes. A cache file with
// a different version is discarded and rebuilt wholesale — the JSON layout is
// an internal warm-start format, never a public contract (eng review D4/2A).
const IndexVersion = 1

// RefInfo is one input.* or data.* reference extracted from a rule body.
// Indirect refs were inherited from a helper rule one dependency level away
// (cross-package via imports); deeper propagation is out of scope for v1.
type RefInfo struct {
	Ref      string `json:"ref"`
	Indirect bool   `json:"indirect"`
}

// RuleInfo is one rule body in the policy set.
//
//	Path    data.terraform.storage.deny
//	Kind    deny | violation | warn | helper
//	File    repo-relative path, Row 1-based — the claim citation target
type RuleInfo struct {
	Path    string    `json:"path"`
	Package string    `json:"package"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	File    string    `json:"file"`
	Row     int       `json:"row"`
	Refs    []RefInfo `json:"refs"`
	// Literals are identifier-like string constants from the rule body
	// (resource types like google_storage_bucket, members like allUsers).
	// Rego compares input fields against literals, so they carry the
	// searchable resource vocabulary that refs alone would miss.
	Literals []string `json:"literals,omitempty"`
	// Attrs are attribute path segments from every ref in the body,
	// including local-var-rooted ones (rc.change.after.public_access_prevention
	// → public_access_prevention) — how `search --attr` finds rules.
	Attrs []string `json:"attrs,omitempty"`
	// IndirectLiterals/IndirectAttrs were inherited from helper rules one
	// dependency level away; matches through them are labeled indirect.
	IndirectLiterals []string `json:"indirect_literals,omitempty"`
	IndirectAttrs    []string `json:"indirect_attrs,omitempty"`
	Deps             []string `json:"deps,omitempty"`
	Doc              string   `json:"doc,omitempty"`
}

// FileError records a file that failed to parse. Parsing is per-file
// tolerant; these never abort indexing (eng review D10).
type FileError struct {
	File string `json:"file"`
	Err  string `json:"error"`
}

// Index is the in-memory source of truth built from a policy repo.
// The engine owns it; index.json on disk is only a versioned cache.
type Index struct {
	Version       int               `json:"version"`
	RepoPath      string            `json:"repo_path"`
	FileHashes    map[string]string `json:"file_hashes"`
	Packages      []string          `json:"packages"`
	Rules         []RuleInfo        `json:"rules"`
	Errors        []FileError       `json:"errors,omitempty"`
	CompileErrors []string          `json:"compile_errors,omitempty"`
	// Vocab is the repo-derived vocabulary (eng review D7): lowercase tokens
	// from ref segments, rule names, and package parts. ask() expands
	// question tokens through it. Regenerated on every index — cannot rot.
	Vocab []string `json:"vocab"`
}

// CleanCompile reports whether eval is allowed: verdicts must describe the
// same policy universe CI enforces, so any parse or compile error blocks
// eval while search/explain keep working (eng review D10).
func (ix *Index) CleanCompile() bool {
	return len(ix.Errors) == 0 && len(ix.CompileErrors) == 0
}

// Brokenness returns a one-line banner describing parse/compile problems,
// or "" when the repo is clean.
func (ix *Index) Brokenness() string {
	if ix.CleanCompile() {
		return ""
	}
	var parts []string
	for _, e := range ix.Errors {
		parts = append(parts, e.File)
	}
	if len(ix.CompileErrors) > 0 {
		parts = append(parts, fmt.Sprintf("%d compile error(s)", len(ix.CompileErrors)))
	}
	return fmt.Sprintf("repo has problems (%s) — search/explain work, eval is blocked until the set compiles", joinMax(parts, 3))
}

func joinMax(parts []string, max int) string {
	if len(parts) > max {
		return fmt.Sprintf("%s, +%d more", joinMax(parts[:max], max), len(parts)-max)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// sortForDeterminism orders every slice so that marshaling the index twice
// on an unchanged repo yields byte-identical JSON (Go map iteration is
// randomized; encoding/json already sorts map keys).
func (ix *Index) sortForDeterminism() {
	sort.Strings(ix.Packages)
	sort.Strings(ix.Vocab)
	sort.Strings(ix.CompileErrors)
	sort.Slice(ix.Errors, func(i, j int) bool { return ix.Errors[i].File < ix.Errors[j].File })
	sort.Slice(ix.Rules, func(i, j int) bool {
		a, b := ix.Rules[i], ix.Rules[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Row != b.Row {
			return a.Row < b.Row
		}
		return a.Path < b.Path
	})
	for i := range ix.Rules {
		r := &ix.Rules[i]
		sort.Slice(r.Refs, func(a, b int) bool {
			if r.Refs[a].Ref != r.Refs[b].Ref {
				return r.Refs[a].Ref < r.Refs[b].Ref
			}
			return !r.Refs[a].Indirect && r.Refs[b].Indirect
		})
		sort.Strings(r.Literals)
		sort.Strings(r.Attrs)
		sort.Strings(r.IndirectLiterals)
		sort.Strings(r.IndirectAttrs)
		sort.Strings(r.Deps)
	}
}

// CachePath returns ~/.cache/regoxplain/<hash-of-repo-path>/index.json. The
// cache never lives inside the policy repo — the company checkout stays clean.
func CachePath(repoPath string) (string, error) {
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	base := os.Getenv("REGOXPLAIN_CACHE_DIR") // test override
	if base == "" {
		base, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "regoxplain", hex.EncodeToString(sum[:8]), "index.json"), nil
}

// SaveCache writes the index as deterministic JSON (warm-start only).
func (ix *Index) SaveCache() error {
	p, err := CachePath(ix.RepoPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	ix.sortForDeterminism()
	data, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(data, '\n'), 0o644)
}

// LoadCache returns the cached index for repoPath, or nil when absent,
// unreadable, or version-mismatched (all mean: rebuild).
func LoadCache(repoPath string) *Index {
	p, err := CachePath(repoPath)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var ix Index
	if err := json.Unmarshal(data, &ix); err != nil || ix.Version != IndexVersion {
		return nil
	}
	return &ix
}
