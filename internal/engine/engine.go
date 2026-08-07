package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Engine owns the in-memory index and refreshes it when the repo changes.
// It is the source of truth (eng review D4/2A): CLI commands and the future
// MCP server both call Ensure() per operation; the JSON cache on disk only
// warms startup. The mutex makes concurrent MCP tool calls safe — no file
// write races, one rebuild at a time.
type Engine struct {
	RepoPath string

	mu       sync.Mutex
	index    *Index
	compiler *ast.Compiler // retained from the last build (review D2); nil after warm start
}

func New(repoPath string) *Engine {
	return &Engine{RepoPath: repoPath}
}

// Ensure returns a current index: cache-warm if fresh, rebuilt when any
// .rego file hash changed (auto-index is the default; an explicit `index`
// run is an optimization, never a prerequisite).
func (e *Engine) Ensure() (*Index, error) {
	ix, _, err := e.Snapshot()
	return ix, err
}

// Snapshot returns the index and its matching compiler as ONE atomic pair
// under the mutex. Callers must never fetch them separately — a concurrent
// rebuild between two calls would pair a stale index with a newer compiler,
// bypassing Evaluate's hash verification and producing wrong file:line
// citations (M2 review finding). On a cache warm start the compiler is
// built once here and retained, so a long-lived MCP server never re-parses
// the repo per eval call.
func (e *Engine) Snapshot() (*Index, *ast.Compiler, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.index == nil {
		e.index = LoadCache(e.RepoPath)
		e.compiler = nil
	}
	if e.index == nil || e.stale(e.index) {
		ix, compiler, err := buildIndexFull(e.RepoPath)
		if err != nil {
			return nil, nil, err
		}
		_ = ix.SaveCache() // best-effort: in-memory index is authoritative
		e.index = ix
		e.compiler = compiler
		return e.index, e.compiler, nil
	}
	if e.compiler == nil && e.index.CleanCompile() {
		// Warm start: compile once, verify the disk still matches the
		// cached index, and retain.
		abs, err := filepath.Abs(e.RepoPath)
		if err == nil {
			modules, hashes, errs, lerr := loadModules(abs)
			if lerr == nil && len(errs) == 0 && hashesEqual(hashes, e.index.FileHashes) {
				c := newCompiler()
				c.Compile(modules)
				if !c.Failed() {
					e.compiler = c
				}
			}
		}
	}
	return e.index, e.compiler, nil
}

func hashesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// stale recomputes per-file content hashes and compares against the index.
func (e *Engine) stale(ix *Index) bool {
	current := map[string]string{}
	abs, err := filepath.Abs(e.RepoPath)
	if err != nil {
		return true
	}
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rego") {
			return nil
		}
		rel, _ := filepath.Rel(abs, path)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			current[rel] = "unreadable"
			return nil
		}
		sum := sha256.Sum256(data)
		current[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return true
	}
	if len(current) != len(ix.FileHashes) {
		return true
	}
	for rel, h := range current {
		if ix.FileHashes[rel] != h {
			return true
		}
	}
	return false
}
