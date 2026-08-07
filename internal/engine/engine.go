package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Engine owns the in-memory index and refreshes it when the repo changes.
// It is the source of truth (eng review D4/2A): CLI commands and the future
// MCP server both call Ensure() per operation; the JSON cache on disk only
// warms startup. The mutex makes concurrent MCP tool calls safe — no file
// write races, one rebuild at a time.
type Engine struct {
	RepoPath string

	mu    sync.Mutex
	index *Index
}

func New(repoPath string) *Engine {
	return &Engine{RepoPath: repoPath}
}

// Ensure returns a current index: cache-warm if fresh, rebuilt when any
// .rego file hash changed (auto-index is the default; an explicit `index`
// run is an optimization, never a prerequisite).
func (e *Engine) Ensure() (*Index, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.index == nil {
		e.index = LoadCache(e.RepoPath)
	}
	if e.index != nil && !e.stale(e.index) {
		return e.index, nil
	}
	ix, err := BuildIndex(e.RepoPath)
	if err != nil {
		return nil, err
	}
	if err := ix.SaveCache(); err == nil {
		// cache write best-effort: in-memory index is authoritative
		_ = err
	}
	e.index = ix
	return ix, nil
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
