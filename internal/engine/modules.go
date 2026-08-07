package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// newCompiler builds the one compiler configuration used by BOTH indexing
// and evaluation (they must agree, or a repo could index clean and then
// behave differently at eval). Network and runtime builtins are stripped:
// a hostile or trojaned .rego file must never be able to call http.send /
// net.lookup* during eval and exfiltrate terraform plan contents — the
// tool's whole trust model is "local, reads files, no network".
func newCompiler() *ast.Compiler {
	caps := ast.CapabilitiesForThisVersion()
	blocked := map[string]bool{
		"http.send":              true,
		"net.lookup_ip_addr":     true,
		"net.lookup_ip_addr_all": true,
		"opa.runtime":            true,
	}
	var kept []*ast.Builtin
	for _, b := range caps.Builtins {
		if !blocked[b.Name] {
			kept = append(kept, b)
		}
	}
	caps.Builtins = kept
	return ast.NewCompiler().WithCapabilities(caps)
}

// loadModules walks repoPath and parses every .rego file, per-file tolerant.
// Shared by the indexer (which records errors and continues) and the
// evaluator (which requires a clean set before any verdict).
func loadModules(abs string) (modules map[string]*ast.Module, hashes map[string]string, errs []FileError, err error) {
	modules = map[string]*ast.Module{}
	hashes = map[string]string{}
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
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
			errs = append(errs, FileError{File: rel, Err: rerr.Error()})
			return nil
		}
		sum := sha256.Sum256(data)
		hashes[rel] = hex.EncodeToString(sum[:])
		mod, perr := ast.ParseModuleWithOpts(rel, string(data), ast.ParserOptions{ProcessAnnotation: true})
		if perr != nil {
			errs = append(errs, FileError{File: rel, Err: perr.Error()})
			return nil
		}
		modules[rel] = mod
		return nil
	})
	return modules, hashes, errs, err
}
