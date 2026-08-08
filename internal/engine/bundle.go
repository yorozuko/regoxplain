package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExplainBundle is the grounded context pack for a rule or file: source,
// one-level dependencies (cross-package), refs, and metadata. In M2 the MCP
// host's model narrates from it; in M1 the CLI prints it — paste-able into
// any chat, and the no-MCP fallback.
type ExplainBundle struct {
	Target   string
	Rules    []RuleInfo
	Sources  map[string]string // file -> content (target + dep files)
	DepPaths []string
}

// BuildBundle assembles the bundle for a rule path (data.pkg.rule) or a
// repo-relative .rego file.
func BuildBundle(ix *Index, target string) (*ExplainBundle, error) {
	b := &ExplainBundle{Target: target, Sources: map[string]string{}}
	byFile := strings.HasSuffix(target, ".rego")

	for _, r := range ix.Rules {
		if (byFile && r.File == target) || (!byFile && r.Path == target) {
			b.Rules = append(b.Rules, r)
		}
	}
	if len(b.Rules) == 0 {
		kind := "rule path"
		if byFile {
			kind = "file"
		}
		return nil, fmt.Errorf("no rules found for %s %q — try `regoxplain search %s`", kind, target, lastSegment(target))
	}

	files := map[string]bool{}
	deps := map[string]bool{}
	for _, r := range b.Rules {
		files[r.File] = true
		for _, d := range r.Deps {
			deps[d] = true
		}
	}
	for _, r := range ix.Rules {
		if deps[r.Path] {
			files[r.File] = true
		}
	}
	for d := range deps {
		b.DepPaths = append(b.DepPaths, d)
	}
	sort.Strings(b.DepPaths)

	for f := range files {
		content, err := os.ReadFile(filepath.Join(ix.RepoPath, f))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		b.Sources[f] = string(content)
	}
	return b, nil
}

// RenderBundle prints the bundle as readable text.
func RenderBundle(b *ExplainBundle) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Explain bundle: %s\n\n", b.Target)
	for _, r := range b.Rules {
		fmt.Fprintf(&sb, "## %s (%s) — %s:%d\n", r.Path, r.Kind, r.File, r.Row)
		if r.Doc != "" {
			fmt.Fprintf(&sb, "doc: %s\n", r.Doc)
		}
		for _, ref := range r.Refs {
			tag := ""
			if ref.Indirect {
				tag = "  (indirect)"
			}
			fmt.Fprintf(&sb, "ref: %s%s\n", ref.Ref, tag)
		}
		sb.WriteString("\n")
	}
	if len(b.DepPaths) > 0 {
		fmt.Fprintf(&sb, "depends on: %s\n\n", strings.Join(b.DepPaths, ", "))
	}
	var files []string
	for f := range b.Sources {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		fmt.Fprintf(&sb, "--- %s ---\n", f)
		// Real per-file line numbers: claims cite file:line, so the bundle
		// must let a reader (or a narrating model) check citations directly.
		for i, line := range strings.Split(strings.TrimRight(b.Sources[f], "\n"), "\n") {
			fmt.Fprintf(&sb, "%4d │ %s\n", i+1, line)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func lastSegment(s string) string {
	s = strings.TrimSuffix(s, ".rego")
	if i := strings.LastIndexAny(s, "./"); i >= 0 {
		return s[i+1:]
	}
	return s
}
