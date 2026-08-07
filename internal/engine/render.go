package engine

import (
	"fmt"
	"strings"
)

// Render produces the CLI text output — the same claim/verdict format the
// M2 MCP tools reuse. Every claim carries its evidence label; no unlabeled
// assertions anywhere (design doc success criterion).
func Render(ans Answer, misses []string, banner string) string {
	var b strings.Builder
	if banner != "" {
		fmt.Fprintf(&b, "⚠ %s\n", banner)
	}
	fmt.Fprintf(&b, "Verdict: %s", ans.Verdict)
	if ans.Capped != "" {
		fmt.Fprintf(&b, "  (capped: %s)", ans.Capped)
	}
	b.WriteString("\n")
	if len(ans.Claims) == 0 {
		b.WriteString("  no rule references these paths — not proven covered\n")
	}
	for i, c := range ans.Claims {
		fmt.Fprintf(&b, "  %d. %s   [%s]\n", i+1, c.Text, c.Evidence)
	}
	if len(misses) > 0 {
		fmt.Fprintf(&b, "  no AST evidence for: %s (try search --resource <type>)\n", strings.Join(misses, ", "))
	}
	return b.String()
}
