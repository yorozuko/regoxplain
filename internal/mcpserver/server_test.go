package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func fixtures(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

// session spins up the server on in-memory transports and returns a connected
// client session — the same wire protocol Copilot speaks, no subprocess.
func session(t *testing.T, defaultRepo string) *mcp.ClientSession {
	t.Helper()
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	ct, st := mcp.NewInMemoryTransports()
	srv := New(defaultRepo).MCP("test")
	go func() {
		_ = srv.Run(context.Background(), st)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolsAreListed(t *testing.T) {
	cs := session(t, fixtures("policies"))
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"search_policies": false, "explain_rule": false, "eval_against_plan": false}
	for _, tool := range res.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %s not listed", name)
		}
	}
}

func TestSearchPoliciesWithEval(t *testing.T) {
	cs := session(t, fixtures("policies"))
	res := call(t, cs, "search_policies", map[string]any{
		"resources": []string{"google_storage_bucket_iam_member"},
		"plan_path": fixtures("plans", "violating.json"),
	})
	if res.IsError {
		t.Fatalf("tool error: %s", textOf(t, res))
	}
	text := textOf(t, res)
	if !strings.Contains(text, "Verdict: covered") || !strings.Contains(text, "verified-by-eval") {
		t.Fatalf("want covered verdict with eval evidence:\n%s", text)
	}
	// Structured output must carry the same verdict.
	sc, err := json.Marshal(res.StructuredContent)
	if err != nil || !strings.Contains(string(sc), `"verdict":"covered"`) {
		t.Fatalf("structured output missing verdict: %s (%v)", sc, err)
	}
}

func TestSearchPoliciesDefaultRepoAndOverride(t *testing.T) {
	// Default repo is the fixture repo; override points at the scalar repo.
	cs := session(t, fixtures("policies"))
	res := call(t, cs, "search_policies", map[string]any{"terms": []string{"pubsub"}})
	if !strings.Contains(textOf(t, res), "not proven") {
		t.Fatalf("default repo has no pubsub rules — want not proven:\n%s", textOf(t, res))
	}
	res2 := call(t, cs, "search_policies", map[string]any{
		"repo":  fixtures("scalar-policies"),
		"terms": []string{"pubsub"},
	})
	if !strings.Contains(textOf(t, res2), "deny") {
		t.Fatalf("override repo should match its scalar deny:\n%s", textOf(t, res2))
	}
}

func TestExplainRuleBundle(t *testing.T) {
	cs := session(t, fixtures("policies"))
	res := call(t, cs, "explain_rule", map[string]any{"target": "data.terraform.network.deny"})
	if res.IsError {
		t.Fatalf("tool error: %s", textOf(t, res))
	}
	text := textOf(t, res)
	for _, want := range []string{"deny_open_firewall.rego", "helpers.rego", "firewall_is_open"} {
		if !strings.Contains(text, want) {
			t.Fatalf("bundle missing %q:\n%s", want, text[:min(len(text), 300)])
		}
	}
}

func TestExplainRuleErrors(t *testing.T) {
	cs := session(t, fixtures("policies"))
	res := call(t, cs, "explain_rule", map[string]any{"target": "data.nope.deny"})
	if !res.IsError {
		t.Fatal("unknown rule must surface as a tool error")
	}
	res2 := call(t, cs, "explain_rule", map[string]any{"target": ""})
	if !res2.IsError {
		t.Fatal("empty target must surface as a tool error")
	}
}

func TestEvalAgainstPlanAndDataGate(t *testing.T) {
	cs := session(t, fixtures("policies"))
	// Missing data must be a hard tool error naming the document (D9).
	res := call(t, cs, "eval_against_plan", map[string]any{
		"plan_path": fixtures("plans", "violating.json"),
		"query":     "data.terraform.iam",
	})
	if !res.IsError || !strings.Contains(textOf(t, res), "data.exemptions") {
		t.Fatalf("missing data must error and name the document:\n%s", textOf(t, res))
	}
	// With data supplied, the iam deny fires with attribution.
	res2 := call(t, cs, "eval_against_plan", map[string]any{
		"plan_path": fixtures("plans", "violating.json"),
		"query":     "data.terraform.iam",
		"data_dir":  fixtures("data"),
	})
	if res2.IsError {
		t.Fatalf("eval with data failed: %s", textOf(t, res2))
	}
	text := textOf(t, res2)
	if !strings.Contains(text, "FIRED data.terraform.iam.deny") || !strings.Contains(text, "body=") {
		t.Fatalf("want fired rule with body attribution:\n%s", text)
	}
}

func TestEvalWrongPlanFileError(t *testing.T) {
	cs := session(t, fixtures("policies"))
	res := call(t, cs, "eval_against_plan", map[string]any{
		"plan_path": fixtures("plans", "notaplan.json"),
	})
	if !res.IsError || !strings.Contains(textOf(t, res), "not a terraform plan") {
		t.Fatalf("wrong plan file must error with the named reason:\n%s", textOf(t, res))
	}
}

// TestConcurrentToolCalls is the design's race test: parallel tool calls
// against one server share cached engines; the engine mutex plus in-memory
// staleness checks must keep this safe. Run under -race.
func TestConcurrentToolCalls(t *testing.T) {
	cs := session(t, fixtures("policies"))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var res *mcp.CallToolResult
			var err error
			switch n % 3 {
			case 0:
				res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
					Name: "search_policies", Arguments: map[string]any{"terms": []string{"bucket"}}})
			case 1:
				res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
					Name: "explain_rule", Arguments: map[string]any{"target": "data.terraform.storage.deny"}})
			default:
				res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{
					Name: "eval_against_plan", Arguments: map[string]any{
						"plan_path": fixtures("plans", "violating.json"),
						"query":     "data.terraform.storage"}})
			}
			if err != nil || res == nil || res.IsError {
				t.Errorf("concurrent call %d failed: %v %s", n, err, textOf(t, res))
			}
		}(i)
	}
	wg.Wait()
}
