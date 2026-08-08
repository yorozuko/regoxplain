package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func fixtures(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func newModel(t *testing.T, opts Options) *Model {
	t.Helper()
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	iso := t.TempDir()
	t.Setenv("HOME", iso)
	t.Setenv("XDG_CONFIG_HOME", iso)
	m, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	return m
}

func typeText(m *Model, s string) {
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
}

func key(m *Model, k tea.KeyType) {
	m.Update(tea.KeyMsg{Type: k})
}

// runEvalSync presses ctrl+e and executes the returned command inline,
// feeding the evalDoneMsg back — deterministic async testing.
func runEvalSync(t *testing.T, m *Model) {
	t.Helper()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlE})
	if cmd == nil {
		return
	}
	if !m.evaluating {
		t.Fatal("evaluating flag must be set while the command runs")
	}
	m.Update(cmd())
}

func TestTypingDrivesLiveSearch(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	if len(m.matches) == 0 {
		t.Fatal("typing 'bucket' should match storage rules")
	}
	view := m.View()
	if !strings.Contains(view, "deny_public_bucket.rego") {
		t.Fatalf("view should list the storage deny:\n%s", view)
	}
	if !strings.Contains(view, "probably covered") || !strings.Contains(view, "backed-by-AST only") {
		t.Fatalf("AST-only verdict must be labeled as unverified:\n%s", view)
	}
}

func TestSelectionChangesEvidencePane(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	if len(m.matches) < 2 {
		t.Fatalf("need >=2 matches, got %d", len(m.matches))
	}
	first := m.matches[m.sel].Rule.Path
	key(m, tea.KeyDown)
	second := m.matches[m.sel].Rule.Path
	if first == second {
		t.Fatal("down arrow must move selection")
	}
	if !strings.Contains(m.View(), "Explain bundle: "+second) {
		t.Fatalf("evidence pane should show the selected rule's bundle (%s)", second)
	}
}

func TestEvalRequiresPlan(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlE})
	if cmd != nil {
		t.Fatal("eval must not dispatch without a plan")
	}
	if !strings.Contains(m.View(), "no plan loaded") {
		t.Fatalf("status should explain the missing plan:\n%s", m.status)
	}
}

func TestEvalUpgradesVerdict(t *testing.T) {
	m := newModel(t, Options{
		Repo:     fixtures("policies"),
		PlanPath: fixtures("plans", "violating.json"),
	})
	typeText(m, "allUsers")
	runEvalSync(t, m)
	view := m.View()
	if !strings.Contains(view, "Verdict: covered") || !strings.Contains(view, "verified-by-eval") {
		t.Fatalf("verdict bar should show covered with eval evidence:\n%s", view)
	}
}

func TestEnvelopeModeInTUI(t *testing.T) {
	m := newModel(t, Options{
		Repo:      fixtures("envelope-policies"),
		PlanPath:  fixtures("plans", "sql-noregion.json"),
		InputMode: "envelope:plan",
	})
	typeText(m, "sql region")
	if len(m.matches) == 0 {
		t.Fatal("should match the envelope repo's sql rules")
	}
	runEvalSync(t, m)
	if !strings.Contains(m.View(), "Verdict: covered") {
		t.Fatalf("missing-region deny should fire under envelope:plan:\n%s", m.View())
	}
}

func TestEmptyQueryClears(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	if len(m.matches) == 0 {
		t.Fatal("precondition: matches exist")
	}
	for range "bucket" {
		key(m, tea.KeyBackspace)
	}
	if len(m.matches) != 0 {
		t.Fatalf("clearing the query must clear matches, got %d", len(m.matches))
	}
}

// --- M3 review cases ---------------------------------------------------------

// Editing the query after a verified eval must reset the verdict bar to
// AST-only — the honesty transition both reviewers demanded a test for.
func TestEditAfterEvalResetsEvidenceTag(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies"), PlanPath: fixtures("plans", "violating.json")})
	typeText(m, "allUsers")
	runEvalSync(t, m)
	if !strings.Contains(m.View(), "verified-by-eval") {
		t.Fatal("precondition: eval evidence on screen")
	}
	typeText(m, "x") // query changed
	if strings.Contains(m.View(), "includes verified-by-eval") {
		t.Fatalf("stale eval evidence survived a query edit:\n%s", m.View())
	}
}

// Cursor keys and modifier chords must NOT wipe a completed eval.
func TestCursorKeysPreserveEval(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies"), PlanPath: fixtures("plans", "violating.json")})
	typeText(m, "allUsers")
	runEvalSync(t, m)
	m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m.Update(tea.KeyMsg{Type: tea.KeyRight})
	if !strings.Contains(m.View(), "verified-by-eval") {
		t.Fatalf("cursor movement wiped eval evidence:\n%s", m.View())
	}
}

// A stale eval result (query changed while evaluating) must be discarded.
func TestStaleEvalResultDiscarded(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies"), PlanPath: fixtures("plans", "violating.json")})
	typeText(m, "allUsers")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlE})
	if cmd == nil {
		t.Fatal("expected eval command")
	}
	msg := cmd()           // eval completes for "allUsers"
	typeText(m, " bucket") // but the query moved on
	m.Update(msg)
	if strings.Contains(m.View(), "includes verified-by-eval") {
		t.Fatalf("stale eval result applied to a newer query:\n%s", m.View())
	}
}

// Eval errors must clear prior verified evidence, never coexist with it.
func TestEvalErrorClearsEvidence(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies"), PlanPath: fixtures("plans", "notaplan.json")})
	typeText(m, "allUsers")
	runEvalSync(t, m)
	view := m.View()
	if !strings.Contains(view, "error:") || strings.Contains(view, "includes verified-by-eval") {
		t.Fatalf("eval error must show and must not claim eval evidence:\n%s", view)
	}
}

// Esc clears the query instead of quitting; ctrl+c quits.
func TestEscClearsInsteadOfQuit(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatal("esc must not quit")
	}
	if len(m.matches) != 0 || m.input.Value() != "" {
		t.Fatal("esc must clear query and matches")
	}
}

// Tiny terminals get a graceful placeholder, not overflowing panes.
func TestTinyTerminal(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	m.Update(tea.WindowSizeMsg{Width: 20, Height: 6})
	if !strings.Contains(m.View(), "terminal too small") {
		t.Fatalf("tiny window must render the placeholder:\n%s", m.View())
	}
}

// Selection stays visible: the list window follows the cursor.
func TestListWindowFollowsSelection(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 12}) // bodyH = 4
	typeText(m, "bucket")
	for i := 0; i < len(m.matches)-1; i++ {
		key(m, tea.KeyDown)
	}
	if m.sel < m.listOff || m.sel >= m.listOff+m.bodyHeight() {
		t.Fatalf("selection %d outside window [%d,%d)", m.sel, m.listOff, m.listOff+m.bodyHeight())
	}
}

// Mouse wheel scrolls the evidence pane.
func TestMouseWheelScrollsEvidence(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "bucket")
	if len(m.bundleLines) < 5 {
		t.Fatalf("need a multi-line bundle, got %d lines", len(m.bundleLines))
	}
	m.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
	if m.scroll != 3 {
		t.Fatalf("wheel down should scroll +3, got %d", m.scroll)
	}
	m.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
	if m.scroll != 0 {
		t.Fatalf("wheel up should scroll back, got %d", m.scroll)
	}
}

// Bundle sources carry real per-file line numbers so claims' file:line
// citations are directly checkable in the evidence pane.
func TestBundleShowsLineNumbers(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("policies")})
	typeText(m, "firewall")
	if !strings.Contains(m.bundle, "   1 │ ") {
		t.Fatalf("bundle should number source lines:\n%s", m.bundle[:min(len(m.bundle), 400)])
	}
}

// A broken repo's banner must survive searching — it explains why ctrl+e
// will refuse (found via user screenshot: banner was overwritten).
func TestBrokenRepoBannerPersists(t *testing.T) {
	m := newModel(t, Options{Repo: fixtures("broken-policies")})
	typeText(m, "bucket")
	if !strings.Contains(m.View(), "⚠") || !strings.Contains(m.View(), "eval is blocked") {
		t.Fatalf("broken-repo banner must persist through searches:\n%s", m.View())
	}
}
