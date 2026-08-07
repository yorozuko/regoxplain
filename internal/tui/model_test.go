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
	key(m, tea.KeyCtrlE)
	if m.evalRan {
		t.Fatal("eval must not run without a plan")
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
	key(m, tea.KeyCtrlE)
	if !m.evalRan {
		t.Fatalf("eval should have run: err=%s status=%s", m.err, m.status)
	}
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
	key(m, tea.KeyCtrlE)
	if !m.evalRan {
		t.Fatalf("envelope eval should run: err=%s", m.err)
	}
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
