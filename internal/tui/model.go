// Package tui is the Milestone 3 terminal interface — promoted from
// "optional future" after work's org policy blocked MCP in Copilot: the
// terminal is the one interface a workplace cannot disable. Pure frontend:
// every answer on screen comes from the same engine calls the CLI and MCP
// server use, evidence labels included.
//
// Loop discipline (M3 review): Update never blocks — evaluation runs as a
// tea.Cmd and stale results are discarded; View is a pure render of state
// precomputed in Update (no engine or filesystem work per frame). The
// snapshot is taken once and refreshed only on ctrl+r or before eval.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/yorozuko/regoxplain/internal/engine"
)

// Options configures the TUI session.
type Options struct {
	Repo             string
	PlanPath         string
	InputMode        string // resolved: flag override or per-repo config
	DataDir          string
	AllowMissingData bool
	EvalTimeout      time.Duration
}

// evalDoneMsg carries an async evaluation result back into Update. The query
// field lets Update discard results that no longer match the screen.
type evalDoneMsg struct {
	query          string
	evals          map[string]*engine.EvalResult
	types          map[string]bool
	allowedMissing []string
	err            error
}

const minWidth, minHeight = 40, 10

// Model is the Bubble Tea model.
type Model struct {
	opts Options
	eng  *engine.Engine
	cfg  *engine.Config

	// snapshot cached at construction; refreshed on ctrl+r and before eval.
	ix       *engine.Index
	compiler *ast.Compiler

	banner    string // repo parse/compile problems — persistent, never overwritten
	input     textinput.Model
	lastQuery string
	matches   []engine.Match
	sel       int
	listOff   int // match-list window offset so the selection stays visible
	scroll    int // evidence pane scroll offset

	bundle      string // precomputed evidence text for the selected match
	bundleLines []string

	answer     engine.Answer
	evaluating bool

	status string
	err    string
	width  int
	height int
}

func New(opts Options) (*Model, error) {
	cfg, err := engine.LoadConfig()
	if err != nil {
		return nil, err
	}
	if opts.InputMode == "" {
		opts.InputMode = cfg.InputModeFor(opts.Repo)
	}
	eng := engine.New(opts.Repo)
	ix, compiler, err := eng.Snapshot()
	if err != nil {
		return nil, err
	}
	ti := textinput.New()
	ti.Placeholder = "type to search policies (free text — repo vocabulary)"
	ti.Focus()
	ti.Prompt = "> "
	m := &Model{
		opts:     opts,
		eng:      eng,
		cfg:      cfg,
		ix:       ix,
		compiler: compiler,
		input:    ti,
		status:   "ready — type to search · ↑/↓ select · ctrl+e evaluate · ctrl+r refresh repo · pgup/pgdn scroll · esc clear · ctrl+c quit",
	}
	m.banner = ix.Brokenness()
	return m, nil
}

func (m *Model) Init() tea.Cmd { return textinput.Blink }

// Update implements tea.Model. It never blocks: evaluation is dispatched as
// a command and lands back as evalDoneMsg.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case evalDoneMsg:
		m.evaluating = false
		if msg.query != strings.TrimSpace(m.input.Value()) {
			m.status = "evaluation finished for an older query — press ctrl+e to re-run"
			return m, nil
		}
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "evaluation failed"
			return m, nil
		}
		m.err = ""
		m.answer = engine.BuildAnswer(m.ix, m.matches, msg.evals, msg.types, msg.allowedMissing)
		m.status = fmt.Sprintf("evaluated against %s [%s]", m.opts.PlanPath, m.opts.InputMode)
		return m, nil

	case tea.MouseMsg:
		// Wheel scrolls the evidence pane — pgup/pgdn work too, but the
		// wheel is what hands reach for.
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.scroll = max(0, m.scroll-3)
		case tea.MouseButtonWheelDown:
			m.scroll = min(max(0, len(m.bundleLines)-1), m.scroll+3)
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEsc:
			// Esc clears (fzf convention); an accidental Esc must not
			// destroy the session. Quit stays on ctrl+c.
			m.input.SetValue("")
			m.search()
			return m, nil
		case tea.KeyUp:
			if m.sel > 0 {
				m.sel--
				m.afterSelectionChange()
			}
			return m, nil
		case tea.KeyDown:
			if m.sel < len(m.matches)-1 {
				m.sel++
				m.afterSelectionChange()
			}
			return m, nil
		case tea.KeyPgUp:
			m.scroll = max(0, m.scroll-10)
			return m, nil
		case tea.KeyPgDown:
			m.scroll = min(max(0, len(m.bundleLines)-1), m.scroll+10)
			return m, nil
		case tea.KeyCtrlR:
			m.refreshSnapshot()
			return m, nil
		case tea.KeyCtrlE:
			return m, m.startEval()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.search()
		return m, cmd
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// refreshSnapshot re-reads the repo (the only moment the TUI touches disk
// outside eval) and re-runs the current query against the fresh index.
func (m *Model) refreshSnapshot() {
	ix, compiler, err := m.eng.Snapshot()
	if err != nil {
		m.err = err.Error()
		return
	}
	m.ix, m.compiler = ix, compiler
	m.banner = ix.Brokenness()
	m.lastQuery = "\x00" // force re-search
	m.search()
	m.status = "repo refreshed"
}

// search runs the live AST-backed query against the CACHED snapshot. It is
// a no-op when the query text is unchanged, so cursor keys and modifier
// chords cannot wipe a completed evaluation (M3 review).
func (m *Model) search() {
	q := strings.TrimSpace(m.input.Value())
	if q == m.lastQuery {
		return
	}
	m.lastQuery = q
	m.err = ""
	m.sel, m.listOff, m.scroll = 0, 0, 0

	if q == "" {
		m.matches = nil
		m.answer = engine.Answer{}
		m.bundle, m.bundleLines = "", nil
		m.status = "type to search"
		return
	}
	terms, misses := engine.AskTokens(m.ix, m.cfg.Aliases, q)
	if len(terms) == 0 {
		m.matches = nil
		m.answer = engine.Answer{Verdict: engine.VerdictNotProven}
		m.bundle, m.bundleLines = "", nil
		m.status = "no AST evidence for: " + strings.Join(misses, ", ")
		return
	}
	m.matches = engine.Search(m.ix, engine.SearchParams{Terms: terms})
	m.answer = engine.BuildAnswer(m.ix, m.matches, nil, nil, nil)
	m.afterSelectionChange()
	m.status = fmt.Sprintf("%d matches — ctrl+e to evaluate against plan", len(m.matches))
	if len(misses) > 0 {
		m.status += " · no AST evidence for: " + strings.Join(misses, ", ")
	}
}

// afterSelectionChange precomputes the evidence pane from the SAME snapshot
// that produced the matches (View stays pure; panes never mix repo states).
func (m *Model) afterSelectionChange() {
	m.scroll = 0
	if len(m.matches) == 0 {
		m.bundle, m.bundleLines = "", nil
		return
	}
	b, err := engine.BuildBundle(m.ix, m.matches[m.sel].Rule.Path)
	if err != nil {
		m.bundle = err.Error()
	} else {
		m.bundle = engine.RenderBundle(b)
	}
	m.bundleLines = strings.Split(m.bundle, "\n")
	// keep the selection visible in the list window
	bodyH := m.bodyHeight()
	if m.sel < m.listOff {
		m.listOff = m.sel
	}
	if m.sel >= m.listOff+bodyH {
		m.listOff = m.sel - bodyH + 1
	}
}

// startEval dispatches evaluation as a command — Update never blocks. Eval
// state is invalidated up front so a failed run can never leave a stale
// "verified" claim on screen.
func (m *Model) startEval() tea.Cmd {
	if m.opts.PlanPath == "" {
		m.status = "no plan loaded — start with --plan <tfplan.json> to enable evaluation"
		return nil
	}
	if len(m.matches) == 0 {
		m.status = "nothing matched — nothing to evaluate"
		return nil
	}
	var paths []string
	for _, match := range m.matches {
		if match.Rule.Kind != "helper" {
			paths = append(paths, match.Rule.Path)
		}
	}
	if len(paths) == 0 {
		m.status = "only helpers matched — nothing to evaluate"
		return nil
	}
	// refresh the snapshot so eval sees current disk, then invalidate any
	// prior eval evidence before the async run
	ix, compiler, err := m.eng.Snapshot()
	if err != nil {
		m.err = err.Error()
		return nil
	}
	m.ix, m.compiler = ix, compiler
	m.answer = engine.BuildAnswer(m.ix, m.matches, nil, nil, nil)
	m.evaluating = true
	m.status = "evaluating…"

	opts := engine.EvalOptions{
		PlanPath:         m.opts.PlanPath,
		InputMode:        m.opts.InputMode,
		DataDir:          m.opts.DataDir,
		AllowMissingData: m.opts.AllowMissingData,
		Timeout:          m.opts.EvalTimeout,
		OnlyRulePaths:    paths,
	}
	query := m.lastQuery
	ixSnap, compilerSnap := m.ix, m.compiler
	o := m.opts
	return func() tea.Msg {
		evals, types, err := engine.Evaluate(context.Background(), ixSnap, compilerSnap, opts)
		msg := evalDoneMsg{query: query, evals: evals, types: types, err: err}
		if err == nil && o.AllowMissingData {
			if missing, merr := engine.MissingData(ixSnap, paths, o.DataDir); merr == nil {
				msg.allowedMissing = missing
			}
		}
		return msg
	}
}

// hasEvalEvidence derives the verdict-bar tag from the claims actually on
// screen — never from a flag that could go stale (M3 review).
func (m *Model) hasEvalEvidence() bool {
	for _, c := range m.answer.Claims {
		if c.Evidence == engine.EvidenceEval {
			return true
		}
	}
	return false
}

func (m *Model) bodyHeight() int {
	h := m.height
	if h < minHeight {
		h = 30
	}
	return h - 8
}

// --- view --------------------------------------------------------------------

var (
	borderStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	selStyle     = lipgloss.NewStyle().Bold(true).Reverse(true)
	dimStyle     = lipgloss.NewStyle().Faint(true)
	verdictStyle = lipgloss.NewStyle().Bold(true)
)

func truncate(s string, w int) string {
	if w <= 1 || len(s) <= w {
		return s
	}
	return s[:w-1] + "…"
}

// View implements tea.Model. Pure render: no engine calls, no mutation.
func (m *Model) View() string {
	if m.width > 0 && (m.width < minWidth || m.height < minHeight) {
		return fmt.Sprintf("terminal too small (%dx%d) — need at least %dx%d", m.width, m.height, minWidth, minHeight)
	}
	w := m.width
	if w < minWidth {
		w = 100
	}
	bodyH := m.bodyHeight()
	listW := w / 3
	detailW := w - listW - 6

	var list strings.Builder
	end := min(len(m.matches), m.listOff+bodyH)
	for i := m.listOff; i < end; i++ {
		match := m.matches[i]
		label := match.Rule.Kind
		if match.Rule.Name != match.Rule.Kind {
			label += " " + match.Rule.Name
		}
		line := truncate(fmt.Sprintf("%s  %s:%d", label, match.Rule.File, match.Rule.Row), listW-2)
		if i == m.sel {
			line = selStyle.Render(line)
		}
		list.WriteString(line + "\n")
	}
	if end < len(m.matches) {
		list.WriteString(dimStyle.Render(fmt.Sprintf("… %d more", len(m.matches)-end)))
	}
	if len(m.matches) == 0 {
		list.WriteString(dimStyle.Render("(no matches)"))
	}

	dEnd := min(len(m.bundleLines), m.scroll+bodyH)
	var detailLines []string
	for _, l := range m.bundleLines[min(m.scroll, len(m.bundleLines)):dEnd] {
		detailLines = append(detailLines, truncate(l, detailW-2))
	}
	detail := strings.Join(detailLines, "\n")

	verdict := "Verdict: —"
	if m.evaluating {
		verdict = "Verdict: evaluating…"
	} else if m.answer.Verdict != "" {
		tag := "backed-by-AST only — ctrl+e to verify"
		if m.hasEvalEvidence() {
			tag = "includes verified-by-eval"
		}
		verdict = fmt.Sprintf("Verdict: %s  (%s)", m.answer.Verdict, tag)
		if m.answer.Capped != "" {
			verdict += "  capped: " + m.answer.Capped
		}
	}

	statusLine := m.status
	if m.err != "" {
		statusLine = "error: " + m.err
	}
	if m.banner != "" {
		statusLine = "⚠ " + m.banner + " · " + statusLine
	}

	panes := lipgloss.JoinHorizontal(lipgloss.Top,
		borderStyle.Width(listW).Height(bodyH).MaxHeight(bodyH+2).Render(list.String()),
		borderStyle.Width(detailW).Height(bodyH).MaxHeight(bodyH+2).Render(detail),
	)
	return lipgloss.JoinVertical(lipgloss.Left,
		borderStyle.Width(w-4).Render(m.input.View()),
		panes,
		verdictStyle.Render(verdict),
		dimStyle.Render(truncate(statusLine, w-2)),
	)
}
