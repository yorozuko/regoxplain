// Package tui is the Milestone 3 terminal interface — promoted from
// "optional future" after work's org policy blocked MCP in Copilot: the
// terminal is the one interface a workplace cannot disable. Pure frontend:
// every answer on screen comes from the same engine calls the CLI and MCP
// server use, evidence labels included.
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/yorozuko/regoxplain/internal/engine"
)

// Options configures the TUI session.
type Options struct {
	Repo      string
	PlanPath  string
	InputMode string // resolved: flag override or per-repo config
	DataDir   string
}

// Model is the Bubble Tea model. Live typing drives AST-backed search;
// evaluation (the expensive, verified step) runs only on explicit request
// (ctrl+e) so the loop stays instant.
type Model struct {
	opts Options
	eng  *engine.Engine
	cfg  *engine.Config

	input   textinput.Model
	matches []engine.Match
	sel     int
	scroll  int // evidence pane scroll offset (lines)

	answer  engine.Answer
	evals   map[string]*engine.EvalResult
	types   map[string]bool
	evalRan bool

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
	ti := textinput.New()
	ti.Placeholder = "type to search policies (free text — repo vocabulary)"
	ti.Focus()
	ti.Prompt = "> "
	return &Model{
		opts:   opts,
		eng:    engine.New(opts.Repo),
		cfg:    cfg,
		input:  ti,
		status: "ready — type to search · ↑/↓ select · ctrl+e evaluate · pgup/pgdn scroll · ctrl+c quit",
	}, nil
}

func (m *Model) Init() tea.Cmd { return textinput.Blink }

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyUp:
			if m.sel > 0 {
				m.sel--
				m.scroll = 0
			}
			return m, nil
		case tea.KeyDown:
			if m.sel < len(m.matches)-1 {
				m.sel++
				m.scroll = 0
			}
			return m, nil
		case tea.KeyPgUp:
			m.scroll -= 10
			if m.scroll < 0 {
				m.scroll = 0
			}
			return m, nil
		case tea.KeyPgDown:
			m.scroll += 10
			return m, nil
		case tea.KeyCtrlE:
			m.runEval()
			return m, nil
		}
		// Everything else feeds the search box and re-queries live.
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.search()
		return m, cmd
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// search runs the live AST-backed query: free text through the repo-derived
// vocabulary, same as `regoxplain ask` — deterministic, instant, unlabeled
// by eval until ctrl+e.
func (m *Model) search() {
	m.err = ""
	m.evalRan = false
	m.evals = nil
	q := strings.TrimSpace(m.input.Value())
	if q == "" {
		m.matches = nil
		m.answer = engine.Answer{}
		m.sel = 0
		return
	}
	ix, _, err := m.eng.Snapshot()
	if err != nil {
		m.err = err.Error()
		return
	}
	terms, _ := engine.AskTokens(ix, m.cfg.Aliases, q)
	if len(terms) == 0 {
		m.matches = nil
		m.answer = engine.Answer{Verdict: engine.VerdictNotProven}
		m.sel = 0
		return
	}
	m.matches = engine.Search(ix, engine.SearchParams{Terms: terms})
	if m.sel >= len(m.matches) {
		m.sel = 0
	}
	m.answer = engine.BuildAnswer(ix, m.matches, nil, nil, nil)
	m.status = fmt.Sprintf("%d matches — ctrl+e to evaluate against plan", len(m.matches))
}

// runEval is the explicit verified step: evaluate matched entrypoints
// against the configured plan and rebuild the answer with eval evidence.
func (m *Model) runEval() {
	if m.opts.PlanPath == "" {
		m.status = "no plan loaded — start with --plan <tfplan.json> to enable evaluation"
		return
	}
	if len(m.matches) == 0 {
		m.status = "nothing matched — nothing to evaluate"
		return
	}
	ix, compiler, err := m.eng.Snapshot()
	if err != nil {
		m.err = err.Error()
		return
	}
	var paths []string
	for _, match := range m.matches {
		if match.Rule.Kind != "helper" {
			paths = append(paths, match.Rule.Path)
		}
	}
	if len(paths) == 0 {
		m.status = "only helpers matched — nothing to evaluate"
		return
	}
	evals, types, err := engine.Evaluate(context.Background(), ix, compiler, engine.EvalOptions{
		PlanPath:      m.opts.PlanPath,
		InputMode:     m.opts.InputMode,
		DataDir:       m.opts.DataDir,
		OnlyRulePaths: paths,
	})
	if err != nil {
		m.err = err.Error()
		return
	}
	m.evals, m.types, m.evalRan = evals, types, true
	m.answer = engine.BuildAnswer(ix, m.matches, evals, types, nil)
	m.status = fmt.Sprintf("evaluated %d entrypoints against %s [%s]", len(paths), m.opts.PlanPath, m.opts.InputMode)
}

// bundleText renders the evidence pane for the selected match.
func (m *Model) bundleText() string {
	if len(m.matches) == 0 {
		return "no matches — refine the query, or check `regoxplain index` for repo problems"
	}
	ix, _, err := m.eng.Snapshot()
	if err != nil {
		return err.Error()
	}
	sel := m.matches[m.sel].Rule
	b, err := engine.BuildBundle(ix, sel.Path)
	if err != nil {
		return err.Error()
	}
	return engine.RenderBundle(b)
}

// --- view --------------------------------------------------------------------

var (
	borderStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	selStyle     = lipgloss.NewStyle().Bold(true).Reverse(true)
	dimStyle     = lipgloss.NewStyle().Faint(true)
	verdictStyle = lipgloss.NewStyle().Bold(true)
)

// View implements tea.Model.
func (m *Model) View() string {
	w := m.width
	if w < 40 {
		w = 100
	}
	h := m.height
	if h < 10 {
		h = 30
	}
	listW := w / 3
	detailW := w - listW - 6
	bodyH := h - 8

	// Matches pane.
	var list strings.Builder
	for i, match := range m.matches {
		if i >= bodyH {
			list.WriteString(dimStyle.Render(fmt.Sprintf("… %d more", len(m.matches)-i)) + "\n")
			break
		}
		line := fmt.Sprintf("%s %s:%d %s", match.Rule.Kind, match.Rule.File, match.Rule.Row, match.Rule.Name)
		if i == m.sel {
			line = selStyle.Render(line)
		}
		list.WriteString(line + "\n")
	}
	if len(m.matches) == 0 {
		list.WriteString(dimStyle.Render("(no matches)"))
	}

	// Evidence pane with manual scroll.
	lines := strings.Split(m.bundleText(), "\n")
	if m.scroll > len(lines)-1 {
		m.scroll = max(0, len(lines)-1)
	}
	end := min(len(lines), m.scroll+bodyH)
	detail := strings.Join(lines[m.scroll:end], "\n")

	// Verdict bar: the engine's answer, evidence labels intact.
	verdict := "Verdict: —"
	if m.answer.Verdict != "" {
		tag := "backed-by-AST only — ctrl+e to verify"
		if m.evalRan {
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

	panes := lipgloss.JoinHorizontal(lipgloss.Top,
		borderStyle.Width(listW).Height(bodyH).Render(list.String()),
		borderStyle.Width(detailW).Height(bodyH).Render(detail),
	)
	return lipgloss.JoinVertical(lipgloss.Left,
		borderStyle.Width(w-4).Render(m.input.View()),
		panes,
		verdictStyle.Render(verdict),
		dimStyle.Render(statusLine),
	)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
