package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/JustNak/ZeusDNS-CLI/dns"
)

// ConfigureResult is what RunConfigure returns.
type ConfigureResult struct {
	Upstreams []string
	Saved     bool
}

type configureMode int

const (
	modeList configureMode = iota
	modeAdd
	modeValidating
)

type testResult struct {
	ok  bool
	err string
}

type testResultMsg struct {
	index int
	ok    bool
	err   string
}

type validateAddMsg struct {
	ok  bool
	err string
	raw string
}

type clearDeletePendingMsg struct{}

type configureModel struct {
	upstreams     []string
	results       map[int]testResult
	pendingTest   int
	cursor        int
	deletePending int
	mode          configureMode
	addInput      textinput.Model
	validateErr   string
	saved         bool
	quitting      bool
}

func initialConfigureModel(current []string) configureModel {
	m := configureModel{
		upstreams:     append([]string(nil), current...),
		results:       map[int]testResult{},
		deletePending: -1,
		mode:          modeList,
	}
	ti := textinput.New()
	ti.Placeholder = "https://dns.controld.com/p2   or   tls://dns.adguard.com"
	ti.CharLimit = 200
	ti.Width = 60
	m.addInput = ti
	return m
}

func (m configureModel) Init() tea.Cmd { return nil }

func (m configureModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case testResultMsg:
		m.results[msg.index] = testResult{ok: msg.ok, err: msg.err}
		if m.pendingTest > 0 {
			m.pendingTest--
		}
		return m, nil

	case validateAddMsg:
		if msg.ok {
			m.upstreams = append(m.upstreams, msg.raw)
			m.addInput.Reset()
			m.validateErr = ""
			m.mode = modeList
			m.cursor = len(m.upstreams) - 1
			return m, nil
		}
		m.validateErr = msg.err
		m.mode = modeAdd
		return m, nil

	case clearDeletePendingMsg:
		m.deletePending = -1
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m configureModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// textinput gets first crack while adding.
	if m.mode == modeAdd {
		switch msg.String() {
		case "esc":
			m.mode = modeList
			m.addInput.Blur()
			m.addInput.Reset()
			m.validateErr = ""
			return m, nil
		case "enter":
			raw := strings.TrimSpace(m.addInput.Value())
			if raw == "" {
				m.validateErr = "resolver is required"
				return m, nil
			}
			m.mode = modeValidating
			m.validateErr = ""
			return m, validateResolverCmd(raw)
		default:
			var cmd tea.Cmd
			m.addInput, cmd = m.addInput.Update(msg)
			return m, cmd
		}
	}

	// modeValidating: wait for the result, but allow quit keys.
	if m.mode == modeValidating {
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil
	}

	// modeList
	// Clean up pending delete on any key except 'd'/'x'.
	if m.deletePending >= 0 {
		switch msg.String() {
		case "d", "x":
			// handled below
		default:
			m.deletePending = -1
		}
	}
	switch msg.String() {
	case "ctrl+c", "q", "esc":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.upstreams)-1 {
			m.cursor++
		}
	case "a":
		if len(m.upstreams) >= 16 {
			return m, nil
		}
		m.mode = modeAdd
		m.validateErr = ""
		m.addInput.Focus()
		return m, textinput.Blink
	case "d", "x":
		if m.deletePending < 0 {
			// First 'd' — set pending, start 1s timeout
			if len(m.upstreams) <= 1 {
				return m, nil
			}
			m.deletePending = m.cursor
			return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
				return clearDeletePendingMsg{}
			})
		}
		if m.deletePending == m.cursor && len(m.upstreams) > 1 {
			m.upstreams = append(m.upstreams[:m.cursor], m.upstreams[m.cursor+1:]...)
			m.results = map[int]testResult{} // fix 2: clear stale results on structural change
			if m.cursor >= len(m.upstreams) {
				m.cursor = len(m.upstreams) - 1
			}
		}
		m.deletePending = -1
	case "[":
		if m.cursor > 0 {
			m.upstreams[m.cursor-1], m.upstreams[m.cursor] = m.upstreams[m.cursor], m.upstreams[m.cursor-1]
			m.cursor--
			m.results = map[int]testResult{}              // fix 2: clear stale results on structural change
			return m, checkUpstreamCmd(0, m.upstreams[0]) // fix 3: re-test new primary
		}
	case "]":
		if m.cursor < len(m.upstreams)-1 {
			m.upstreams[m.cursor+1], m.upstreams[m.cursor] = m.upstreams[m.cursor], m.upstreams[m.cursor+1]
			m.cursor++
			m.results = map[int]testResult{}              // fix 2: clear stale results on structural change
			return m, checkUpstreamCmd(0, m.upstreams[0]) // fix 3: re-test new primary
		}
	case "t":
		if len(m.upstreams) == 0 {
			return m, nil
		}
		m.results = map[int]testResult{}
		m.pendingTest = len(m.upstreams)
		return m, m.testAllCmd()
	case "s":
		m.saved = true
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m configureModel) testAllCmd() tea.Cmd {
	cmds := make([]tea.Cmd, len(m.upstreams))
	for i, raw := range m.upstreams {
		cmds[i] = checkUpstreamCmd(i, raw)
	}
	return tea.Batch(cmds...)
}

func checkUpstreamCmd(i int, raw string) tea.Cmd {
	return func() tea.Msg {
		u, err := dns.ParseUpstream(raw)
		if err != nil {
			return testResultMsg{index: i, ok: false, err: err.Error()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), dns.CheckTimeout)
		defer cancel()
		if err := u.Check(ctx); err != nil {
			return testResultMsg{index: i, ok: false, err: err.Error()}
		}
		return testResultMsg{index: i, ok: true}
	}
}

func validateResolverCmd(raw string) tea.Cmd {
	return func() tea.Msg {
		u, err := dns.ParseUpstream(raw)
		if err != nil {
			return validateAddMsg{ok: false, err: err.Error(), raw: raw}
		}
		ctx, cancel := context.WithTimeout(context.Background(), dns.CheckTimeout)
		defer cancel()
		if err := u.Check(ctx); err != nil {
			return validateAddMsg{ok: false, err: "resolver didn't respond: " + err.Error(), raw: raw}
		}
		return validateAddMsg{ok: true, raw: raw}
	}
}

func (m configureModel) View() string {
	var b strings.Builder
	b.WriteString(Banner())
	b.WriteString("\n\n")

	switch m.mode {
	case modeAdd, modeValidating:
		b.WriteString(SubTitle.Render("Add a resolver") + "\n\n")
		b.WriteString("  " + m.addInput.View() + "\n\n")
		if m.validateErr != "" {
			b.WriteString(ErrStyle.Render("  ! "+truncate(m.validateErr, 70)) + "\n\n")
		}
		if m.mode == modeValidating {
			b.WriteString(DimStyle.Render("  validating...") + "\n\n")
		}
		b.WriteString(DimStyle.Render("  enter = validate & add   esc = cancel"))
		return b.String()
	}

	b.WriteString(SubTitle.Render("Configure Upstreams") + "\n\n")
	if len(m.upstreams) == 0 {
		b.WriteString(DimStyle.Render("  No upstreams. Press 'a' to add one.\n"))
	} else {
		for i, raw := range m.upstreams {
			cursor := "  "
			if i == m.cursor {
				cursor = CursorStyle.Render("> ")
			}
			badge := PrimaryBadge.Render("[primary]")
			if i > 0 {
				badge = LabelStyle.Render("[fallback]")
			}
			tag := LabelStyle.Render(typeTag(raw))
			res := ""
			if r, ok := m.results[i]; ok {
				if r.ok {
					res = OKStyle.Render("✓")
				} else {
					res = ErrStyle.Render("✗ " + truncate(r.err, 30))
				}
			}
			b.WriteString(fmt.Sprintf("%s%-2d. %-50s %s %s %s\n", cursor, i+1, raw, badge, tag, res))
		}
	}
	b.WriteString("\n")
	if m.pendingTest > 0 {
		b.WriteString(YellowStyle.Render("testing...") + "\n\n")
	}
	b.WriteString(DimStyle.Render("  [a]dd  [d]elete  [[]move up  ]]move down  [t]est all  [s]ave  [q]uit"))
	if m.deletePending >= 0 && m.deletePending < len(m.upstreams) {
		b.WriteString("\n" + YellowStyle.Render("  press d again to delete "+truncate(m.upstreams[m.deletePending], 40)))
	}
	return b.String()
}

func typeTag(raw string) string {
	u, err := dns.ParseUpstream(raw)
	if err != nil {
		return "?"
	}
	return string(u.Proto)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// RunConfigure opens the interactive upstream-management menu. It returns the
// (possibly reordered) list and whether the user chose to save.
func RunConfigure(current []string) (*ConfigureResult, error) {
	p := tea.NewProgram(initialConfigureModel(current), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	m, ok := final.(configureModel)
	if !ok {
		return nil, fmt.Errorf("unexpected final model")
	}
	return &ConfigureResult{Upstreams: m.upstreams, Saved: m.saved}, nil
}
