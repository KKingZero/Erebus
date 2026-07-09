package aitui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/core/theme"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	openai "github.com/sashabaranov/go-openai"
)

// QuitMode describes how the user left the AI TUI.
type QuitMode int

const (
	QuitNone QuitMode = iota
	QuitBack
	QuitAll
)

// SessionMode is selected via Shift+Tab.
type SessionMode int

const (
	ModeNormal SessionMode = iota
	ModePlan
	ModeAuto
)

var sessionModes = []struct {
	ID    SessionMode
	Label string
	Hint  string
}{
	{ModeNormal, "Normal", "Chat and quick guidance"},
	{ModePlan, "Plan", "Structured attack-path planning"},
	{ModeAuto, "Auto", "Autonomous agent execution"},
}

// Options configures an AI TUI session.
type Options struct {
	LLMCfg     llm.Config
	AgentCfg   *agent.Config
	InitialMsg string
}

type entryKind int

const (
	entryUser entryKind = iota
	entryAI
	entrySystem
	entryStep
	entryError
)

type entry struct {
	kind entryKind
	body string
}

type approvalReply struct {
	action agent.ApprovalAction
	reason string
}

type pendingApproval struct {
	id, risk, desc string
	reply          chan approvalReply
}

type model struct {
	opts            Options
	width           int
	height          int
	viewport        viewport.Model
	input           textinput.Model
	entries         []entry
	messages        []openai.ChatCompletionMessage
	busy            bool
	quitMode        QuitMode
	agentCh         chan tea.Msg
	modeIdx         int
	modelPickerOpen bool
	modelPickerIdx  int
	runCtx          context.Context
	cancel          context.CancelFunc
	pending         *pendingApproval
}

type chatDoneMsg struct {
	reply string
	err   error
}

type agentEventMsg struct {
	line string
	done bool
	err  error
}

type approvalNeededMsg struct {
	id, risk, desc string
	reply          chan approvalReply
}

var (
	headerStyle     = theme.Accent
	subheadStyle    = theme.Default
	footerStyle     = theme.Default
	modeActive      = theme.Active.Padding(0, 1)
	modeInactive    = theme.Inactive.Padding(0, 1)
	inputBoxStyle   = theme.Box
	userLabel       = theme.Accent
	aiLabel         = theme.Accent
	systemLabel     = theme.Default
	stepLabel       = theme.AccentPlain
	errLabel        = theme.Accent
	bodyStyle       = theme.Default
	errBody         = theme.Accent
	separatorStyle  = theme.Default
	pickerBoxStyle  = theme.Border.Border(lipgloss.NormalBorder()).Padding(0, 2)
	pickerSelected  = theme.Active
	pickerItemStyle = theme.Default
	approvalStyle   = theme.Accent
)

// Run starts the AI chat TUI. Blocks until the user exits.
func Run(opts Options) (QuitMode, error) {
	m := newModel(opts)
	defer m.cancel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return QuitNone, err
	}
	return final.(model).quitMode, nil
}

func newModel(opts Options) model {
	ti := textinput.New()
	ti.Placeholder = "Ask Erebus..."
	ti.Prompt = "› "
	ti.CharLimit = 4096
	ti.TextStyle = theme.Default
	ti.PromptStyle = theme.Accent
	ti.PlaceholderStyle = theme.Default
	ti.Cursor.Style = theme.Default
	ti.Focus()

	runCtx, cancel := context.WithCancel(context.Background())
	m := model{
		opts:           opts,
		input:          ti,
		viewport:       viewport.New(80, 20),
		modelPickerIdx: pickerIndexForProvider(opts.LLMCfg.Provider),
		runCtx:         runCtx,
		cancel:         cancel,
		messages: []openai.ChatCompletionMessage{{
			Role:    openai.ChatMessageRoleSystem,
			Content: llm.ErebusSystemPrompt,
		}},
	}
	m.appendSystem("Erebus AI ready. Tab = model · Shift+Tab = mode (Normal / Plan / Auto).")
	if opts.AgentCfg != nil {
		m.appendSystem("Teamserver connected — use Auto mode to run the agent. Approvals happen in this TUI ([a]/[d]).")
	} else {
		m.appendSystem("No teamserver — Normal/Plan chat only. Start with: erebus serve")
	}
	m.syncViewport()
	return m
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink}
	if msg := strings.TrimSpace(m.opts.InitialMsg); msg != "" {
		cmds = append(cmds, func() tea.Msg { return autoSubmitMsg{text: msg} })
	}
	return tea.Batch(cmds...)
}

type autoSubmitMsg struct {
	text string
}

func (m model) currentMode() SessionMode {
	return sessionModes[m.modeIdx].ID
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		return m, nil

	case autoSubmitMsg:
		return m.handleSubmit(msg.text)

	case tea.KeyMsg:
		if m.pending != nil {
			switch msg.String() {
			case "a", "A", "y", "Y":
				return m.resolveApproval(agent.ApprovalGrant, "")
			case "d", "D", "n", "N":
				return m.resolveApproval(agent.ApprovalDeny, "denied in TUI")
			case "ctrl+c":
				return m.quit(QuitBack)
			}
			return m, nil
		}

		if m.busy {
			switch msg.String() {
			case "ctrl+c":
				return m.quit(QuitBack)
			}
			return m, nil
		}

		if m.modelPickerOpen {
			switch msg.String() {
			case "tab", "down":
				m.modelPickerIdx = (m.modelPickerIdx + 1) % len(pickerModels)
				return m, nil
			case "shift+tab", "up":
				m.modelPickerIdx = (m.modelPickerIdx - 1 + len(pickerModels)) % len(pickerModels)
				return m, nil
			case "enter":
				return m.applyModelChoice(m.modelPickerIdx)
			case "esc":
				m.modelPickerOpen = false
				return m, nil
			case "ctrl+c":
				return m.quit(QuitBack)
			}
			return m, nil
		}

		switch msg.String() {
		case "shift+tab":
			return m.cycleMode()
		case "tab":
			m.modelPickerOpen = true
			m.modelPickerIdx = pickerIndexForProvider(m.opts.LLMCfg.Provider)
			return m, nil
		case "ctrl+c":
			return m.quit(QuitBack)
		case "enter":
			text := strings.TrimSpace(m.input.Value())
			if text == "" {
				return m, nil
			}
			m.input.SetValue("")
			return m.handleSubmit(text)
		}

	case chatDoneMsg:
		m.busy = false
		if msg.err != nil {
			if errors.Is(msg.err, context.Canceled) {
				return m, textinput.Blink
			}
			m.appendError(msg.err.Error())
		} else {
			reply := strings.TrimSpace(msg.reply)
			m.messages = append(m.messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleAssistant,
				Content: reply,
			})
			m.appendAI(reply)
		}
		m.syncViewport()
		return m, textinput.Blink

	case approvalNeededMsg:
		m.pending = &pendingApproval{
			id:    msg.id,
			risk:  msg.risk,
			desc:  msg.desc,
			reply: msg.reply,
		}
		m.appendSystem(formatApprovalBanner(msg.id, msg.risk, msg.desc))
		m.syncViewport()
		return m, listenAgent(m.runCtx, m.agentCh)

	case agentEventMsg:
		if msg.line != "" {
			m.appendStep(msg.line)
			m.syncViewport()
		}
		if !msg.done {
			return m, listenAgent(m.runCtx, m.agentCh)
		}
		// Unblock any in-flight OnApproval wait so the agent goroutine cannot leak.
		m = m.forceResolvePending(agent.ApprovalDeny, "agent ended")
		m.busy = false
		if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
			m.appendError("Agent: " + msg.err.Error())
			m.syncViewport()
		}
		return m, textinput.Blink
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) resolveApproval(action agent.ApprovalAction, reason string) (tea.Model, tea.Cmd) {
	m = m.forceResolvePending(action, reason)
	return m, listenAgent(m.runCtx, m.agentCh)
}

// forceResolvePending sends a decision on any pending approval and clears UI state.
// Safe to call when pending is nil. Does not schedule listenAgent.
func (m model) forceResolvePending(action agent.ApprovalAction, reason string) model {
	p := m.pending
	m.pending = nil
	if p == nil || p.reply == nil {
		return m
	}
	label := "approved"
	if action == agent.ApprovalDeny {
		label = "denied"
	}
	if reason == "agent ended" || reason == "session quit" {
		m.appendSystem(fmt.Sprintf("Approval cancelled (%s): %s", reason, p.id))
	} else {
		m.appendSystem(fmt.Sprintf("Approval %s: %s", label, p.id))
	}
	m.syncViewport()
	select {
	case p.reply <- approvalReply{action: action, reason: reason}:
	default:
	}
	return m
}

func (m model) cycleMode() (tea.Model, tea.Cmd) {
	m.modeIdx = (m.modeIdx + 1) % len(sessionModes)
	m.resetChatSystem()
	mode := sessionModes[m.modeIdx]
	m.appendSystem(fmt.Sprintf("Mode: %s — %s", mode.Label, mode.Hint))
	if mode.ID == ModeAuto && m.opts.AgentCfg == nil {
		m.appendSystem("Auto needs teamserver (erebus serve) + operator and approver certs under ~/.erebus/certs/.")
	}
	m.syncViewport()
	return m, nil
}

func (m *model) resetChatSystem() {
	sys := llm.ErebusSystemPrompt
	if m.currentMode() == ModePlan {
		sys = agent.PlanSystemPrompt()
	}
	m.messages = []openai.ChatCompletionMessage{{
		Role:    openai.ChatMessageRoleSystem,
		Content: sys,
	}}
}

func (m model) handleSubmit(text string) (tea.Model, tea.Cmd) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "/back":
		return m.quit(QuitBack)
	case "/quit":
		return m.quit(QuitAll)
	case "/clear":
		m.entries = nil
		m.resetChatSystem()
		m.appendSystem("Transcript cleared.")
		m.syncViewport()
		return m, nil
	}

	m.appendUser(text)

	switch m.currentMode() {
	case ModeAuto:
		if m.opts.AgentCfg == nil {
			m.appendError("Auto mode requires teamserver (erebus serve) plus operator and approver certs (~/.erebus/certs/).")
			m.syncViewport()
			return m, nil
		}
		if m.opts.AgentCfg.ApproverCert == "" || m.opts.AgentCfg.ApproverKey == "" {
			m.appendError("Auto mode needs approver_cert/approver_key for in-TUI [a]/[d] dual-control. Run erebus serve to generate seats.")
			m.syncViewport()
			return m, nil
		}
		m.busy = true
		m.appendSystem("Starting autonomous agent (Auto)… high-risk steps pause for [a]/[d] here.")
		m.syncViewport()
		ch := make(chan tea.Msg, 64)
		m.agentCh = ch
		go runAgent(m.runCtx, m.opts.AgentCfg, text, ch)
		return m, listenAgent(m.runCtx, ch)

	case ModePlan:
		// Ensure plan system prompt is active for this turn.
		if len(m.messages) == 0 || m.messages[0].Role != openai.ChatMessageRoleSystem {
			m.resetChatSystem()
		} else if m.messages[0].Content != agent.PlanSystemPrompt() {
			m.messages[0].Content = agent.PlanSystemPrompt()
		}
		m.messages = append(m.messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: text,
		})
		m.busy = true
		client := llm.NewClient(m.opts.LLMCfg)
		msgs := append([]openai.ChatCompletionMessage(nil), m.messages...)
		return m, chatCmd(m.runCtx, client, msgs)

	default: // ModeNormal
		if len(m.messages) == 0 || m.messages[0].Role != openai.ChatMessageRoleSystem {
			m.resetChatSystem()
		} else if m.messages[0].Content != llm.ErebusSystemPrompt {
			m.messages[0].Content = llm.ErebusSystemPrompt
		}
		m.messages = append(m.messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: text,
		})
		m.busy = true
		client := llm.NewClient(m.opts.LLMCfg)
		msgs := append([]openai.ChatCompletionMessage(nil), m.messages...)
		return m, chatCmd(m.runCtx, client, msgs)
	}
}

func (m model) quit(mode QuitMode) (tea.Model, tea.Cmd) {
	m = m.forceResolvePending(agent.ApprovalDeny, "session quit")
	m.quitMode = mode
	if m.cancel != nil {
		m.cancel()
	}
	return m, tea.Quit
}

func (m model) View() string {
	if m.width == 0 {
		return "Loading...\n"
	}

	backend := "advisory"
	if m.opts.AgentCfg != nil {
		backend = "teamserver"
	}
	header := headerStyle.Render(" Erebus AI ")
	subhead := subheadStyle.Render(fmt.Sprintf(" %s / %s · %s · %s ",
		m.opts.LLMCfg.Provider, m.opts.LLMCfg.Model, backend, sessionModes[m.modeIdx].Hint))

	footer := m.renderFooter()
	inputArea := m.renderInputArea()

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		subhead,
		m.viewport.View(),
		inputArea,
		footer,
	)
}

func (m model) renderInputArea() string {
	inputBox := m.renderInputBox()
	if m.pending != nil {
		banner := m.renderApprovalBanner()
		return lipgloss.JoinVertical(lipgloss.Left, banner, inputBox)
	}
	if !m.modelPickerOpen {
		return inputBox
	}
	picker := m.renderModelPicker()
	return lipgloss.JoinVertical(lipgloss.Left, picker, inputBox)
}

func (m model) renderApprovalBanner() string {
	boxW := max(20, m.width-2)
	body := formatApprovalBanner(m.pending.id, m.pending.risk, m.pending.desc)
	return approvalStyle.Width(boxW).Render(body)
}

func formatApprovalBanner(id, risk, desc string) string {
	return fmt.Sprintf(
		"⚠ APPROVAL REQUIRED\n  id:   %s\n  risk: %s\n  task: %s\n\n  [a] approve    [d] deny    (ctrl+c cancel agent)",
		id, risk, desc,
	)
}

func (m model) renderModelPicker() string {
	var lines []string
	for i, choice := range pickerModels {
		line := "  " + choice.Label
		if i == m.modelPickerIdx {
			line = pickerSelected.Render("→ " + choice.Label)
		} else {
			line = pickerItemStyle.Render("  " + choice.Label)
		}
		lines = append(lines, line)
	}
	return pickerBoxStyle.Render(strings.Join(lines, "\n"))
}

func (m model) applyModelChoice(idx int) (tea.Model, tea.Cmd) {
	m.modelPickerOpen = false
	choice := pickerModels[idx]

	fileCfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		m.appendError(err.Error())
		m.syncViewport()
		return m, nil
	}
	if err := fileCfg.SetActive(choice.Provider); err != nil {
		m.appendError(err.Error())
		m.syncViewport()
		return m, nil
	}

	if choice.Provider == string(llm.ProviderOllama) {
		cfg, _ := fileCfg.ActiveConfig()
		if resolved, err := llm.ResolveOllamaModel(cfg); err == nil {
			_ = fileCfg.SetModel(choice.Provider, resolved.Model)
		}
	}

	if err := llm.SaveFile(llm.DefaultConfigPath, fileCfg); err != nil {
		m.appendError(err.Error())
		m.syncViewport()
		return m, nil
	}

	active, err := fileCfg.ActiveConfig()
	if err != nil {
		m.appendError(err.Error())
		m.syncViewport()
		return m, nil
	}
	m.opts.LLMCfg = active
	if m.opts.AgentCfg != nil {
		m.opts.AgentCfg.LLM = agent.LLMConfig{
			BaseURL: active.BaseURL,
			APIKey:  active.APIKey,
			Model:   active.Model,
		}
	}
	m.appendSystem(fmt.Sprintf("Model: %s (%s / %s)", choice.Label, active.Provider, active.Model))
	m.syncViewport()
	return m, nil
}

func (m model) renderInputBox() string {
	boxW := max(20, m.width-2)

	var modeBar strings.Builder
	for i, mode := range sessionModes {
		label := " " + mode.Label + " "
		if i == m.modeIdx {
			modeBar.WriteString(modeActive.Render(label))
		} else {
			modeBar.WriteString(modeInactive.Render(label))
		}
		if i < len(sessionModes)-1 {
			modeBar.WriteString(subheadStyle.Render(" │ "))
		}
	}

	inputW := boxW - 4
	if inputW < 10 {
		inputW = 10
	}
	m.input.Width = inputW
	inputLine := m.input.View()
	if m.pending != nil || m.busy {
		inputLine = subheadStyle.Render("› (waiting…)")
	}

	inner := lipgloss.JoinVertical(lipgloss.Left,
		modeBar.String(),
		separatorStyle.Render(strings.Repeat("─", boxW-4)),
		inputLine,
	)

	return inputBoxStyle.Width(boxW).Render(inner)
}

func (m model) renderFooter() string {
	if m.pending != nil {
		return approvalStyle.Render("  High-risk action blocked — [a] approve  [d] deny")
	}
	hint := footerStyle.Render("Tab model · ⇧Tab mode")
	cmds := footerStyle.Render("  /back · /quit · /clear")
	status := ""
	if m.busy {
		status = footerStyle.Render("  ⣿ working...")
	}
	return hint + cmds + status
}

func (m *model) layout() {
	headerH := 2
	inputH := 6
	if m.modelPickerOpen {
		inputH += len(pickerModels) + 3
	}
	if m.pending != nil {
		inputH += 4
	}
	footerH := 1
	innerH := m.height - headerH - inputH - footerH - 2
	if innerH < 3 {
		innerH = 3
	}
	m.viewport.Width = max(20, m.width-2)
	m.viewport.Height = innerH
	m.syncViewport()
}

func (m *model) appendUser(text string) {
	m.entries = append(m.entries, entry{kind: entryUser, body: text})
}

func (m *model) appendAI(text string) {
	m.entries = append(m.entries, entry{kind: entryAI, body: text})
}

func (m *model) appendSystem(text string) {
	m.entries = append(m.entries, entry{kind: entrySystem, body: text})
}

func (m *model) appendStep(text string) {
	m.entries = append(m.entries, entry{kind: entryStep, body: text})
}

func (m *model) appendError(text string) {
	m.entries = append(m.entries, entry{kind: entryError, body: text})
}

func (m *model) syncViewport() {
	m.viewport.SetContent(m.renderTranscript())
	m.viewport.GotoBottom()
}

func (m *model) renderTranscript() string {
	if len(m.entries) == 0 {
		return subheadStyle.Render("  No messages yet.")
	}
	w := max(20, m.viewport.Width-4)
	var blocks []string
	for i, e := range m.entries {
		blocks = append(blocks, renderEntry(e, w))
		if i < len(m.entries)-1 {
			blocks = append(blocks, "")
		}
	}
	return strings.Join(blocks, "\n")
}

func renderEntry(e entry, width int) string {
	var label lipgloss.Style
	var content lipgloss.Style
	switch e.kind {
	case entryUser:
		label = userLabel
		content = bodyStyle
	case entryAI:
		label = aiLabel
		content = bodyStyle
	case entrySystem:
		label = systemLabel
		content = systemLabel
	case entryStep:
		label = stepLabel
		content = bodyStyle
	case entryError:
		label = errLabel
		content = errBody
	}

	title := label.Render(labelFor(e.kind))
	line := separatorStyle.Render(strings.Repeat("─", max(4, width-lipgloss.Width(title)-1)))
	header := title + " " + line
	body := content.Width(width).Render(e.body)
	return header + "\n" + body
}

func labelFor(k entryKind) string {
	switch k {
	case entryUser:
		return "You"
	case entryAI:
		return "Erebus"
	case entrySystem:
		return "·"
	case entryStep:
		return "Agent"
	case entryError:
		return "Error"
	default:
		return "?"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func chatCmd(ctx context.Context, client *llm.Client, messages []openai.ChatCompletionMessage) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		reply, err := client.ChatMessages(ctx, messages)
		return chatDoneMsg{reply: reply, err: err}
	}
}

func listenAgent(ctx context.Context, ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-ch:
			return msg
		case <-ctx.Done():
			return agentEventMsg{done: true, err: ctx.Err()}
		}
	}
}

func sendAgentMsg(ctx context.Context, ch chan<- tea.Msg, msg tea.Msg) {
	select {
	case ch <- msg:
	case <-ctx.Done():
	}
}

func runAgent(ctx context.Context, cfg *agent.Config, objective string, ch chan<- tea.Msg) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if cfg.ApproverCert == "" || cfg.ApproverKey == "" {
		sendAgentMsg(ctx, ch, agentEventMsg{
			done: true,
			err:  fmt.Errorf("approver certs required for Auto (run erebus serve)"),
		})
		return
	}

	err := agent.Run(ctx, cfg, agent.RunOptions{
		Objective: objective,
		OnApproval: func(id, risk, desc string) (agent.ApprovalAction, string) {
			reply := make(chan approvalReply, 1)
			sendAgentMsg(ctx, ch, approvalNeededMsg{
				id: id, risk: risk, desc: desc, reply: reply,
			})
			select {
			case r := <-reply:
				return r.action, r.reason
			case <-ctx.Done():
				return agent.ApprovalDeny, "cancelled"
			}
		},
		OnStep: func(step agent.StepOutput) {
			sendAgentMsg(ctx, ch, agentEventMsg{line: formatStep(step)})
		},
	})
	sendAgentMsg(ctx, ch, agentEventMsg{done: true, err: err})
}

func formatStep(step agent.StepOutput) string {
	if step.Done {
		return "done: " + step.Message
	}
	if step.Error != "" {
		return fmt.Sprintf("step %d · %s FAILED: %s", step.Step, step.Tool, step.Error)
	}
	if step.Tool != "" {
		return fmt.Sprintf("step %d · %s (%s): %s", step.Step, step.Tool, step.Risk, truncate(step.Result, 300))
	}
	if step.Message != "" {
		return fmt.Sprintf("step %d · %s", step.Step, step.Message)
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
