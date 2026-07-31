// Package aisetup provides an interactive Shannon-style LLM configuration wizard.
package aisetup

import (
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/core/theme"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Result is returned after a successful setup run.
type Result struct {
	Provider string
	Model    string
	KeyMask  string
	Path     string
	Cancelled bool
}

type step int

const (
	stepProvider step = iota
	stepAuth
	stepKey
	stepModel
	stepCustomModel
	stepDone
)

type authChoice int

const (
	authAPIKey authChoice = iota
	authEnv
)

type providerOption struct {
	ID          string
	Label       string
	Recommended bool
	NeedsKey    bool
	APIKeyEnv   string
}

type model struct {
	step       step
	providers  []providerOption
	provIdx    int
	authIdx    int
	modelIdx   int
	models     []string
	keyInput   textinput.Model
	modelInput textinput.Model
	provider   string
	auth       authChoice
	apiKey     string
	modelName  string
	width      int
	errMsg     string
	cancelled  bool
	savedPath  string
	result     Result
	quitting   bool
}

var (
	titleStyle   = theme.Accent
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	activeStyle  = theme.Accent
	cursorStyle  = theme.Accent.Bold(true)
	footerStyle  = dimStyle
	valueStyle   = lipgloss.NewStyle()
)

// Run launches the interactive setup wizard. Requires a TTY.
func Run() (Result, error) {
	if !isTerminal() {
		return Result{}, fmt.Errorf("interactive terminal required — run `ai setup` in a TTY")
	}

	m := newModel()
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	out, ok := final.(model)
	if !ok {
		return Result{}, fmt.Errorf("unexpected setup model type")
	}
	if out.cancelled || out.result.Cancelled {
		return Result{Cancelled: true}, nil
	}
	return out.result, nil
}

func isTerminal() bool {
	return termIsTerminal(int(os.Stdin.Fd())) && termIsTerminal(int(os.Stdout.Fd()))
}

func termIsTerminal(fd int) bool {
	// local import wrapper — golang.org/x/term is already a module dep
	return isTerminalFD(fd)
}

func newModel() model {
	providers := setupProviders()
	keyIn := textinput.New()
	keyIn.Placeholder = "sk-ant-..."
	keyIn.EchoMode = textinput.EchoPassword
	keyIn.EchoCharacter = '•'
	keyIn.CharLimit = 512
	keyIn.Width = 64
	keyIn.Prompt = ""

	modelIn := textinput.New()
	modelIn.Placeholder = "model-id"
	modelIn.CharLimit = 128
	modelIn.Width = 48
	modelIn.Prompt = ""

	// Prefer currently active provider if known.
	provIdx := 0
	if cfg, err := llm.LoadFile(llm.DefaultConfigPath); err == nil {
		for i, p := range providers {
			if p.ID == cfg.Active {
				provIdx = i
				break
			}
		}
	}

	return model{
		step:       stepProvider,
		providers:  providers,
		provIdx:    provIdx,
		keyInput:   keyIn,
		modelInput: modelIn,
	}
}

func setupProviders() []providerOption {
	// Curated order: hosted first (Anthropic recommended), local last — Shannon-like.
	order := []string{
		string(llm.ProviderAnthropic),
		string(llm.ProviderOpenAI),
		string(llm.ProviderGemini),
		string(llm.ProviderKimi),
		string(llm.ProviderBedrock),
		string(llm.ProviderOllama),
	}
	out := make([]providerOption, 0, len(order))
	for _, id := range order {
		meta, err := llm.LookupProvider(id)
		if err != nil {
			continue
		}
		label := meta.Label
		rec := meta.ID == llm.ProviderAnthropic
		if rec {
			label = meta.Label + " (Claude models — recommended)"
		}
		out = append(out, providerOption{
			ID:          id,
			Label:       label,
			Recommended: rec,
			NeedsKey:    meta.NeedsKey,
			APIKeyEnv:   meta.APIKeyEnv,
		})
	}
	return out
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			m.quitting = true
			m.result = Result{Cancelled: true}
			return m, tea.Quit
		}

		switch m.step {
		case stepProvider:
			return m.updateList(msg, len(m.providers), &m.provIdx, m.confirmProvider)
		case stepAuth:
			return m.updateList(msg, 2, &m.authIdx, m.confirmAuth)
		case stepKey:
			return m.updateKey(msg)
		case stepModel:
			n := len(m.models) + 1 // + custom entry
			return m.updateList(msg, n, &m.modelIdx, m.confirmModel)
		case stepCustomModel:
			return m.updateCustomModel(msg)
		case stepDone:
			m.quitting = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m model) updateList(msg tea.KeyMsg, n int, idx *int, confirm func() (model, tea.Cmd)) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if *idx > 0 {
			*idx--
		}
	case "down", "j":
		if *idx < n-1 {
			*idx++
		}
	case "enter":
		return confirm()
	}
	return m, nil
}

func (m model) confirmProvider() (model, tea.Cmd) {
	p := m.providers[m.provIdx]
	m.provider = p.ID
	m.errMsg = ""

	if !p.NeedsKey {
		// Ollama: skip auth + key.
		m.auth = authAPIKey
		m.apiKey = "ollama"
		return m.enterModelStep()
	}
	m.step = stepAuth
	m.authIdx = 0
	return m, nil
}

func (m model) confirmAuth() (model, tea.Cmd) {
	m.auth = authChoice(m.authIdx)
	m.errMsg = ""
	p := m.currentProvider()

	if m.auth == authEnv {
		envKey := strings.TrimSpace(os.Getenv(p.APIKeyEnv))
		if envKey == "" {
			m.errMsg = fmt.Sprintf("%s is not set in the environment", p.APIKeyEnv)
			return m, nil
		}
		m.apiKey = llm.NormalizeAPIKey(envKey)
		return m.enterModelStep()
	}

	m.step = stepKey
	m.keyInput.SetValue("")
	m.keyInput.Placeholder = keyPlaceholder(p.ID)
	return m, m.keyInput.Focus()
}

func (m model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		key := llm.NormalizeAPIKey(m.keyInput.Value())
		if key == "" {
			m.errMsg = "API key cannot be empty"
			return m, nil
		}
		if warn := keyFormatHint(m.provider, key); warn != "" {
			// Soft warn only for obviously wrong prefixes; still allow continue if they re-enter? 
			// For multi-paste already normalized. Block clearly wrong vendor keys.
			if isWrongVendorKey(m.provider, key) {
				m.errMsg = warn
				return m, nil
			}
		}
		m.apiKey = key
		m.errMsg = ""
		return m.enterModelStep()
	case "backspace":
		// let textinput handle
	}

	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	return m, cmd
}

func (m model) enterModelStep() (model, tea.Cmd) {
	m.models = llm.SuggestedModels(m.provider)
	m.modelIdx = 0
	// Prefer currently saved model if in list.
	if cfg, err := llm.LoadFile(llm.DefaultConfigPath); err == nil {
		if s, ok := cfg.Providers[m.provider]; ok && s.Model != "" {
			for i, id := range m.models {
				if id == s.Model {
					m.modelIdx = i
					break
				}
			}
		}
	}
	// Ollama: try discovered models.
	if m.provider == string(llm.ProviderOllama) {
		if cfg, err := llm.Load(llm.DefaultConfigPath); err == nil {
			if resolved, err := llm.ResolveOllamaModel(cfg); err == nil && resolved.Model != "" {
				// Put discovered model first if not already listed.
				found := false
				for i, id := range m.models {
					if id == resolved.Model {
						m.modelIdx = i
						found = true
						break
					}
				}
				if !found {
					m.models = append([]string{resolved.Model}, m.models...)
					m.modelIdx = 0
				}
			}
		}
	}
	m.step = stepModel
	return m, nil
}

func (m model) confirmModel() (model, tea.Cmd) {
	if m.modelIdx >= len(m.models) {
		// Custom model ID
		m.step = stepCustomModel
		m.modelInput.SetValue("")
		m.errMsg = ""
		return m, m.modelInput.Focus()
	}
	m.modelName = m.models[m.modelIdx]
	return m.save()
}

func (m model) updateCustomModel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		name := strings.TrimSpace(m.modelInput.Value())
		if name == "" {
			m.errMsg = "Model ID cannot be empty"
			return m, nil
		}
		m.modelName = name
		m.errMsg = ""
		return m.save()
	}
	var cmd tea.Cmd
	m.modelInput, cmd = m.modelInput.Update(msg)
	return m, cmd
}

func (m model) save() (model, tea.Cmd) {
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		m.errMsg = err.Error()
		return m, nil
	}
	if err := cfg.SetAPIKey(m.provider, m.apiKey, true); err != nil {
		m.errMsg = err.Error()
		return m, nil
	}
	if err := cfg.SetModel(m.provider, m.modelName); err != nil {
		m.errMsg = err.Error()
		return m, nil
	}
	if err := llm.SaveFile(llm.DefaultConfigPath, cfg); err != nil {
		m.errMsg = err.Error()
		return m, nil
	}

	path := expandHome(llm.DefaultConfigPath)
	m.savedPath = path
	m.step = stepDone
	m.result = Result{
		Provider: m.provider,
		Model:    m.modelName,
		KeyMask:  llm.MaskKey(m.apiKey),
		Path:     path,
	}
	m.quitting = true
	return m, tea.Quit
}

func (m model) currentProvider() providerOption {
	for _, p := range m.providers {
		if p.ID == m.provider {
			return p
		}
	}
	if m.provIdx >= 0 && m.provIdx < len(m.providers) {
		return m.providers[m.provIdx]
	}
	return providerOption{}
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Erebus AI Setup") + "\n\n")

	// Completed steps stay visible (Shannon-style vertical form).
	m.renderCompleted(&b)

	if m.cancelled {
		// Show the step that was abandoned, then a red cancel notice.
		switch m.step {
		case stepProvider:
			b.WriteString(errStyle.Render("■ Select your AI provider") + "\n")
		case stepAuth:
			b.WriteString(errStyle.Render("■ Authentication method") + "\n")
			b.WriteString("  API Key\n")
		case stepKey:
			p := m.currentProvider()
			b.WriteString(errStyle.Render(fmt.Sprintf("■ Enter your %s API key", displayName(p))) + "\n")
		case stepModel, stepCustomModel:
			b.WriteString(errStyle.Render("■ Model") + "\n")
		}
		b.WriteString("\n" + errStyle.Render("Setup cancelled.") + "\n")
		return b.String()
	}

	switch m.step {
	case stepProvider:
		m.renderActiveHeader(&b, "Select your AI provider")
		m.renderRadio(&b, providerLabels(m.providers), m.provIdx)
	case stepAuth:
		m.renderActiveHeader(&b, "Authentication method")
		p := m.currentProvider()
		opts := []string{"API Key", fmt.Sprintf("Environment variable (%s)", p.APIKeyEnv)}
		m.renderRadio(&b, opts, m.authIdx)
	case stepKey:
		p := m.currentProvider()
		m.renderActiveHeader(&b, fmt.Sprintf("Enter your %s API key", displayName(p)))
		b.WriteString("  " + m.keyInput.View() + "\n")
	case stepModel:
		m.renderActiveHeader(&b, "Model")
		opts := append([]string{}, m.models...)
		opts = append(opts, "Enter a model ID…")
		m.renderRadio(&b, opts, m.modelIdx)
	case stepCustomModel:
		m.renderActiveHeader(&b, "Enter a model ID")
		b.WriteString("  " + m.modelInput.View() + "\n")
	case stepDone:
		b.WriteString(okStyle.Render("◇ Configuration saved to ") + valueStyle.Render(m.savedPath) + "\n")
		b.WriteString(fmt.Sprintf("  %-10s %s\n", "Provider", m.result.Provider))
		b.WriteString(fmt.Sprintf("  %-10s %s\n", "Model", m.result.Model))
		if m.provider != string(llm.ProviderOllama) {
			b.WriteString(fmt.Sprintf("  %-10s %s\n", "Key", m.result.KeyMask))
		}
		b.WriteString("\n" + dimStyle.Render("Run `ai` to open the chat terminal.") + "\n")
		return b.String()
	}

	if m.errMsg != "" {
		b.WriteString("\n" + errStyle.Render("  "+m.errMsg) + "\n")
	}

	b.WriteString("\n" + footerStyle.Render("↑/↓ navigate  ·  Enter: confirm  ·  Esc: cancel") + "\n")
	return b.String()
}

func (m model) renderCompleted(b *strings.Builder) {
	// Steps completed before current.
	if m.step > stepProvider {
		writeDone(b, "Select your AI provider", providerLabelByID(m.providers, m.provider))
	}
	if m.step > stepAuth && m.currentProvider().NeedsKey {
		label := "API Key"
		if m.auth == authEnv {
			label = "Environment variable"
		}
		writeDone(b, "Authentication method", label)
	}
	if m.step > stepKey && m.currentProvider().NeedsKey && m.auth == authAPIKey {
		writeDone(b, fmt.Sprintf("Enter your %s API key", displayName(m.currentProvider())), maskBullets(m.apiKey))
	}
	if m.step > stepModel && m.modelName != "" {
		writeDone(b, "Model", m.modelName)
	}
}

func writeDone(b *strings.Builder, title, value string) {
	b.WriteString(okStyle.Render("◇ ") + title + "\n")
	b.WriteString("  " + valueStyle.Render(value) + "\n\n")
}

func (m model) renderActiveHeader(b *strings.Builder, title string) {
	b.WriteString(activeStyle.Render("◇ ") + activeStyle.Render(title) + "\n")
}

func (m model) renderRadio(b *strings.Builder, options []string, selected int) {
	for i, opt := range options {
		if i == selected {
			b.WriteString("  " + cursorStyle.Render("● "+opt) + "\n")
			continue
		}
		b.WriteString("  ○ " + opt + "\n")
	}
}

func providerLabels(ps []providerOption) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Label
	}
	return out
}

func providerLabelByID(ps []providerOption, id string) string {
	for _, p := range ps {
		if p.ID == id {
			// strip recommendation suffix for completed summary
			if i := strings.Index(p.Label, " ("); i > 0 {
				return p.Label[:i]
			}
			return p.Label
		}
	}
	return id
}

func displayName(p providerOption) string {
	if i := strings.Index(p.Label, " ("); i > 0 {
		return p.Label[:i]
	}
	if p.Label != "" {
		return p.Label
	}
	return p.ID
}

func keyPlaceholder(provider string) string {
	switch llm.ProviderID(provider) {
	case llm.ProviderAnthropic:
		return "sk-ant-api03-..."
	case llm.ProviderOpenAI:
		return "sk-..."
	case llm.ProviderGemini:
		return "AIza..."
	default:
		return "API key"
	}
}

func keyFormatHint(provider, key string) string {
	switch llm.ProviderID(provider) {
	case llm.ProviderAnthropic:
		if !strings.HasPrefix(key, "sk-ant-") {
			return "Anthropic keys usually start with sk-ant-"
		}
	case llm.ProviderOpenAI:
		if strings.HasPrefix(key, "sk-ant-") {
			return "That looks like an Anthropic key, not OpenAI"
		}
	}
	return ""
}

func isWrongVendorKey(provider, key string) bool {
	switch llm.ProviderID(provider) {
	case llm.ProviderAnthropic:
		return strings.HasPrefix(key, "sk-") && !strings.HasPrefix(key, "sk-ant-")
	case llm.ProviderOpenAI:
		return strings.HasPrefix(key, "sk-ant-")
	default:
		return false
	}
}

func maskBullets(key string) string {
	n := len(key)
	if n > 48 {
		n = 48
	}
	if n < 8 {
		n = 8
	}
	return strings.Repeat("•", n)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + p[1:]
		}
	}
	return p
}
