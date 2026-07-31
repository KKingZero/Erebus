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
	Provider  string
	Model     string
	KeyMask   string
	Path      string
	BaseURL   string
	Cancelled bool
}

type step int

const (
	stepProvider step = iota
	stepOllamaMode
	stepOllamaHost
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

type ollamaModeChoice int

const (
	ollamaLocal ollamaModeChoice = iota
	ollamaRemote
	ollamaCloud
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
	ollamaIdx  int
	models     []string
	keyInput   textinput.Model
	modelInput textinput.Model
	hostInput  textinput.Model
	provider   string
	auth       authChoice
	apiKey     string
	baseURL    string
	ollamaMode ollamaModeChoice
	modelName  string
	width      int
	errMsg     string
	statusMsg  string
	probing    bool
	cancelled  bool
	savedPath  string
	result     Result
	quitting   bool
}

type ollamaProbeMsg struct {
	models []string
	err    error
}

var (
	titleStyle  = theme.Accent
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	activeStyle = theme.Accent
	cursorStyle = theme.Accent.Bold(true)
	footerStyle = dimStyle
	valueStyle  = lipgloss.NewStyle()
)

// Run launches the interactive setup wizard. Requires a TTY.
func Run() (Result, error) {
	if !isTerminal() {
		return Result{}, fmt.Errorf("interactive terminal required — run `ai setup` in a TTY")
	}

	m := newModel()
	p := tea.NewProgram(
		&m,
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
	)
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	out, ok := final.(*model)
	if !ok {
		return Result{}, fmt.Errorf("unexpected setup model type %T", final)
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

	hostIn := textinput.New()
	hostIn.Placeholder = "http://192.168.1.10:11434"
	hostIn.CharLimit = 256
	hostIn.Width = 56
	hostIn.Prompt = ""

	provIdx := 0
	ollamaIdx := 0
	if cfg, err := llm.LoadFile(llm.DefaultConfigPath); err == nil {
		for i, p := range providers {
			if p.ID == cfg.Active {
				provIdx = i
				break
			}
		}
		if s, ok := cfg.Providers[string(llm.ProviderOllama)]; ok {
			switch llm.DetectOllamaMode(s.BaseURL) {
			case llm.OllamaModeCloud:
				ollamaIdx = int(ollamaCloud)
			case llm.OllamaModeRemote:
				ollamaIdx = int(ollamaRemote)
				hostIn.SetValue(s.BaseURL)
			default:
				ollamaIdx = int(ollamaLocal)
			}
		}
	}

	return model{
		step:       stepProvider,
		providers:  providers,
		provIdx:    provIdx,
		ollamaIdx:  ollamaIdx,
		keyInput:   keyIn,
		modelInput: modelIn,
		hostInput:  hostIn,
	}
}

func setupProviders() []providerOption {
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
			label = "Anthropic (Claude models — recommended)"
		}
		if meta.ID == llm.ProviderOllama {
			label = "Ollama (local / remote / cloud)"
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

func ollamaModeLabels() []string {
	return []string{
		"Local (localhost:11434)",
		"Remote host (self-hosted)",
		"Ollama Cloud (ollama.com)",
	}
}

func (m *model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case ollamaProbeMsg:
		m.probing = false
		m.statusMsg = ""
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			// Fall back to curated suggestions so setup can still complete.
			m.models = llm.SuggestedModels(string(llm.ProviderOllama))
			if len(m.models) == 0 {
				m.models = []string{"llama3.2"}
			}
		} else {
			m.errMsg = ""
			m.models = msg.models
			if len(m.models) == 0 {
				m.models = llm.SuggestedModels(string(llm.ProviderOllama))
			}
		}
		m.modelIdx = 0
		preferred := ""
		if cfg, err := llm.LoadFile(llm.DefaultConfigPath); err == nil {
			if s, ok := cfg.Providers[string(llm.ProviderOllama)]; ok {
				preferred = s.Model
			}
		}
		picked := llm.PickOllamaModel(preferred, m.models, "llama3.2")
		for i, n := range m.models {
			if n == picked {
				m.modelIdx = i
				break
			}
		}
		m.step = stepModel
		return m, nil

	case tea.KeyMsg:
		if m.probing {
			if isCancelKey(msg) {
				m.cancelled = true
				m.quitting = true
				m.result = Result{Cancelled: true}
				return m, tea.Quit
			}
			return m, nil
		}
		if isCancelKey(msg) || (isListStep(m.step) && msg.String() == "q") {
			m.cancelled = true
			m.quitting = true
			m.result = Result{Cancelled: true}
			return m, tea.Quit
		}

		switch m.step {
		case stepProvider:
			return m, m.updateList(msg, len(m.providers), &m.provIdx, m.confirmProvider)
		case stepOllamaMode:
			return m, m.updateList(msg, 3, &m.ollamaIdx, m.confirmOllamaMode)
		case stepOllamaHost:
			return m, m.updateHost(msg)
		case stepAuth:
			return m, m.updateList(msg, 2, &m.authIdx, m.confirmAuth)
		case stepKey:
			return m, m.updateKey(msg)
		case stepModel:
			n := len(m.models) + 1
			return m, m.updateList(msg, n, &m.modelIdx, m.confirmModel)
		case stepCustomModel:
			return m, m.updateCustomModel(msg)
		case stepDone:
			m.quitting = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func isCancelKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "ctrl+c", "esc":
		return true
	}
	return msg.Type == tea.KeyEscape || msg.Type == tea.KeyCtrlC
}

func isListStep(s step) bool {
	return s == stepProvider || s == stepOllamaMode || s == stepAuth || s == stepModel
}

func isUpKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "up", "k", "shift+up", "ctrl+up", "alt+up", "ctrl+p", "pgup":
		return true
	}
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftUp, tea.KeyCtrlUp, tea.KeyPgUp:
		return true
	}
	return false
}

func isDownKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "down", "j", "shift+down", "ctrl+down", "alt+down", "ctrl+n", "pgdown":
		return true
	}
	switch msg.Type {
	case tea.KeyDown, tea.KeyShiftDown, tea.KeyCtrlDown, tea.KeyPgDown:
		return true
	}
	return false
}

func isEnterKey(msg tea.KeyMsg) bool {
	if msg.String() == "enter" {
		return true
	}
	return msg.Type == tea.KeyEnter
}

func (m *model) updateList(msg tea.KeyMsg, n int, idx *int, confirm func() tea.Cmd) tea.Cmd {
	if n <= 0 {
		return nil
	}
	switch {
	case isUpKey(msg):
		if *idx > 0 {
			*idx--
		} else {
			*idx = n - 1
		}
	case isDownKey(msg):
		if *idx < n-1 {
			*idx++
		} else {
			*idx = 0
		}
	case msg.String() == "tab":
		*idx = (*idx + 1) % n
	case msg.String() == "shift+tab":
		*idx = (*idx - 1 + n) % n
	case isEnterKey(msg) || msg.String() == " ":
		return confirm()
	}
	return nil
}

func (m *model) confirmProvider() tea.Cmd {
	p := m.providers[m.provIdx]
	m.provider = p.ID
	m.errMsg = ""
	m.statusMsg = ""

	if p.ID == string(llm.ProviderOllama) {
		m.step = stepOllamaMode
		return nil
	}
	if !p.NeedsKey {
		m.auth = authAPIKey
		m.apiKey = "ollama"
		m.baseURL = ""
		return m.enterModelStep()
	}
	m.step = stepAuth
	m.authIdx = 0
	return nil
}

func (m *model) confirmOllamaMode() tea.Cmd {
	m.ollamaMode = ollamaModeChoice(m.ollamaIdx)
	m.errMsg = ""
	switch m.ollamaMode {
	case ollamaLocal:
		m.baseURL = llm.OllamaLocalBaseURL
		m.apiKey = "ollama"
		return m.startOllamaProbe()
	case ollamaRemote:
		m.step = stepOllamaHost
		if strings.TrimSpace(m.hostInput.Value()) == "" {
			m.hostInput.SetValue("http://")
		}
		return m.hostInput.Focus()
	case ollamaCloud:
		m.baseURL = llm.OllamaCloudBaseURL
		m.step = stepAuth
		m.authIdx = 0
		// Prefer env if present.
		if v := strings.TrimSpace(os.Getenv(llm.OllamaAPIKeyEnv)); v != "" {
			m.authIdx = int(authEnv)
		}
		return nil
	}
	return nil
}

func (m *model) updateHost(msg tea.KeyMsg) tea.Cmd {
	if isEnterKey(msg) {
		host := strings.TrimSpace(m.hostInput.Value())
		if host == "" || host == "http://" || host == "https://" {
			m.errMsg = "Enter a host URL (e.g. http://192.168.1.10:11434)"
			return nil
		}
		m.baseURL = llm.NormalizeOllamaBaseURL(host)
		m.apiKey = "ollama"
		m.errMsg = ""
		return m.startOllamaProbe()
	}
	var cmd tea.Cmd
	m.hostInput, cmd = m.hostInput.Update(msg)
	return cmd
}

func (m *model) confirmAuth() tea.Cmd {
	m.auth = authChoice(m.authIdx)
	m.errMsg = ""
	p := m.currentProvider()
	envName := p.APIKeyEnv
	if m.provider == string(llm.ProviderOllama) {
		envName = llm.OllamaAPIKeyEnv
	}

	if m.auth == authEnv {
		envKey := strings.TrimSpace(os.Getenv(envName))
		if envKey == "" {
			m.errMsg = fmt.Sprintf("%s is not set in the environment", envName)
			return nil
		}
		m.apiKey = llm.NormalizeAPIKey(envKey)
		if m.provider == string(llm.ProviderOllama) {
			return m.startOllamaProbe()
		}
		return m.enterModelStep()
	}

	m.step = stepKey
	m.keyInput.SetValue("")
	m.keyInput.Placeholder = keyPlaceholder(m.provider)
	if m.provider == string(llm.ProviderOllama) {
		m.keyInput.Placeholder = "ollama cloud API key"
	}
	return m.keyInput.Focus()
}

func (m *model) updateKey(msg tea.KeyMsg) tea.Cmd {
	if isEnterKey(msg) {
		key := llm.NormalizeAPIKey(m.keyInput.Value())
		if key == "" {
			m.errMsg = "API key cannot be empty"
			return nil
		}
		if warn := keyFormatHint(m.provider, key); warn != "" {
			if isWrongVendorKey(m.provider, key) {
				m.errMsg = warn
				return nil
			}
		}
		m.apiKey = key
		m.errMsg = ""
		if m.provider == string(llm.ProviderOllama) {
			return m.startOllamaProbe()
		}
		return m.enterModelStep()
	}

	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	return cmd
}

func (m *model) startOllamaProbe() tea.Cmd {
	m.probing = true
	m.statusMsg = fmt.Sprintf("Probing Ollama at %s…", m.baseURL)
	m.errMsg = ""
	base := m.baseURL
	key := m.apiKey
	return func() tea.Msg {
		models, err := llm.ProbeOllama(base, key)
		return ollamaProbeMsg{models: models, err: err}
	}
}

func (m *model) enterModelStep() tea.Cmd {
	m.models = llm.SuggestedModels(m.provider)
	m.modelIdx = 0
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
	m.step = stepModel
	return nil
}

func (m *model) confirmModel() tea.Cmd {
	if m.modelIdx >= len(m.models) {
		m.step = stepCustomModel
		m.modelInput.SetValue("")
		m.errMsg = ""
		return m.modelInput.Focus()
	}
	m.modelName = m.models[m.modelIdx]
	return m.save()
}

func (m *model) updateCustomModel(msg tea.KeyMsg) tea.Cmd {
	if isEnterKey(msg) {
		name := strings.TrimSpace(m.modelInput.Value())
		if name == "" {
			m.errMsg = "Model ID cannot be empty"
			return nil
		}
		m.modelName = name
		m.errMsg = ""
		return m.save()
	}
	var cmd tea.Cmd
	m.modelInput, cmd = m.modelInput.Update(msg)
	return cmd
}

func (m *model) save() tea.Cmd {
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		m.errMsg = err.Error()
		return nil
	}
	if m.baseURL != "" && m.provider == string(llm.ProviderOllama) {
		if err := cfg.SetBaseURL(m.provider, m.baseURL); err != nil {
			m.errMsg = err.Error()
			return nil
		}
	}
	if err := cfg.SetAPIKey(m.provider, m.apiKey, true); err != nil {
		m.errMsg = err.Error()
		return nil
	}
	// Re-apply base URL after SetAPIKey (which may reset from empty defaults).
	if m.baseURL != "" && m.provider == string(llm.ProviderOllama) {
		if err := cfg.SetBaseURL(m.provider, m.baseURL); err != nil {
			m.errMsg = err.Error()
			return nil
		}
	}
	if err := cfg.SetModel(m.provider, m.modelName); err != nil {
		m.errMsg = err.Error()
		return nil
	}
	if err := llm.SaveFile(llm.DefaultConfigPath, cfg); err != nil {
		m.errMsg = err.Error()
		return nil
	}

	path := expandHome(llm.DefaultConfigPath)
	m.savedPath = path
	m.step = stepDone
	m.result = Result{
		Provider: m.provider,
		Model:    m.modelName,
		KeyMask:  llm.MaskKey(m.apiKey),
		Path:     path,
		BaseURL:  m.baseURL,
	}
	m.quitting = true
	return tea.Quit
}

func (m *model) currentProvider() providerOption {
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

func (m *model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Erebus AI Setup") + "\n\n")
	m.renderCompleted(&b)

	if m.cancelled {
		switch m.step {
		case stepProvider:
			b.WriteString(errStyle.Render("■ Select your AI provider") + "\n")
		case stepOllamaMode:
			b.WriteString(errStyle.Render("■ Ollama mode") + "\n")
		case stepOllamaHost:
			b.WriteString(errStyle.Render("■ Remote Ollama host") + "\n")
		case stepAuth:
			b.WriteString(errStyle.Render("■ Authentication method") + "\n")
		case stepKey:
			b.WriteString(errStyle.Render("■ Enter API key") + "\n")
		case stepModel, stepCustomModel:
			b.WriteString(errStyle.Render("■ Model") + "\n")
		}
		b.WriteString("\n" + errStyle.Render("Setup cancelled.") + "\n")
		return b.String()
	}

	if m.probing {
		m.renderActiveHeader(&b, "Connecting to Ollama")
		b.WriteString("  " + dimStyle.Render(m.statusMsg) + "\n")
		b.WriteString("\n" + footerStyle.Render("Esc: cancel") + "\n")
		return b.String()
	}

	switch m.step {
	case stepProvider:
		m.renderActiveHeader(&b, "Select your AI provider")
		m.renderRadio(&b, providerLabels(m.providers), m.provIdx)
	case stepOllamaMode:
		m.renderActiveHeader(&b, "Ollama mode")
		m.renderRadio(&b, ollamaModeLabels(), m.ollamaIdx)
	case stepOllamaHost:
		m.renderActiveHeader(&b, "Remote Ollama base URL")
		b.WriteString("  " + m.hostInput.View() + "\n")
		b.WriteString(dimStyle.Render("  Example: http://gpu-box:11434  or  http://10.0.0.5:11434/v1") + "\n")
	case stepAuth:
		m.renderActiveHeader(&b, "Authentication method")
		envName := m.currentProvider().APIKeyEnv
		if m.provider == string(llm.ProviderOllama) {
			envName = llm.OllamaAPIKeyEnv
		}
		opts := []string{"API Key", fmt.Sprintf("Environment variable (%s)", envName)}
		m.renderRadio(&b, opts, m.authIdx)
	case stepKey:
		title := fmt.Sprintf("Enter your %s API key", displayName(m.currentProvider()))
		if m.provider == string(llm.ProviderOllama) {
			title = "Enter your Ollama Cloud API key"
		}
		m.renderActiveHeader(&b, title)
		b.WriteString("  " + m.keyInput.View() + "\n")
	case stepModel:
		m.renderActiveHeader(&b, "Model")
		if m.baseURL != "" && m.provider == string(llm.ProviderOllama) {
			b.WriteString(dimStyle.Render("  "+m.baseURL) + "\n")
		}
		opts := append([]string{}, m.models...)
		opts = append(opts, "Enter a model ID…")
		m.renderRadio(&b, opts, m.modelIdx)
	case stepCustomModel:
		m.renderActiveHeader(&b, "Enter a model ID")
		b.WriteString("  " + m.modelInput.View() + "\n")
	case stepDone:
		b.WriteString(okStyle.Render("◇ Configuration saved to ") + valueStyle.Render(m.savedPath) + "\n")
		b.WriteString(fmt.Sprintf("  %-10s %s\n", "Provider", m.result.Provider))
		if m.result.BaseURL != "" {
			b.WriteString(fmt.Sprintf("  %-10s %s\n", "Base URL", m.result.BaseURL))
		}
		b.WriteString(fmt.Sprintf("  %-10s %s\n", "Model", m.result.Model))
		if m.result.KeyMask != "" && m.result.KeyMask != "(local/none)" {
			b.WriteString(fmt.Sprintf("  %-10s %s\n", "Key", m.result.KeyMask))
		} else if m.provider == string(llm.ProviderOllama) && llm.DetectOllamaMode(m.result.BaseURL) != llm.OllamaModeCloud {
			b.WriteString(fmt.Sprintf("  %-10s %s\n", "Key", "(not required)"))
		}
		b.WriteString("\n" + dimStyle.Render("Run `ai` to open the chat terminal.") + "\n")
		return b.String()
	}

	if m.errMsg != "" {
		b.WriteString("\n" + errStyle.Render("  "+m.errMsg) + "\n")
		if m.step == stepModel {
			b.WriteString(dimStyle.Render("  (using fallback model list — you can still continue)") + "\n")
		}
	}

	b.WriteString("\n" + footerStyle.Render("↑/↓ or j/k  ·  Tab  ·  Enter: confirm  ·  Esc: cancel") + "\n")
	return b.String()
}

func (m *model) renderCompleted(b *strings.Builder) {
	if m.step > stepProvider {
		writeDone(b, "Select your AI provider", providerLabelByID(m.providers, m.provider))
	}
	if m.provider == string(llm.ProviderOllama) && m.step > stepOllamaMode {
		writeDone(b, "Ollama mode", ollamaModeLabels()[m.ollamaMode])
	}
	if m.provider == string(llm.ProviderOllama) && m.ollamaMode == ollamaRemote && m.step > stepOllamaHost {
		writeDone(b, "Remote Ollama host", m.baseURL)
	}
	// Auth completed for non-ollama key providers, or ollama cloud.
	showAuth := false
	if m.provider != string(llm.ProviderOllama) && m.currentProvider().NeedsKey && m.step > stepAuth {
		showAuth = true
	}
	if m.provider == string(llm.ProviderOllama) && m.ollamaMode == ollamaCloud && m.step > stepAuth {
		showAuth = true
	}
	if showAuth {
		label := "API Key"
		if m.auth == authEnv {
			label = "Environment variable"
		}
		writeDone(b, "Authentication method", label)
	}
	showKey := false
	if m.provider != string(llm.ProviderOllama) && m.currentProvider().NeedsKey && m.auth == authAPIKey && m.step > stepKey {
		showKey = true
	}
	if m.provider == string(llm.ProviderOllama) && m.ollamaMode == ollamaCloud && m.auth == authAPIKey && m.step > stepKey {
		showKey = true
	}
	if showKey {
		writeDone(b, "API key", maskBullets(m.apiKey))
	}
	if m.step > stepModel && m.modelName != "" {
		writeDone(b, "Model", m.modelName)
	}
}

func writeDone(b *strings.Builder, title, value string) {
	b.WriteString(okStyle.Render("◇ ") + title + "\n")
	b.WriteString("  " + valueStyle.Render(value) + "\n\n")
}

func (m *model) renderActiveHeader(b *strings.Builder, title string) {
	b.WriteString(activeStyle.Render("◇ ") + activeStyle.Render(title) + "\n")
}

func (m *model) renderRadio(b *strings.Builder, options []string, selected int) {
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
	case llm.ProviderOllama:
		return "OLLAMA_API_KEY"
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
