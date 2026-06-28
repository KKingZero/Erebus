package core

import (
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
	"golang.org/x/term"
)

func (c *Console) cmdAI(args []string) {
	if len(args) == 0 {
		c.runAITUI("")
		return
	}
	switch args[0] {
	case "providers":
		c.aiProviders()
	case "provider":
		c.aiSetProvider(args[1:])
	case "key":
		c.aiSetKey(args[1:])
	case "model":
		c.aiSetModel(args[1:])
	case "config":
		c.aiShowConfig()
	case "help":
		c.aiUsage()
	default:
		if c.mode == OutputJSON {
			c.runAI(strings.Join(args, " "))
			return
		}
		c.runAITUI(strings.Join(args, " "))
	}
}

func (c *Console) aiUsage() {
	msg := `AI commands:
  ai                               Open AI chat terminal (TUI)
  ai <message>                     Open TUI and send first message
  ai providers                     List LLM providers
  ai provider <name>               Switch active provider (ollama, openai, anthropic, bedrock, kimi)
  ai key <provider>                Set API key (hidden prompt; never pass key on command line)
  ai model <provider> <model>      Set model for a provider
  ai config                        Show active provider and saved keys (masked)

In TUI: /back = return to erebus ›   /quit = exit Erebus   /clear = reset transcript
Providers: ollama (local), openai, anthropic, bedrock, kimi`
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: msg,
	})
}

func (c *Console) aiProviders() {
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	var b strings.Builder
	b.WriteString("\nLLM providers:\n")
	for _, p := range llm.SupportedProviders() {
		active := ""
		if cfg.Active == string(p.ID) {
			active = " *"
		}
		keyStatus := "no key"
		if cfg.HasAPIKey(string(p.ID)) {
			keyStatus = "key set"
		}
		if !p.NeedsKey {
			keyStatus = "local"
		}
		settings := cfg.Providers[string(p.ID)]
		model := settings.Model
		if model == "" {
			model = p.DefaultModel
		}
		b.WriteString(fmt.Sprintf("  %-10s %-28s model=%-22s %s%s\n",
			p.ID, p.Label, model, keyStatus, active))
	}
	b.WriteString(fmt.Sprintf("\nActive: %s\n", cfg.Active))
	b.WriteString("Set key: ai key <provider> <api-key>\n")
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: b.String(),
		Data: map[string]interface{}{
			"active": cfg.Active,
		},
	})
}

func (c *Console) aiSetProvider(args []string) {
	if len(args) != 1 {
		emitError(c.mode, "ai", "Usage: ai provider <ollama|openai|anthropic|bedrock|kimi>")
		return
	}
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := cfg.SetActive(args[0]); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := llm.SaveFile(llm.DefaultConfigPath, cfg); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	meta, _ := llm.LookupProvider(args[0])
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: fmt.Sprintf("> Active LLM provider: %s (%s)", meta.ID, meta.Label),
		Data: map[string]string{
			"provider": string(meta.ID),
		},
	})
}

func (c *Console) aiSetKey(args []string) {
	if len(args) < 1 {
		emitError(c.mode, "ai", "Usage: ai key <provider>")
		return
	}
	provider := args[0]
	meta, err := llm.LookupProvider(provider)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if !meta.NeedsKey {
		emitError(c.mode, "ai", fmt.Sprintf("%s does not require an API key", meta.Label))
		return
	}

	if len(args) >= 2 {
		emitError(c.mode, "ai", "Do not pass API keys on the command line (saved in shell history). Use: ai key "+provider)
		return
	}

	apiKey := ""
	if c.mode == OutputHuman && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "> Enter %s API key: ", meta.Label)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			emitError(c.mode, "ai", fmt.Sprintf("read API key: %v", err))
			return
		}
		apiKey = string(raw)
	} else {
		emitError(c.mode, "ai", "Usage: ai key <provider> (interactive terminal required for hidden prompt)")
		return
	}
	if strings.TrimSpace(apiKey) == "" {
		emitError(c.mode, "ai", "API key cannot be empty")
		return
	}

	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := cfg.SetAPIKey(provider, apiKey, true); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := llm.SaveFile(llm.DefaultConfigPath, cfg); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: fmt.Sprintf("> Saved %s API key and set provider active (%s)", meta.Label, llm.MaskKey(apiKey)),
		Data: map[string]string{
			"provider": provider,
		},
	})
}

func (c *Console) aiSetModel(args []string) {
	if len(args) != 2 {
		emitError(c.mode, "ai", "Usage: ai model <provider> <model>")
		return
	}
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := cfg.SetModel(args[0], args[1]); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	if err := llm.SaveFile(llm.DefaultConfigPath, cfg); err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: fmt.Sprintf("> %s model set to %s", args[0], args[1]),
	})
}

func (c *Console) aiShowConfig() {
	cfg, err := llm.LoadFile(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}
	active, err := cfg.ActiveConfig()
	if err != nil && cfg.HasAPIKey(cfg.Active) {
		emitError(c.mode, "ai", err.Error())
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\nActive provider: %s\n", cfg.Active))
	if active.Provider != "" {
		b.WriteString(fmt.Sprintf("  base_url: %s\n", active.BaseURL))
		b.WriteString(fmt.Sprintf("  model:    %s\n", active.Model))
	}
	b.WriteString("\nSaved providers:\n")
	for _, p := range llm.SupportedProviders() {
		s := cfg.Providers[string(p.ID)]
		b.WriteString(fmt.Sprintf("  %-10s key=%-14s model=%s\n",
			p.ID, llm.MaskKey(s.APIKey), firstNonEmpty(s.Model, p.DefaultModel)))
	}
	b.WriteString(fmt.Sprintf("\nConfig file: %s\n", expandErebusPath(llm.DefaultConfigPath)))
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: b.String(),
		Data: map[string]interface{}{
			"active": cfg.Active,
			"model":  active.Model,
		},
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func expandErebusPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + p[1:]
		}
	}
	return p
}