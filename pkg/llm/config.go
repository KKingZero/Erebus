package llm

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultConfigPath = "~/.erebus/llm.yaml"

// Config is the resolved settings for the active provider (OpenAI-compatible API).
type Config struct {
	BaseURL  string `yaml:"base_url"`
	APIKey   string `yaml:"api_key"`
	Model    string `yaml:"model"`
	Provider string `yaml:"provider"`
}

// ProviderSettings holds per-provider credentials and overrides.
type ProviderSettings struct {
	APIKey  string `yaml:"api_key,omitempty"`
	Model   string `yaml:"model,omitempty"`
	BaseURL string `yaml:"base_url,omitempty"`
	Region  string `yaml:"region,omitempty"` // bedrock
}

// FileConfig is the on-disk multi-provider layout.
type FileConfig struct {
	Active    string                      `yaml:"active"`
	Providers map[string]ProviderSettings `yaml:"providers"`

	// Legacy single-provider fields (still supported).
	Provider string `yaml:"provider,omitempty"`
	BaseURL  string `yaml:"base_url,omitempty"`
	APIKey   string `yaml:"api_key,omitempty"`
	Model    string `yaml:"model,omitempty"`
}

// DefaultFileConfig returns a new file config with Ollama active.
func DefaultFileConfig() FileConfig {
	cfg := FileConfig{
		Active:    string(ProviderOllama),
		Providers: make(map[string]ProviderSettings),
	}
	for _, p := range supportedProviders {
		cfg.Providers[string(p.ID)] = defaultProviderSettings(p)
	}
	return cfg
}

func defaultProviderSettings(p ProviderMeta) ProviderSettings {
	s := ProviderSettings{
		Model:   p.DefaultModel,
		BaseURL: p.BaseURL,
	}
	if p.ID == ProviderOllama {
		s.APIKey = "ollama"
	}
	if p.ID == ProviderBedrock {
		s.Region = p.Region
	}
	return s
}

// DefaultConfig returns resolved Ollama defaults.
func DefaultConfig() Config {
	return resolveProvider(ProviderOllama, ProviderSettings{
		APIKey:  "ollama",
		Model:   "llama3.2",
		BaseURL: OllamaLocalBaseURL,
	})
}

// Load reads ~/.erebus/llm.yaml and returns the active provider config.
func Load(path string) (Config, error) {
	fileCfg, err := LoadFile(path)
	if err != nil {
		return Config{}, err
	}
	return fileCfg.ActiveConfig()
}

// LoadFile reads the full multi-provider config from disk.
func LoadFile(path string) (FileConfig, error) {
	cfg := DefaultFileConfig()
	path = expandPath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.applyEnvToAll()
			return cfg, nil
		}
		return cfg, fmt.Errorf("read llm config %s: %w", path, err)
	}

	parsed := FileConfig{}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return cfg, fmt.Errorf("parse llm config: %w", err)
	}
	cfg = mergeFileConfig(cfg, parsed)
	cfg.applyEnvToAll()
	cfg.normalize()
	return cfg, nil
}

// SaveFile writes the config with restrictive permissions.
func SaveFile(path string, cfg FileConfig) error {
	path = expandPath(path)
	cfg.normalize()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal llm config: %w", err)
	}
	if err := os.MkdirAll(expandPath("~/.erebus"), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write llm config: %w", err)
	}
	return nil
}

// ActiveConfig resolves the currently selected provider.
func (f *FileConfig) ActiveConfig() (Config, error) {
	active := f.Active
	if active == "" {
		active = string(ProviderOllama)
	}
	settings, ok := f.Providers[active]
	if !ok {
		return Config{}, fmt.Errorf("active provider %q not configured", active)
	}
	cfg := resolveProvider(ProviderID(active), settings)
	if cfg.Provider == string(ProviderOllama) && OllamaNeedsAPIKey(cfg.BaseURL) {
		if cfg.APIKey == "" || cfg.APIKey == "ollama" {
			return cfg, fmt.Errorf("Ollama Cloud API key not set — run: ai setup (or set %s)", OllamaAPIKeyEnv)
		}
	}
	if cfg.Provider != string(ProviderOllama) && cfg.APIKey == "" {
		meta, _ := LookupProvider(active)
		if meta.NeedsKey {
			return cfg, fmt.Errorf("%s API key not set — run: ai setup", meta.Label)
		}
	}
	return cfg, nil
}

// SetAPIKey stores a key for a provider and optionally activates it.
func (f *FileConfig) SetAPIKey(provider, apiKey string, activate bool) error {
	meta, err := LookupProvider(provider)
	if err != nil {
		return err
	}
	if f.Providers == nil {
		f.Providers = make(map[string]ProviderSettings)
	}
	cur := f.Providers[provider]
	if cur.Model == "" {
		cur = defaultProviderSettings(meta)
	}
	cur.APIKey = NormalizeAPIKey(apiKey)
	if meta.ID == ProviderOllama && cur.APIKey == "" && !OllamaNeedsAPIKey(cur.BaseURL) {
		cur.APIKey = "ollama"
	}
	f.Providers[provider] = cur
	if activate {
		f.Active = provider
	}
	return nil
}

// SetBaseURL sets the base URL for a provider (used by Ollama local/remote/cloud).
func (f *FileConfig) SetBaseURL(provider, baseURL string) error {
	meta, err := LookupProvider(provider)
	if err != nil {
		return err
	}
	if f.Providers == nil {
		f.Providers = make(map[string]ProviderSettings)
	}
	cur := f.Providers[provider]
	if cur.Model == "" && cur.BaseURL == "" {
		cur = defaultProviderSettings(meta)
	}
	baseURL = strings.TrimSpace(baseURL)
	if meta.ID == ProviderOllama {
		baseURL = NormalizeOllamaBaseURL(baseURL)
	}
	cur.BaseURL = baseURL
	f.Providers[provider] = cur
	return nil
}

// SetActive switches the active provider.
func (f *FileConfig) SetActive(provider string) error {
	if _, err := LookupProvider(provider); err != nil {
		return err
	}
	if f.Providers == nil {
		f.Providers = make(map[string]ProviderSettings)
	}
	if _, ok := f.Providers[provider]; !ok {
		meta, _ := LookupProvider(provider)
		f.Providers[provider] = defaultProviderSettings(meta)
	}
	f.Active = provider
	return nil
}

// SetModel sets the model for a provider.
func (f *FileConfig) SetModel(provider, model string) error {
	meta, err := LookupProvider(provider)
	if err != nil {
		return err
	}
	if f.Providers == nil {
		f.Providers = make(map[string]ProviderSettings)
	}
	cur := f.Providers[provider]
	if cur.Model == "" {
		cur = defaultProviderSettings(meta)
	}
	cur.Model = strings.TrimSpace(model)
	f.Providers[provider] = cur
	return nil
}

// HasAPIKey reports whether a non-empty key is configured.
func (f *FileConfig) HasAPIKey(provider string) bool {
	s, ok := f.Providers[provider]
	if !ok {
		return false
	}
	if provider == string(ProviderOllama) {
		if OllamaNeedsAPIKey(s.BaseURL) {
			k := strings.TrimSpace(s.APIKey)
			return k != "" && k != "ollama"
		}
		return true
	}
	return strings.TrimSpace(s.APIKey) != ""
}

func mergeFileConfig(base, src FileConfig) FileConfig {
	if src.Active != "" {
		base.Active = src.Active
	}
	if src.Providers != nil {
		if base.Providers == nil {
			base.Providers = make(map[string]ProviderSettings)
		}
		for k, v := range src.Providers {
			cur := base.Providers[k]
			if v.APIKey != "" {
				cur.APIKey = v.APIKey
			}
			if v.Model != "" {
				cur.Model = v.Model
			}
			if v.BaseURL != "" {
				cur.BaseURL = v.BaseURL
			}
			if v.Region != "" {
				cur.Region = v.Region
			}
			base.Providers[k] = cur
		}
	}

	// Legacy top-level single-provider file.
	if src.Provider != "" || src.BaseURL != "" || src.APIKey != "" || src.Model != "" {
		legacyProvider := src.Provider
		if legacyProvider == "" {
			legacyProvider = string(ProviderOllama)
		}
		base.Active = legacyProvider
		cur := base.Providers[legacyProvider]
		if src.APIKey != "" {
			cur.APIKey = src.APIKey
		}
		if src.Model != "" {
			cur.Model = src.Model
		}
		if src.BaseURL != "" {
			cur.BaseURL = src.BaseURL
		}
		base.Providers[legacyProvider] = cur
	}
	return base
}

func (f *FileConfig) applyEnvToAll() {
	for id, settings := range f.Providers {
		f.Providers[id] = applyProviderEnv(ProviderID(id), settings)
	}
}

func applyProviderEnv(id ProviderID, s ProviderSettings) ProviderSettings {
	meta, err := LookupProvider(string(id))
	if err != nil {
		return s
	}
	s.APIKey = os.ExpandEnv(s.APIKey)
	s.Model = os.ExpandEnv(s.Model)
	s.BaseURL = os.ExpandEnv(s.BaseURL)
	s.Region = os.ExpandEnv(s.Region)

	if strings.TrimSpace(s.APIKey) == "" && meta.APIKeyEnv != "" {
		if v := os.Getenv(meta.APIKeyEnv); v != "" {
			s.APIKey = v
		}
	}
	// Local/remote Ollama: dummy key is fine. Cloud needs a real key (env or yaml).
	if id == ProviderOllama && strings.TrimSpace(s.APIKey) == "" && !OllamaNeedsAPIKey(s.BaseURL) {
		s.APIKey = "ollama"
	}
	if id == ProviderOllama && s.BaseURL != "" {
		s.BaseURL = NormalizeOllamaBaseURL(s.BaseURL)
	}
	return s
}

func (f *FileConfig) normalize() {
	if f.Providers == nil {
		f.Providers = make(map[string]ProviderSettings)
	}
	for _, p := range supportedProviders {
		id := string(p.ID)
		if _, ok := f.Providers[id]; !ok {
			f.Providers[id] = defaultProviderSettings(p)
		}
	}
	if f.Active == "" {
		f.Active = string(ProviderOllama)
	}
}

func resolveProvider(id ProviderID, s ProviderSettings) Config {
	meta, _ := LookupProvider(string(id))
	model := s.Model
	if model == "" {
		model = meta.DefaultModel
	}
	baseURL := s.BaseURL
	if baseURL == "" {
		if id == ProviderBedrock {
			baseURL = bedrockBaseURL(s.Region)
		} else {
			baseURL = meta.BaseURL
		}
	}
	apiKey := strings.TrimSpace(s.APIKey)
	if id == ProviderOllama {
		baseURL = NormalizeOllamaBaseURL(baseURL)
		if apiKey == "" && !OllamaNeedsAPIKey(baseURL) {
			apiKey = "ollama"
		}
	}
	cfg := Config{
		BaseURL:  baseURL,
		APIKey:   apiKey,
		Model:    model,
		Provider: string(id),
	}
	cfg.normalize()
	return cfg
}

func (c *Config) normalize() {
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if c.Provider == string(ProviderOllama) {
		c.BaseURL = NormalizeOllamaBaseURL(c.BaseURL)
		if c.APIKey == "" && !OllamaNeedsAPIKey(c.BaseURL) {
			c.APIKey = "ollama"
		}
		return
	}
	if !strings.HasSuffix(c.BaseURL, "/v1") {
		if strings.Contains(c.BaseURL, "11434") {
			c.BaseURL = c.BaseURL + "/v1"
		}
	}
}

// MaskKey returns a redacted key for display.
func MaskKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "(not set)"
	}
	if key == "ollama" {
		return "(local/none)"
	}
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func expandPath(s string) string {
	if strings.HasPrefix(s, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + s[1:]
		}
	}
	return s
}