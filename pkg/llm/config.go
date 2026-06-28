package llm

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultConfigPath = "~/.erebus/llm.yaml"

// Config holds OpenAI-compatible LLM settings (Ollama, OpenAI, etc.).
type Config struct {
	BaseURL string `yaml:"base_url"`
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	Provider string `yaml:"provider"` // ollama, openai, custom
}

// DefaultConfig returns Ollama-local defaults.
func DefaultConfig() Config {
	host := strings.TrimSuffix(os.Getenv("OLLAMA_HOST"), "/")
	if host == "" {
		host = "http://localhost:11434"
	}
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "llama3.2"
	}
	return Config{
		BaseURL:  host + "/v1",
		APIKey:   "ollama",
		Model:    model,
		Provider: "ollama",
	}
}

// Load reads YAML from path, falling back to DefaultConfig for unset fields.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	path = expandPath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.applyEnvOverrides()
			return cfg, nil
		}
		return cfg, fmt.Errorf("read llm config %s: %w", path, err)
	}
	fileCfg := Config{}
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("parse llm config: %w", err)
	}
	merge(&cfg, fileCfg)
	cfg.expandEnv()
	cfg.applyEnvOverrides()
	cfg.normalize()
	return cfg, nil
}

func merge(dst *Config, src Config) {
	if src.BaseURL != "" {
		dst.BaseURL = src.BaseURL
	}
	if src.APIKey != "" {
		dst.APIKey = src.APIKey
	}
	if src.Model != "" {
		dst.Model = src.Model
	}
	if src.Provider != "" {
		dst.Provider = src.Provider
	}
}

func (c *Config) expandEnv() {
	c.BaseURL = os.ExpandEnv(c.BaseURL)
	c.APIKey = os.ExpandEnv(c.APIKey)
	c.Model = os.ExpandEnv(c.Model)
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("OPENAI_API_KEY"); v != "" && c.APIKey == "ollama" {
		c.APIKey = v
		if strings.Contains(c.BaseURL, "11434") {
			c.BaseURL = "https://api.openai.com/v1"
			c.Provider = "openai"
			if c.Model == "llama3.2" {
				c.Model = "gpt-4o"
			}
		}
	}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		c.BaseURL = v
	}
	if v := os.Getenv("OPENAI_MODEL"); v != "" {
		c.Model = v
	}
}

func (c *Config) normalize() {
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if !strings.HasSuffix(c.BaseURL, "/v1") {
		// Allow bare Ollama host in YAML.
		if strings.Contains(c.BaseURL, "11434") || c.Provider == "ollama" {
			c.BaseURL = c.BaseURL + "/v1"
		}
	}
	if c.APIKey == "" {
		c.APIKey = "ollama"
	}
	if c.Provider == "" {
		if strings.Contains(c.BaseURL, "11434") || strings.Contains(c.BaseURL, "ollama") {
			c.Provider = "ollama"
		} else {
			c.Provider = "custom"
		}
	}
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