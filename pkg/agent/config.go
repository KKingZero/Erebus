package agent

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultConfigPath = "~/.erebus/agent.yaml"

// Config holds agent connection and LLM settings.
type Config struct {
	Server       string         `yaml:"server"`
	Cert         string         `yaml:"cert"`
	Key          string         `yaml:"key"`
	CA           string         `yaml:"ca"`
	ApproverCert string         `yaml:"approver_cert"` // dual-control seat (CN approver)
	ApproverKey  string         `yaml:"approver_key"`
	LLM          LLMConfig      `yaml:"llm"`
	Autonomy     AutonomyConfig `yaml:"autonomy"`
}

type LLMConfig struct {
	BaseURL string `yaml:"base_url"`
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
}

type AutonomyConfig struct {
	MaxSteps    int  `yaml:"max_steps"`
	AutoApprove bool `yaml:"auto_approve"`
}

// LoadConfig reads YAML from path, expanding ~ and ${ENV} in string fields.
func LoadConfig(path string) (*Config, error) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadConfigOptional loads agent config when present; returns error if file missing or invalid.
func LoadConfigOptional(path string) (*Config, error) {
	path = expandPath(path)
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return loadConfigFile(path)
}

func loadConfigFile(path string) (*Config, error) {
	path = expandPath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.expandEnv()
	cfg.setDefaults()
	return cfg, nil
}

func (c *Config) expandEnv() {
	c.Server = expandEnv(c.Server)
	c.Cert = expandPath(expandEnv(c.Cert))
	c.Key = expandPath(expandEnv(c.Key))
	c.CA = expandPath(expandEnv(c.CA))
	c.ApproverCert = expandPath(expandEnv(c.ApproverCert))
	c.ApproverKey = expandPath(expandEnv(c.ApproverKey))
	c.LLM.BaseURL = expandEnv(c.LLM.BaseURL)
	c.LLM.APIKey = expandEnv(c.LLM.APIKey)
	c.LLM.Model = expandEnv(c.LLM.Model)
}

func (c *Config) setDefaults() {
	if c.Server == "" {
		c.Server = "127.0.0.1:50051"
	}
	if c.LLM.BaseURL == "" {
		if os.Getenv("OPENAI_API_KEY") != "" {
			c.LLM.BaseURL = "https://api.openai.com/v1"
		} else {
			host := strings.TrimSuffix(os.Getenv("OLLAMA_HOST"), "/")
			if host == "" {
				host = "http://localhost:11434"
			}
			c.LLM.BaseURL = host + "/v1"
		}
	}
	if c.LLM.Model == "" {
		if strings.Contains(c.LLM.BaseURL, "openai.com") {
			c.LLM.Model = "gpt-4o"
		} else if v := os.Getenv("OLLAMA_MODEL"); v != "" {
			c.LLM.Model = v
		} else {
			c.LLM.Model = "llama3.2"
		}
	}
	if c.LLM.APIKey == "" {
		if os.Getenv("OPENAI_API_KEY") != "" {
			c.LLM.APIKey = os.Getenv("OPENAI_API_KEY")
		} else {
			c.LLM.APIKey = "ollama"
		}
	}
	if c.Autonomy.MaxSteps <= 0 {
		c.Autonomy.MaxSteps = 50
	}
}

func (c *Config) validate() error {
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return fmt.Errorf("config must set cert, key, and ca paths")
	}
	return nil
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

func expandEnv(s string) string {
	return os.ExpandEnv(s)
}