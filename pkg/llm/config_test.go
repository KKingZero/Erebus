package llm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigOllama(t *testing.T) {
	cfg := DefaultConfig()
	if !strings.Contains(cfg.BaseURL, "11434") {
		t.Fatalf("expected ollama url, got %s", cfg.BaseURL)
	}
	if cfg.Model == "" {
		t.Fatal("expected default model")
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/erebus-llm-test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "ollama" {
		t.Fatalf("provider %q", cfg.Provider)
	}
}

func TestNormalizeBareOllamaHost(t *testing.T) {
	cfg := Config{BaseURL: "http://localhost:11434", Provider: "ollama", APIKey: "ollama", Model: "mistral"}
	cfg.normalize()
	if cfg.BaseURL != "http://localhost:11434/v1" {
		t.Fatalf("base url %q", cfg.BaseURL)
	}
}

func TestOpenAIEnvFallback(t *testing.T) {
	os.Setenv("OPENAI_API_KEY", "sk-test")
	defer os.Unsetenv("OPENAI_API_KEY")

	cfg := DefaultFileConfig()
	cfg.Active = "openai"
	cfg.Providers["openai"] = ProviderSettings{Model: "gpt-4o"}
	cfg.applyEnvToAll()

	active, err := cfg.ActiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	if active.APIKey != "sk-test" {
		t.Fatalf("api key %q", active.APIKey)
	}
}

func TestLegacySingleProviderYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "llm.yaml")
	content := `provider: openai
base_url: "https://api.openai.com/v1"
api_key: "sk-legacy"
model: "gpt-4o-mini"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "openai" || cfg.APIKey != "sk-legacy" || cfg.Model != "gpt-4o-mini" {
		t.Fatalf("got %+v", cfg)
	}
}

func TestSetAPIKeyRequiresKeyForOpenAI(t *testing.T) {
	cfg := DefaultFileConfig()
	cfg.Active = "openai"
	_, err := cfg.ActiveConfig()
	if err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestBedrockBaseURLFromRegion(t *testing.T) {
	cfg := resolveProvider(ProviderBedrock, ProviderSettings{
		APIKey: "bedrock-key",
		Region: "us-west-2",
		Model:  "us.anthropic.claude-sonnet-4-6",
	})
	if !strings.Contains(cfg.BaseURL, "us-west-2") {
		t.Fatalf("base url %q", cfg.BaseURL)
	}
}

func TestMaskKey(t *testing.T) {
	if MaskKey("sk-1234567890abcdef") != "sk-1...cdef" {
		t.Fatalf("mask %q", MaskKey("sk-1234567890abcdef"))
	}
}