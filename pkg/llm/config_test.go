package llm

import (
	"os"
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

func TestOpenAIEnvOverride(t *testing.T) {
	os.Setenv("OPENAI_API_KEY", "sk-test")
	defer os.Unsetenv("OPENAI_API_KEY")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	if cfg.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("base url %q", cfg.BaseURL)
	}
}