package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigExpandEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yaml")
	os.Setenv("TEST_AGENT_KEY", "secret-key")
	defer os.Unsetenv("TEST_AGENT_KEY")

	content := `server: "127.0.0.1:50051"
cert: "` + filepath.Join(dir, "op.pem") + `"
key: "` + filepath.Join(dir, "op-key.pem") + `"
ca: "` + filepath.Join(dir, "ca.pem") + `"
llm:
  api_key: "${TEST_AGENT_KEY}"
  model: "test-model"
`
	for _, f := range []string{"op.pem", "op-key.pem", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.APIKey != "secret-key" {
		t.Fatalf("got api key %q", cfg.LLM.APIKey)
	}
	if cfg.LLM.Model != "test-model" {
		t.Fatalf("got model %q", cfg.LLM.Model)
	}
}