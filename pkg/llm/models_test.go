package llm

import "testing"

func TestNormalizeAPIKeyCollapsesRepeats(t *testing.T) {
	base := "sk-ant-api03-ABCDEFGHabcdefgh0123456789ABCDEFGHabcdefgh0123456789ABCD"
	got := NormalizeAPIKey(base + base + base)
	if got != base {
		t.Fatalf("got len=%d want len=%d", len(got), len(base))
	}
}

func TestNormalizeAPIKeyTrims(t *testing.T) {
	if NormalizeAPIKey("  sk-test  ") != "sk-test" {
		t.Fatal("trim failed")
	}
}

func TestSuggestedModelsAnthropic(t *testing.T) {
	ms := SuggestedModels("anthropic")
	if len(ms) == 0 || ms[0] != "claude-sonnet-4-6" {
		t.Fatalf("unexpected models: %v", ms)
	}
}
