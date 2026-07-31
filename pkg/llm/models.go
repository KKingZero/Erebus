package llm

import "strings"

// SuggestedModels returns curated model IDs for interactive setup.
// The first entry is the recommended default when the provider has no saved model.
func SuggestedModels(provider string) []string {
	switch ProviderID(provider) {
	case ProviderAnthropic:
		return []string{
			"claude-sonnet-4-6",
			"claude-opus-4-8",
			"claude-opus-4-7",
			"claude-haiku-4-5-20251001",
		}
	case ProviderOpenAI:
		return []string{
			"gpt-4o",
			"gpt-4o-mini",
			"o3",
			"o4-mini",
		}
	case ProviderGemini:
		return []string{
			"gemini-2.0-flash",
			"gemini-2.5-pro",
			"gemini-2.5-flash",
		}
	case ProviderKimi:
		return []string{
			"kimi-k2.6",
			"kimi-k2.7-code",
			"moonshot-v1-8k",
		}
	case ProviderBedrock:
		return []string{
			"us.anthropic.claude-sonnet-4-6",
			"us.anthropic.claude-opus-4-6",
			"us.anthropic.claude-haiku-4-5-20251001-v1:0",
		}
	case ProviderOllama:
		return []string{
			"llama3.2",
			"mistral",
			"qwen2.5-coder",
			"gemma3",
		}
	default:
		return nil
	}
}

// NormalizeAPIKey trims whitespace and collapses accidental multi-paste
// (e.g. the same key pasted 2–5 times end-to-end).
func NormalizeAPIKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return key
	}
	// Exact N-fold repetition of a shorter string.
	for n := 2; n <= 5; n++ {
		if len(key)%n != 0 {
			continue
		}
		part := key[:len(key)/n]
		if part != "" && strings.Repeat(part, n) == key {
			return part
		}
	}
	// Multiple Anthropic key prefixes glued together (possibly different keys).
	if c := strings.Count(key, "sk-ant-"); c > 1 {
		rest := key[len("sk-ant-"):]
		if i := strings.Index(rest, "sk-ant-"); i >= 0 {
			return key[:len("sk-ant-")+i]
		}
	}
	return key
}
