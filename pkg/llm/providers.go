package llm

import "fmt"

// ProviderID identifies a supported LLM backend.
type ProviderID string

const (
	ProviderOllama    ProviderID = "ollama"
	ProviderOpenAI    ProviderID = "openai"
	ProviderAnthropic ProviderID = "anthropic"
	ProviderGrok      ProviderID = "grok" // xAI Grok (api.x.ai)
	ProviderBedrock   ProviderID = "bedrock"
	ProviderKimi      ProviderID = "kimi"
	ProviderGemini    ProviderID = "gemini"
)

// ProviderMeta describes defaults and env fallbacks for a provider.
type ProviderMeta struct {
	ID          ProviderID
	Label       string
	BaseURL     string
	DefaultModel string
	APIKeyEnv   string
	NeedsKey    bool
	Region      string // bedrock only
}

var supportedProviders = []ProviderMeta{
	{
		ID:           ProviderOllama,
		Label:        "Ollama (local / remote / cloud)",
		BaseURL:      OllamaLocalBaseURL,
		DefaultModel: "llama3.2",
		APIKeyEnv:    OllamaAPIKeyEnv, // optional local; required for Ollama Cloud
		NeedsKey:     false,           // local/remote usually; cloud enforced separately
	},
	{
		ID:           ProviderOpenAI,
		Label:        "OpenAI",
		BaseURL:      "https://api.openai.com/v1",
		DefaultModel: "gpt-4o",
		APIKeyEnv:    "OPENAI_API_KEY",
		NeedsKey:     true,
	},
	{
		ID:           ProviderAnthropic,
		Label:        "Anthropic",
		BaseURL:      "https://api.anthropic.com/v1",
		DefaultModel: "claude-sonnet-4-6",
		APIKeyEnv:    "ANTHROPIC_API_KEY",
		NeedsKey:     true,
	},
	{
		ID:           ProviderGrok,
		Label:        "Grok (xAI)",
		BaseURL:      "https://api.x.ai/v1",
		DefaultModel: "grok-4.5",
		APIKeyEnv:    "XAI_API_KEY",
		NeedsKey:     true,
	},
	{
		ID:           ProviderBedrock,
		Label:        "Amazon Bedrock",
		BaseURL:      "https://bedrock-mantle.us-east-1.api.aws/v1",
		DefaultModel: "us.anthropic.claude-sonnet-4-6",
		APIKeyEnv:    "AWS_BEARER_TOKEN_BEDROCK",
		NeedsKey:     true,
		Region:       "us-east-1",
	},
	{
		ID:           ProviderKimi,
		Label:        "Kimi (Moonshot K series)",
		BaseURL:      "https://api.moonshot.ai/v1",
		DefaultModel: "kimi-k2.6",
		APIKeyEnv:    "MOONSHOT_API_KEY",
		NeedsKey:     true,
	},
	{
		ID:           ProviderGemini,
		Label:        "Google Gemini",
		BaseURL:      "https://generativelanguage.googleapis.com/v1beta/openai",
		DefaultModel: "gemini-2.0-flash",
		APIKeyEnv:    "GOOGLE_API_KEY",
		NeedsKey:     true,
	},
}

// SupportedProviders returns built-in provider metadata.
func SupportedProviders() []ProviderMeta {
	out := make([]ProviderMeta, len(supportedProviders))
	copy(out, supportedProviders)
	return out
}

// LookupProvider returns metadata for id or an error.
func LookupProvider(id string) (ProviderMeta, error) {
	for _, p := range supportedProviders {
		if string(p.ID) == id {
			return p, nil
		}
	}
	return ProviderMeta{}, fmt.Errorf("unknown provider %q (supported: ollama, openai, anthropic, grok, bedrock, kimi, gemini)", id)
}

func bedrockBaseURL(region string) string {
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://bedrock-mantle.%s.api.aws/v1", region)
}