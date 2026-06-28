package aitui

// modelChoice is a user-facing label mapped to an LLM provider id.
type modelChoice struct {
	Label    string
	Provider string
}

// pickerModels are shown in the Tab model selector (order matters).
var pickerModels = []modelChoice{
	{Label: "Claude", Provider: "anthropic"},
	{Label: "Gemini", Provider: "gemini"},
	{Label: "ChatGPT", Provider: "openai"},
	{Label: "Kimi", Provider: "kimi"},
	{Label: "local ai", Provider: "ollama"},
}

func pickerIndexForProvider(provider string) int {
	for i, m := range pickerModels {
		if m.Provider == provider {
			return i
		}
	}
	return 0
}