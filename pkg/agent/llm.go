package agent

import (
	"context"
	"fmt"

	openai "github.com/sashabaranov/go-openai"
)

// LLM wraps an OpenAI-compatible chat API.
type LLM struct {
	client *openai.Client
	model  string
}

// NewLLM creates a client with configurable base URL.
func NewLLM(cfg LLMConfig) *LLM {
	clientCfg := openai.DefaultConfig(cfg.APIKey)
	clientCfg.BaseURL = cfg.BaseURL
	return &LLM{
		client: openai.NewClientWithConfig(clientCfg),
		model:  cfg.Model,
	}
}

// Chat sends messages and returns the assistant message (may include tool calls).
func (l *LLM) Chat(ctx context.Context, messages []openai.ChatCompletionMessage) (openai.ChatCompletionMessage, error) {
	resp, err := l.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:    l.model,
		Messages: messages,
		Tools:    OpenAITools(),
	})
	if err != nil {
		return openai.ChatCompletionMessage{}, fmt.Errorf("chat completion: %w", err)
	}
	if len(resp.Choices) == 0 {
		return openai.ChatCompletionMessage{}, fmt.Errorf("empty LLM response")
	}
	return resp.Choices[0].Message, nil
}