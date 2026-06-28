package llm

import (
	"context"
	"fmt"

	openai "github.com/sashabaranov/go-openai"
)

// Client wraps an OpenAI-compatible chat API (Ollama, OpenAI, etc.).
type Client struct {
	client *openai.Client
	model  string
	cfg    Config
}

// NewClient creates a chat client from config.
func NewClient(cfg Config) *Client {
	clientCfg := openai.DefaultConfig(cfg.APIKey)
	clientCfg.BaseURL = cfg.BaseURL
	return &Client{
		client: openai.NewClientWithConfig(clientCfg),
		model:  cfg.Model,
		cfg:    cfg,
	}
}

// Provider returns the configured provider name (ollama, openai, custom).
func (c *Client) Provider() string {
	return c.cfg.Provider
}

// Model returns the configured model name.
func (c *Client) Model() string {
	return c.model
}

// Chat sends a single user message with optional system prompt and returns assistant text.
func (c *Client) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	messages := []openai.ChatCompletionMessage{}
	if systemPrompt != "" {
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: systemPrompt,
		})
	}
	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: userMessage,
	})
	return c.ChatMessages(ctx, messages)
}

// ChatMessages sends a full message history and returns assistant text.
func (c *Client) ChatMessages(ctx context.Context, messages []openai.ChatCompletionMessage) (string, error) {
	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:    c.model,
		Messages: messages,
	})
	if err != nil {
		return "", fmt.Errorf("%s chat (%s): %w", c.cfg.Provider, c.model, err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("empty response from %s", c.cfg.Provider)
	}
	return resp.Choices[0].Message.Content, nil
}