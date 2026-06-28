package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LargestOllamaModel returns the biggest model installed locally (by reported size).
func LargestOllamaModel(host string) (string, error) {
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		host = "http://localhost:11434"
	}
	host = strings.TrimSuffix(host, "/v1")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(host + "/api/tags")
	if err != nil {
		return "", fmt.Errorf("ollama unreachable at %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama tags: HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("parse ollama tags: %w", err)
	}
	if len(payload.Models) == 0 {
		return "", fmt.Errorf("no ollama models installed — run: ollama pull llama3.2")
	}

	best := payload.Models[0].Name
	var bestSize int64
	for _, m := range payload.Models {
		if m.Size >= bestSize {
			bestSize = m.Size
			best = m.Name
		}
	}
	return best, nil
}

// ResolveOllamaModel picks the largest local model, falling back to configured model.
func ResolveOllamaModel(cfg Config) (Config, error) {
	host := cfg.BaseURL
	if host == "" {
		host = "http://localhost:11434/v1"
	}
	name, err := LargestOllamaModel(host)
	if err != nil {
		return cfg, err
	}
	cfg.Model = name
	cfg.Provider = string(ProviderOllama)
	return cfg, nil
}