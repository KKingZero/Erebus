package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// OllamaLocalBaseURL is the default local OpenAI-compatible endpoint.
	OllamaLocalBaseURL = "http://localhost:11434/v1"
	// OllamaCloudBaseURL is Ollama Cloud's OpenAI-compatible endpoint.
	OllamaCloudBaseURL = "https://ollama.com/v1"
	// OllamaAPIKeyEnv is the env var for Ollama Cloud (and authenticated hosts).
	OllamaAPIKeyEnv = "OLLAMA_API_KEY"
)

// OllamaMode is a setup/runtime hint derived from base URL (not stored separately).
type OllamaMode string

const (
	OllamaModeLocal  OllamaMode = "local"
	OllamaModeRemote OllamaMode = "remote"
	OllamaModeCloud  OllamaMode = "cloud"
)

// IsOllamaCloudURL reports whether baseURL points at Ollama Cloud.
func IsOllamaCloudURL(baseURL string) bool {
	u := strings.ToLower(strings.TrimSpace(baseURL))
	return strings.Contains(u, "ollama.com")
}

// DetectOllamaMode classifies a base URL as local, remote, or cloud.
func DetectOllamaMode(baseURL string) OllamaMode {
	if IsOllamaCloudURL(baseURL) {
		return OllamaModeCloud
	}
	u := strings.ToLower(strings.TrimSpace(baseURL))
	if u == "" || strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1") {
		return OllamaModeLocal
	}
	return OllamaModeRemote
}

// NormalizeOllamaBaseURL ensures an OpenAI-compatible /v1 base URL.
func NormalizeOllamaBaseURL(baseURL string) string {
	u := strings.TrimSpace(baseURL)
	if u == "" {
		return OllamaLocalBaseURL
	}
	u = strings.TrimSuffix(u, "/")
	// Allow bare host:port
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	if !strings.HasSuffix(u, "/v1") {
		u = u + "/v1"
	}
	return u
}

// ollamaRoot strips a trailing /v1 for native Ollama API paths.
func ollamaRoot(baseURL string) string {
	u := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	u = strings.TrimSuffix(u, "/v1")
	return u
}

func ollamaHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second}
}

func setOllamaAuth(req *http.Request, apiKey string) {
	key := strings.TrimSpace(apiKey)
	if key == "" || key == "ollama" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
}

// ListOllamaModels returns installed/available model names.
// Tries native GET /api/tags first, then OpenAI-compatible GET /v1/models.
// apiKey is optional for local; required for Ollama Cloud.
func ListOllamaModels(baseURL, apiKey string) ([]string, error) {
	baseURL = NormalizeOllamaBaseURL(baseURL)
	root := ollamaRoot(baseURL)
	client := ollamaHTTPClient()

	var lastErr error
	if names, err := listOllamaTags(client, root, apiKey); err == nil && len(names) > 0 {
		return names, nil
	} else if err != nil {
		lastErr = err
	}

	if names, err := listOllamaV1Models(client, baseURL, apiKey); err == nil && len(names) > 0 {
		return names, nil
	} else if err != nil {
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no models found at %s — pull one or check API key", root)
}

func listOllamaTags(client *http.Client, root, apiKey string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, root+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	setOllamaAuth(req, apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama unreachable at %s: %w", root, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama /api/tags: HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("parse ollama tags: %w", err)
	}
	out := make([]string, 0, len(payload.Models))
	for _, m := range payload.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func listOllamaV1Models(client *http.Client, baseURL, apiKey string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(baseURL, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	setOllamaAuth(req, apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama unreachable at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama /v1/models: HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("parse ollama /v1/models: %w", err)
	}
	out := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ProbeOllama checks connectivity and returns available models.
func ProbeOllama(baseURL, apiKey string) (models []string, err error) {
	return ListOllamaModels(baseURL, apiKey)
}

// PickOllamaModel chooses: preferred if available → first non-embedding → first → fallback.
func PickOllamaModel(preferred string, available []string, fallback string) string {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" {
		for _, n := range available {
			if n == preferred {
				return n
			}
		}
		// Allow "llama3.2" to match "llama3.2:latest"
		for _, n := range available {
			base := strings.Split(n, ":")[0]
			if base == preferred || n == preferred+":latest" {
				return n
			}
		}
	}
	for _, n := range available {
		low := strings.ToLower(n)
		if strings.Contains(low, "embed") || strings.Contains(low, "embedding") {
			continue
		}
		return n
	}
	if len(available) > 0 {
		return available[0]
	}
	if preferred != "" {
		return preferred
	}
	if fallback != "" {
		return fallback
	}
	return "llama3.2"
}

// LargestOllamaModel returns the biggest model installed locally (by reported size).
// Deprecated for defaults; kept for callers/tests. Prefer ListOllamaModels + PickOllamaModel.
func LargestOllamaModel(host string) (string, error) {
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		host = "http://localhost:11434"
	}
	host = strings.TrimSuffix(host, "/v1")

	client := ollamaHTTPClient()
	req, err := http.NewRequest(http.MethodGet, host+"/api/tags", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
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

// ResolveOllamaModel lists models and picks a smart default:
// configured model if still available → first useful available → named default.
func ResolveOllamaModel(cfg Config) (Config, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = OllamaLocalBaseURL
	}
	cfg.BaseURL = NormalizeOllamaBaseURL(cfg.BaseURL)
	models, err := ListOllamaModels(cfg.BaseURL, cfg.APIKey)
	if err != nil {
		return cfg, err
	}
	cfg.Model = PickOllamaModel(cfg.Model, models, "llama3.2")
	cfg.Provider = string(ProviderOllama)
	return cfg, nil
}

// OllamaNeedsAPIKey reports whether this Ollama endpoint needs a real API key.
func OllamaNeedsAPIKey(baseURL string) bool {
	return IsOllamaCloudURL(baseURL)
}
