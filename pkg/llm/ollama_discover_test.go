package llm

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLargestOllamaModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[
			{"name":"small:latest","size":100},
			{"name":"big:latest","size":9000},
			{"name":"mid:latest","size":500}
		]}`))
	}))
	defer srv.Close()

	got, err := LargestOllamaModel(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != "big:latest" {
		t.Fatalf("got %q", got)
	}
}

func TestListOllamaModelsTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3.2:latest"},{"name":"mistral:latest"}]}`))
	}))
	defer srv.Close()

	names, err := ListOllamaModels(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("got %v", names)
	}
}

func TestListOllamaModelsAuthAndV1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/tags" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"cloud-a"},{"id":"cloud-b"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	names, err := ListOllamaModels(srv.URL+"/v1", "secret-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "cloud-a" {
		t.Fatalf("got %v", names)
	}
}

func TestPickOllamaModel(t *testing.T) {
	avail := []string{"nomic-embed-text", "llama3.2:latest", "mistral:latest"}
	if g := PickOllamaModel("llama3.2", avail, "x"); g != "llama3.2:latest" {
		t.Fatalf("preferred match: %q", g)
	}
	if g := PickOllamaModel("", avail, "x"); g != "llama3.2:latest" {
		t.Fatalf("skip embed: %q", g)
	}
	if g := PickOllamaModel("gone", nil, "fallback"); g != "gone" {
		t.Fatalf("keep preferred offline: %q", g)
	}
	if g := PickOllamaModel("", nil, "fallback"); g != "fallback" {
		t.Fatalf("fallback: %q", g)
	}
}

func TestNormalizeAndDetectOllama(t *testing.T) {
	if g := NormalizeOllamaBaseURL("localhost:11434"); g != "http://localhost:11434/v1" {
		t.Fatalf("normalize host: %q", g)
	}
	if g := NormalizeOllamaBaseURL("https://ollama.com"); g != "https://ollama.com/v1" {
		t.Fatalf("normalize cloud: %q", g)
	}
	if DetectOllamaMode("https://ollama.com/v1") != OllamaModeCloud {
		t.Fatal("cloud detect")
	}
	if DetectOllamaMode("http://localhost:11434/v1") != OllamaModeLocal {
		t.Fatal("local detect")
	}
	if DetectOllamaMode("http://gpu:11434/v1") != OllamaModeRemote {
		t.Fatal("remote detect")
	}
	if !OllamaNeedsAPIKey("https://ollama.com/v1") {
		t.Fatal("cloud needs key")
	}
}

func TestResolveOllamaModelPrefersConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"models":[{"name":"a:latest"},{"name":"b:latest"}]}`))
	}))
	defer srv.Close()

	cfg, err := ResolveOllamaModel(Config{
		BaseURL:  srv.URL + "/v1",
		APIKey:   "ollama",
		Model:    "b",
		Provider: "ollama",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Model != "b:latest" {
		t.Fatalf("model %q", cfg.Model)
	}
}
