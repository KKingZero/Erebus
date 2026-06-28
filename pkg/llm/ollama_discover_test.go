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