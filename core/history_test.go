package core

import (
	"os"
	"testing"
)

func TestCommandMayContainSecret(t *testing.T) {
	if !commandMayContainSecret("ai key openai sk-secret") {
		t.Fatal("expected secret command")
	}
	if commandMayContainSecret("ai key openai") {
		t.Fatal("provider only should not scrub")
	}
	if !commandMayContainSecret("ai setup sk-secret") {
		t.Fatal("setup with trailing secret should scrub")
	}
	if commandMayContainSecret("ai setup") {
		t.Fatal("plain setup should not scrub")
	}
	if commandMayContainSecret("ai providers") {
		t.Fatal("unrelated command")
	}
}

func TestScrubLastHistoryEntry(t *testing.T) {
	path := t.TempDir() + "/history"
	if err := os.WriteFile(path, []byte("help\nai key openai sk-leak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scrubLastHistoryEntry(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "help\n" {
		t.Fatalf("got %q", string(data))
	}
}