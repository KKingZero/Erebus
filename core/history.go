package core

import (
	"os"
	"path/filepath"
	"strings"
)

// erebusHistoryPath returns a private history file under ~/.erebus.
func erebusHistoryPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "erebus_history")
	}
	dir := filepath.Join(home, ".erebus")
	_ = os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, "history")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_ = f.Close()
		_ = os.Chmod(path, 0o600)
	}
	return path
}

// commandMayContainSecret reports whether a REPL line could embed credentials.
func commandMayContainSecret(line string) bool {
	parts := strings.Fields(line)
	// ai key <provider> <secret...>
	return len(parts) >= 4 && parts[0] == "ai" && parts[1] == "key"
}

// scrubLastHistoryEntry removes the most recent line from the history file.
func scrubLastHistoryEntry(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 0 {
		return
	}
	lines = lines[:len(lines)-1]
	out := strings.Join(lines, "\n")
	if len(lines) > 0 {
		out += "\n"
	}
	_ = os.WriteFile(path, []byte(out), 0o600)
}