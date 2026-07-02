package tasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveJailedPathAllowsRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	got, err := resolveJailedPath("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(filepath.Join(dir, "notes.txt"))
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveJailedPathRejectsAbsolute(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := resolveJailedPath("/etc/passwd"); err == nil {
		t.Fatal("expected error for absolute path")
	}
}

func TestResolveJailedPathRejectsParentTraversal(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"../secret", "..", "sub/../../etc/passwd"} {
		if _, err := resolveJailedPath(p); err == nil {
			t.Fatalf("expected error for %q", p)
		}
	}
}

func TestResolveJailedPathNestedRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveJailedPath(filepath.Join("data", "file.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, filepath.Join("data", "file.bin")) {
		t.Fatalf("unexpected resolved path: %s", got)
	}
}