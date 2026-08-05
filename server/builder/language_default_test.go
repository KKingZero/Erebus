package builder

import (
	"strings"
	"testing"
)

func TestBuild_DefaultLanguageIsC(t *testing.T) {
	// Empty language → C path. HTTPS without CACertPath fails closed.
	_, err := Build(&BuildRequest{
		Language:  "",
		OS:        "linux",
		Arch:      "amd64",
		Format:    FormatEXE,
		Transport: "https",
	})
	if err == nil {
		t.Fatal("expected error for C HTTPS without CACertPath")
	}
	if !strings.Contains(err.Error(), "CACertPath") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_ExplicitGoStillAccepted(t *testing.T) {
	// Should not route to BuildC; will fail later on missing project/tooling if run fully.
	// We only assert it does not reject language go immediately as unsupported.
	_, err := Build(&BuildRequest{
		Language:   "go",
		OS:         "linux",
		Arch:       "amd64",
		Format:     FormatEXE,
		Callbacks:  []string{"https://127.0.0.1:443"},
		SleepMs:    5000,
		JitterPct:  10,
		CACertPath: "/nonexistent-ca-for-test.pem", // HTTPS requires path; fails on stat/read
	})
	// May fail on CA path or go build; must not be "unsupported language"
	if err != nil && strings.Contains(err.Error(), "unsupported implant language") {
		t.Fatalf("go language rejected: %v", err)
	}
}

func TestBuild_HTTPSRequiresCACertPath(t *testing.T) {
	_, err := Build(&BuildRequest{
		Language:  "go",
		OS:        "linux",
		Arch:      "amd64",
		Format:    FormatEXE,
		Transport: "https",
		Callbacks: []string{"https://127.0.0.1:443"},
		SleepMs:   5000,
		JitterPct: 10,
	})
	if err == nil {
		t.Fatal("expected error when CACertPath missing for HTTPS")
	}
	if !strings.Contains(err.Error(), "CACertPath") {
		t.Fatalf("expected CACertPath error, got: %v", err)
	}
}
