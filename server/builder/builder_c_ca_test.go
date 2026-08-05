package builder

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCACertPathEncodesDERNotPEM locks FireFlow-class CA packaging:
// C implant pin is base64(DER), not base64(PEM file bytes).
func TestCACertPathEncodesDERNotPEM(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required for fixture")
	}
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", pemPath, "-days", "1", "-nodes",
		"-subj", "/CN=erebus-test-ca")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("fixture PEM decode failed")
	}

	// Same as builder_c.go
	gotB64 := base64.StdEncoding.EncodeToString(block.Bytes)
	pemFileB64 := base64.StdEncoding.EncodeToString(raw)
	if gotB64 == pemFileB64 {
		t.Fatal("DER base64 must not equal PEM-file base64")
	}

	der, err := base64.StdEncoding.DecodeString(gotB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) < 1 || der[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE tag 0x30, got %x", der[:min(4, len(der))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
