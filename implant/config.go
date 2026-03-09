package implant

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Build-time injected via ldflags
var (
	implantID     = ""
	implantSecret = ""
	callbackURL   = "https://127.0.0.1:443"
	sleepMs       = "5000"
	jitterPct     = "20"
	caCertPEM     = "" // Base64-encoded CA cert PEM, injected at build time
)

type Config struct {
	ImplantID string
	Secret    []byte
	Callback  string
	Sleep     time.Duration
	JitterPct int
	CACertPEM string // Decoded CA cert PEM for TLS pinning
}

func LoadConfig() (*Config, error) {
	if implantID == "" {
		return nil, fmt.Errorf("implant ID not set (build with ldflags)")
	}
	if implantSecret == "" {
		return nil, fmt.Errorf("implant secret not set (build with ldflags)")
	}

	secret, err := hex.DecodeString(implantSecret)
	if err != nil {
		return nil, fmt.Errorf("decode implant secret: %w", err)
	}

	sleep, _ := strconv.Atoi(sleepMs)
	if sleep <= 0 {
		sleep = 5000
	}

	jitter, _ := strconv.Atoi(jitterPct)
	if jitter < 0 || jitter > 100 {
		jitter = 20
	}

	// Decode base64-encoded CA cert PEM if provided
	var decodedCACert string
	if caCertPEM != "" {
		decoded, err := base64.StdEncoding.DecodeString(caCertPEM)
		if err == nil {
			decodedCACert = string(decoded)
		}
	}

	return &Config{
		ImplantID: implantID,
		Secret:    secret,
		Callback:  callbackURL,
		Sleep:     time.Duration(sleep) * time.Millisecond,
		JitterPct: jitter,
		CACertPEM: decodedCACert,
	}, nil
}
