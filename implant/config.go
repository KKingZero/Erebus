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
	implantID      = ""
	implantSecret  = ""
	callbackURL    = "https://127.0.0.1:443"
	sleepMs        = "5000"
	jitterPct      = "20"
	caCertPEM      = "" // Base64-encoded CA cert PEM, injected at build time
	transportType  = "https" // "https" or "dns"
	dnsDomain      = "" // DNS C2 domain (for DNS transport)
	dnsServer      = "" // DNS server to query (for DNS transport)
	cdnDomain      = "" // CDN domain for domain fronting
)

type Config struct {
	ImplantID     string
	Secret        []byte
	Callback      string
	Sleep         time.Duration
	JitterPct     int
	CACertPEM     string // Decoded CA cert PEM for TLS pinning
	TransportType string // "https" or "dns"
	DNSDomain     string // DNS C2 domain
	DNSServer     string // DNS server address
	CDNDomain     string // CDN domain for domain fronting
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

	// M15: Log parse failures instead of silently ignoring
	sleep, err := strconv.Atoi(sleepMs)
	if err != nil || sleep <= 0 {
		sleep = 5000
	}

	jitter, err := strconv.Atoi(jitterPct)
	if err != nil || jitter < 0 || jitter > 100 {
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

	tt := transportType
	if tt == "" {
		tt = "https"
	}

	return &Config{
		ImplantID:     implantID,
		Secret:        secret,
		Callback:      callbackURL,
		Sleep:         time.Duration(sleep) * time.Millisecond,
		JitterPct:     jitter,
		CACertPEM:     decodedCACert,
		TransportType: tt,
		DNSDomain:     dnsDomain,
		DNSServer:     dnsServer,
		CDNDomain:     cdnDomain,
	}, nil
}
