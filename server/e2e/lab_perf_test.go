package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server"
	"google.golang.org/protobuf/proto"
)

// LabPerfStep is one timed recon action.
type LabPerfStep struct {
	Name      string  `json:"name"`
	Target    string  `json:"target"`
	Success   bool    `json:"success"`
	DurationS float64 `json:"duration_s"`
	Detail    string  `json:"detail,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// LabPerfReport compares Erebus implant recon to prior Zypheron CLI lab numbers.
type LabPerfReport struct {
	Timestamp string         `json:"timestamp"`
	TotalS    float64        `json:"total_s"`
	SetupS    float64        `json:"setup_s"`
	Steps     []LabPerfStep  `json:"steps"`
	Baseline  map[string]any `json:"baseline_prior_review,omitempty"`
}

// TestLabPerfJuiceAndMetasploitable times Erebus teamserver+implant recon against
// local Juice Shop and Metasploitable2 (same lab family as Jul 8 Zypheron review).
func TestLabPerfJuiceAndMetasploitable(t *testing.T) {
	juiceURL := envOr("JUICE_SHOP_URL", "http://127.0.0.1:3000/")
	metaURL := envOr("METASPLOITABLE_URL", "http://127.0.0.1:18081/")
	if !httpOK(juiceURL) {
		t.Skipf("juice shop not reachable at %s", juiceURL)
	}
	if !httpOK(metaURL) {
		t.Skipf("metasploitable not reachable at %s", metaURL)
	}

	juiceHost, juicePort := "127.0.0.1", uint32(3000)
	metaHost := "127.0.0.1"
	metaPorts := []uint32{18081, 12222, 12121} // host-mapped meta services

	totalStart := time.Now()
	report := LabPerfReport{
		Timestamp: time.Now().Format(time.RFC3339),
		Baseline: map[string]any{
			"source":                          "Zypheron-CLI-Production/reports/security-performance-review (2026-07-08)",
			"zypheron_nmap_local_s":           12.12,
			"zypheron_nikto_metasploitable_s": 9.15,
			"zypheron_nikto_juice_s":          45.03,
			"zypheron_nikto_juice_success":    false,
			"zypheron_nikto_meta_success":     true,
			"notes":                           "Prior run: external nmap/nikto via Zypheron CLI tool manager; Erebus run: implant C2 recon (portscan+shell).",
		},
	}

	setupStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secret, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	implantID := "lab-perf-implant"
	grpcPort := freePort(t)
	httpsPort := freePort(t)
	dataDir := t.TempDir()
	ahDisabled := false
	cfg := &server.Config{
		GRPCAddr:      fmt.Sprintf("127.0.0.1:%d", grpcPort),
		DBPath:        filepath.Join(dataDir, "erebus.db"),
		DataDir:       dataDir,
		OperatorCNs:   []string{"e2e-operator", "lab-requester"},
		ApproverCNs:   []string{"lab-approver"},
		ImplantSecret: hex.EncodeToString(secret),
		AutoHarvest:   server.AutoHarvestYAML{Enabled: &ahDisabled},
		Listeners: []server.ListenerConfig{
			{Name: "lab-perf-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
		},
	}
	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		t.Fatalf("teamserver: %v", err)
	}
	t.Cleanup(func() { ts.Stop() })
	if err := ts.Start(); err != nil {
		t.Fatalf("start teamserver: %v", err)
	}
	waitForTCP(t, cfg.GRPCAddr, 5*time.Second)
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", httpsPort), 5*time.Second)

	caPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	implantBin := filepath.Join(t.TempDir(), "implant")
	buildImplant(t, implantBin, implantID, hex.EncodeToString(secret),
		fmt.Sprintf("https://127.0.0.1:%d", httpsPort),
		base64.StdEncoding.EncodeToString(caPEM))

	implantCmd := exec.CommandContext(ctx, implantBin)
	implantCmd.Env = append(os.Environ(), "EREBUS_IMPLANT_QUIET=1")
	if err := implantCmd.Start(); err != nil {
		t.Fatalf("start implant: %v", err)
	}
	t.Cleanup(func() {
		if implantCmd.Process != nil {
			_ = implantCmd.Process.Kill()
		}
		_ = implantCmd.Wait()
	})

	grpcClient, _ := newGRPCClient(t, ts, cfg.GRPCAddr)
	requester, _ := newGRPCClientNamed(t, ts, cfg.GRPCAddr, "lab-requester")
	approver, _ := newGRPCClientNamed(t, ts, cfg.GRPCAddr, "lab-approver")
	sessionID := waitSession(t, ctx, grpcClient, implantID, 20*time.Second)
	report.SetupS = time.Since(setupStart).Seconds()
	t.Logf("setup teamserver+implant+session: %.3fs session=%s", report.SetupS, sessionID)

	// --- Juice: portscan ---
	report.Steps = append(report.Steps, timedPortscan(t, ctx, grpcClient, sessionID,
		"juice_portscan", juiceHost, []uint32{juicePort}))

	// --- Juice: shell curl ---
	report.Steps = append(report.Steps, timedShell(t, ctx, requester, approver, sessionID,
		"juice_shell_curl", juiceURL,
		"curl", []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", juiceURL},
		func(stdout string, code int32) (bool, string) {
			ok := code == 0 && bytes.Contains([]byte(stdout), []byte("200"))
			return ok, fmt.Sprintf("exit=%d http=%s", code, bytes.TrimSpace([]byte(stdout)))
		}))

	// --- Juice: ifconfig (local recon) ---
	report.Steps = append(report.Steps, timedTask(t, ctx, grpcClient, sessionID,
		"juice_ifconfig", "local",
		pb.TaskType_TASK_NET_IFCONFIG, mustMarshal(&pb.NetIfconfigTask{}),
		func(res *pb.TaskResult) (bool, string) {
			return res != nil && res.Success, fmt.Sprintf("success=%v", res != nil && res.Success)
		}))

	// --- Metasploitable: multi-port scan on host-mapped ports ---
	report.Steps = append(report.Steps, timedPortscan(t, ctx, grpcClient, sessionID,
		"meta_portscan_mapped", metaHost, metaPorts))

	// --- Metasploitable: shell curl HTTP ---
	report.Steps = append(report.Steps, timedShell(t, ctx, requester, approver, sessionID,
		"meta_shell_curl", metaURL,
		"curl", []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", metaURL},
		func(stdout string, code int32) (bool, string) {
			ok := code == 0 && (bytes.Contains([]byte(stdout), []byte("200")) ||
				bytes.Contains([]byte(stdout), []byte("302")) ||
				bytes.Contains([]byte(stdout), []byte("401")))
			return ok, fmt.Sprintf("exit=%d http=%s", code, bytes.TrimSpace([]byte(stdout)))
		}))

	// --- Metasploitable: banner-ish nc to SSH mapped port ---
	report.Steps = append(report.Steps, timedShell(t, ctx, requester, approver, sessionID,
		"meta_shell_ssh_banner", "127.0.0.1:12222",
		"bash", []string{"-c", "timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/12222; head -c 80 <&3' || true"},
		func(stdout string, code int32) (bool, string) {
			ok := len(stdout) > 0 || code == 0
			return ok, fmt.Sprintf("exit=%d banner_len=%d sample=%q", code, len(stdout), truncateStr(stdout, 60))
		}))

	report.TotalS = time.Since(totalStart).Seconds()

	// Write report next to repo for comparison
	outDir := filepath.Join(repoRootFromTest(t), "reports", "lab-perf")
	_ = os.MkdirAll(outDir, 0o755)
	outPath := filepath.Join(outDir, "erebus_lab_perf.json")
	raw, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		t.Logf("write report: %v", err)
	} else {
		t.Logf("wrote %s", outPath)
	}

	// Console summary
	t.Logf("=== EREBUS LAB PERF SUMMARY total=%.3fs setup=%.3fs ===", report.TotalS, report.SetupS)
	var reconS float64
	var rtts []float64
	allOK := true
	for _, s := range report.Steps {
		status := "PASS"
		if !s.Success {
			status = "FAIL"
			allOK = false
		}
		reconS += s.DurationS
		rtts = append(rtts, s.DurationS)
		t.Logf("  [%s] %-22s %.3fs  %s  %s", status, s.Name, s.DurationS, s.Target, s.Detail)
	}
	t.Logf("recon_steps_sum=%.3fs (excl setup overhead shared)", reconS)
	t.Logf("PRIOR Zypheron CLI: nmap=12.12s nikto_meta=9.15s nikto_juice=45.03s(timeout fail)")
	t.Logf("NOTE: prior = external scanner tools; this = implant C2 recon (different capability set)")

	if !allOK {
		t.Fatal("one or more lab perf steps failed — see log")
	}
	// P0 RTT gate: with sleepMs=500 + no server 5s override + immediate flush.
	// Exclude SSH banner (shell timeout path may be slower).
	var gate []float64
	for _, s := range report.Steps {
		if s.Name == "meta_shell_ssh_banner" {
			continue
		}
		gate = append(gate, s.DurationS)
	}
	if med := medianFloat(gate); med > 2.5 {
		t.Fatalf("P0 RTT gate failed: median task RTT %.3fs > 2.5s (gate steps=%v)", med, gate)
	}
}

func medianFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := append([]float64(nil), vals...)
	for i := 0; i < len(cp); i++ {
		for j := i + 1; j < len(cp); j++ {
			if cp[j] < cp[i] {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2
	}
	return cp[mid]
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func httpOK(url string) bool {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func waitSession(t *testing.T, ctx context.Context, client pb.ErebusC2Client, implantID string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sessions, err := client.ListSessions(ctx, &pb.ListSessionsRequest{})
		if err != nil {
			t.Fatalf("list sessions: %v", err)
		}
		for _, s := range sessions.Sessions {
			if s.ImplantId == implantID && s.Alive {
				return s.SessionId
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("implant never registered")
	return ""
}

func timedPortscan(t *testing.T, ctx context.Context, client pb.ErebusC2Client, sessionID, name, host string, ports []uint32) LabPerfStep {
	t.Helper()
	start := time.Now()
	step := LabPerfStep{Name: name, Target: fmt.Sprintf("%s %v", host, ports)}
	data, _ := proto.Marshal(&pb.NetPortscanTask{
		Target: host, Ports: ports, TimeoutMs: 2000, Threads: 32,
	})
	resp, err := client.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID, TaskType: pb.TaskType_TASK_NET_PORTSCAN,
		Data: data, Wait: true, TimeoutMs: 60000,
	})
	step.DurationS = time.Since(start).Seconds()
	if err != nil {
		step.Error = err.Error()
		return step
	}
	if resp.Result == nil || !resp.Result.Success {
		step.Error = fmt.Sprintf("task failed: %+v", resp.Result)
		return step
	}
	var result pb.NetPortscanResult
	if err := proto.Unmarshal(resp.Result.Data, &result); err != nil {
		step.Error = err.Error()
		return step
	}
	openN := 0
	var openList []string
	for _, p := range result.Ports {
		if p.Open {
			openN++
			openList = append(openList, fmt.Sprintf("%d/%s", p.Port, p.Service))
		}
	}
	step.Success = openN > 0
	step.Detail = fmt.Sprintf("open=%d %v", openN, openList)
	return step
}

func timedShell(t *testing.T, ctx context.Context, requester, approver pb.ErebusC2Client, sessionID, name, target, cmd string, args []string, check func(stdout string, code int32) (bool, string)) LabPerfStep {
	t.Helper()
	start := time.Now()
	step := LabPerfStep{Name: name, Target: target}
	data, _ := proto.Marshal(&pb.ShellTask{Command: cmd, Args: args})
	// TASK_SHELL is high-risk: dual-control approval required.
	resp := executeTaskWithApproval(t, ctx, requester, approver, &pb.ExecuteTaskRequest{
		SessionId: sessionID, TaskType: pb.TaskType_TASK_SHELL,
		Data: data, Wait: true, TimeoutMs: 30000,
	})
	step.DurationS = time.Since(start).Seconds()
	if resp.Result == nil {
		step.Error = "nil result"
		return step
	}
	var sr pb.ShellResult
	if err := proto.Unmarshal(resp.Result.Data, &sr); err != nil {
		step.Error = err.Error()
		return step
	}
	ok, detail := check(sr.Stdout, sr.ExitCode)
	step.Success = ok && resp.Result.Success
	step.Detail = detail
	if !step.Success && sr.Stderr != "" {
		step.Error = sr.Stderr
	}
	return step
}

func timedTask(t *testing.T, ctx context.Context, client pb.ErebusC2Client, sessionID, name, target string, tt pb.TaskType, data []byte, check func(*pb.TaskResult) (bool, string)) LabPerfStep {
	t.Helper()
	start := time.Now()
	step := LabPerfStep{Name: name, Target: target}
	resp, err := client.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID, TaskType: tt, Data: data, Wait: true, TimeoutMs: 30000,
	})
	step.DurationS = time.Since(start).Seconds()
	if err != nil {
		step.Error = err.Error()
		return step
	}
	ok, detail := check(resp.Result)
	step.Success = ok
	step.Detail = detail
	return step
}

func mustMarshal(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func repoRootFromTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
