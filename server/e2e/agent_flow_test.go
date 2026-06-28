package e2e_test

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

func TestAgentExecutorShell(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, sim, sessionID, grpcAddr := startAgentE2EFixture(t, ctx)
	client := newAgentClient(t, sim, grpcAddr)
	defer client.Close()
	if err := client.StartSubscribe(ctx); err != nil {
		t.Fatal(err)
	}

	exec := &agent.Executor{Client: client}
	result, err := exec.RunTool(ctx, "run_shell",
		fmt.Sprintf(`{"session_id":%q,"command":"echo agent-e2e-ok"}`, sessionID),
		sessionID)
	if err != nil {
		t.Fatalf("run_shell: %v", err)
	}
	if !strings.Contains(result, "agent-e2e-ok") {
		t.Fatalf("unexpected result: %s", result)
	}
	close(sim.done)
}

func TestAgentExecutorLDAPSuggestions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ts, sim, sessionID, grpcAddr := startAgentE2EFixture(t, ctx)
	grpcClient, _ := newGRPCClient(t, ts, grpcAddr)

	client := newAgentClient(t, sim, grpcAddr)
	defer client.Close()
	if err := client.StartSubscribe(ctx); err != nil {
		t.Fatal(err)
	}

	exec := &agent.Executor{Client: client}
	type runResult struct {
		out string
		err error
	}
	done := make(chan runResult, 1)
	go func() {
		out, err := exec.RunTool(ctx, "ldap_enum", fmt.Sprintf(`{
			"session_id":%q,
			"query_type":"kerberoastable",
			"domain":"corp.local",
			"target_dc":"dc01.corp.local"
		}`, sessionID), sessionID)
		done <- runResult{out, err}
	}()

	approvalID := waitForPendingApproval(t, ctx, grpcClient, sessionID, pb.TaskType_TASK_LDAP_ENUM)
	if _, err := grpcClient.Approve(ctx, &pb.ApproveRequest{ApprovalId: approvalID}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	var rr runResult
	select {
	case rr = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ldap_enum timed out")
	}
	if rr.err != nil {
		t.Fatalf("ldap_enum: %v", rr.err)
	}
	if !strings.Contains(rr.out, "next_suggested_actions") {
		t.Fatalf("expected suggestions: %s", rr.out)
	}
	if !strings.Contains(rr.out, "kerberoast") {
		t.Fatalf("expected kerberoast suggestion: %s", rr.out)
	}
	close(sim.done)
}

func TestAgentExecutorFileDownload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, sim, sessionID, grpcAddr := startAgentE2EFixture(t, ctx)
	client := newAgentClient(t, sim, grpcAddr)
	defer client.Close()
	if err := client.StartSubscribe(ctx); err != nil {
		t.Fatal(err)
	}

	exec := &agent.Executor{Client: client}
	result, err := exec.RunTool(ctx, "file_download",
		fmt.Sprintf(`{"session_id":%q,"remote_path":"/etc/hosts"}`, sessionID),
		sessionID)
	if err != nil {
		t.Fatalf("file_download: %v", err)
	}
	if !strings.Contains(result, "e2e-test-file") {
		t.Fatalf("unexpected result: %s", result)
	}
	close(sim.done)
}

func TestAgentExecutorApprovalFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ts, sim, sessionID, grpcAddr := startAgentE2EFixture(t, ctx)
	grpcClient, _ := newGRPCClient(t, ts, grpcAddr)

	client := newAgentClient(t, sim, grpcAddr)
	defer client.Close()
	if err := client.StartSubscribe(ctx); err != nil {
		t.Fatal(err)
	}

	var approvalID string
	var approvalMu sync.Mutex
	exec := &agent.Executor{
		Client: client,
		OnApproval: func(id, risk, desc string) {
			approvalMu.Lock()
			approvalID = id
			approvalMu.Unlock()
		},
	}

	done := make(chan error, 1)
	go func() {
		_, err := exec.RunTool(ctx, "creds_dump",
			fmt.Sprintf(`{"session_id":%q,"method":"lsass"}`, sessionID),
			sessionID)
		done <- err
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		approvalMu.Lock()
		id := approvalID
		approvalMu.Unlock()
		if id != "" {
			break
		}
		pending, err := grpcClient.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err == nil {
			for _, a := range pending.Approvals {
				if a.SessionId == sessionID && a.TaskType == pb.TaskType_TASK_CREDS_DUMP {
					approvalID = a.Id
					break
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if approvalID == "" {
		t.Fatal("expected approval callback or pending approval")
	}

	if _, err := grpcClient.Approve(ctx, &pb.ApproveRequest{ApprovalId: approvalID}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("creds_dump after approve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("creds_dump timed out after approval")
	}
	close(sim.done)
}

func startAgentE2EFixture(t *testing.T, ctx context.Context) (*server.Teamserver, *implantSim, string, string) {
	t.Helper()

	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	implantID := "agent-e2e-implant"
	grpcPort := freePort(t)
	httpsPort := freePort(t)
	dataDir := t.TempDir()
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", grpcPort)

	ahDisabled := false
	cfg := &server.Config{
		GRPCAddr:      grpcAddr,
		DBPath:        filepath.Join(dataDir, "erebus.db"),
		DataDir:       dataDir,
		ImplantSecret: hex.EncodeToString(secret),
		AutoHarvest:   server.AutoHarvestYAML{Enabled: &ahDisabled},
		Listeners: []server.ListenerConfig{
			{Name: "agent-e2e-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
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
	waitForTCP(t, grpcAddr, 5*time.Second)
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", httpsPort), 5*time.Second)

	_, opTLS := newGRPCClient(t, ts, grpcAddr)
	httpsURL := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	httpClient := newHTTPSClient(opTLS)

	sim := &implantSim{
		t:          t,
		ts:         ts,
		secret:     secret,
		implantID:  implantID,
		httpClient: httpClient,
		baseURL:    httpsURL,
		done:       make(chan struct{}),
	}

	sessionID, sessionKey := sim.register(ctx)
	sim.sessionID = sessionID
	sim.sessionKey = sessionKey
	go sim.beaconLoop(ctx)

	return ts, sim, sessionID, grpcAddr
}

func newAgentClient(t *testing.T, sim *implantSim, addr string) *agent.Client {
	t.Helper()
	dir := t.TempDir()
	_, certPEM, keyPEM, err := sim.ts.CA.GenerateClientCert("e2e-agent")
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "agent.pem")
	keyPath := filepath.Join(dir, "agent-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	caDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sim.ts.CA.Cert.Raw})
	if err := os.WriteFile(caPath, caDER, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := agent.Connect(&agent.Config{
		Server: addr,
		Cert:   certPath,
		Key:    keyPath,
		CA:     caPath,
	})
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func waitForPendingApproval(t *testing.T, ctx context.Context, client pb.ErebusC2Client, sessionID string, taskType pb.TaskType) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pending, err := client.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err != nil {
			t.Fatalf("list pending: %v", err)
		}
		for _, a := range pending.Approvals {
			if a.SessionId == sessionID && a.TaskType == taskType {
				return a.Id
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for pending approval task=%s session=%s", taskType, sessionID)
	return ""
}