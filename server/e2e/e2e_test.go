package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	implanttasks "github.com/KKingZero/erebus-exploit-framwork/implant/tasks"
	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// TestLiveE2E runs steps 1–4 against a real teamserver:
//  1. Start teamserver (gRPC + HTTPS on ephemeral ports)
//  2. Simulate implant register + beacon loop
//  3. Execute shell task via gRPC and verify result
//  4. Verify creds-dump approval gate (pending → approve → dispatch)
func TestLiveE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	implantID := "e2e-implant"

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
			{Name: "e2e-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
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

	grpcClient, opTLS := newGRPCClient(t, ts, cfg.GRPCAddr)
	httpsURL := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	httpClient := newHTTPSClient(opTLS)

	sim := &implantSim{
		t:          t,
		secret:     secret,
		implantID:  implantID,
		httpClient: httpClient,
		baseURL:    httpsURL,
		done:       make(chan struct{}),
	}

	// Step 2: register + background beacon loop
	sessionID, sessionKey := sim.register(ctx)
	sim.sessionID = sessionID
	sim.sessionKey = sessionKey
	go sim.beaconLoop(ctx)

	// Step 3: shell task round-trip
	shellData, _ := proto.Marshal(&pb.ShellTask{Command: "echo erebus-e2e-ok"})
	execResp, err := grpcClient.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID,
		TaskType:  pb.TaskType_TASK_SHELL,
		Data:      shellData,
		Wait:      true,
		TimeoutMs: 30000,
	})
	if err != nil {
		t.Fatalf("execute shell: %v", err)
	}
	if execResp.Result == nil || !execResp.Result.Success {
		t.Fatalf("shell failed: %+v", execResp.Result)
	}
	shellResult := &pb.ShellResult{}
	if err := proto.Unmarshal(execResp.Result.Data, shellResult); err != nil {
		t.Fatalf("unmarshal shell result: %v", err)
	}
	if shellResult.ExitCode != 0 {
		t.Fatalf("shell exit code %d stderr=%q", shellResult.ExitCode, shellResult.Stderr)
	}
	if !bytes.Contains([]byte(shellResult.Stdout), []byte("erebus-e2e-ok")) {
		t.Fatalf("unexpected stdout: %q", shellResult.Stdout)
	}

	// Step 4: approval gate for creds dump
	approvalDone := make(chan error, 1)
	go func() {
		_, err := grpcClient.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
			SessionId: sessionID,
			TaskType:  pb.TaskType_TASK_CREDS_DUMP,
			Wait:      true,
			TimeoutMs: 30000,
		})
		approvalDone <- err
	}()

	var approvalID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pending, err := grpcClient.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err != nil {
			t.Fatalf("list pending: %v", err)
		}
		for _, a := range pending.Approvals {
			if a.TaskType == pb.TaskType_TASK_CREDS_DUMP && a.SessionId == sessionID {
				approvalID = a.Id
				break
			}
		}
		if approvalID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if approvalID == "" {
		t.Fatal("expected pending creds_dump approval")
	}

	if _, err := grpcClient.Approve(ctx, &pb.ApproveRequest{ApprovalId: approvalID}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	select {
	case err := <-approvalDone:
		if err != nil {
			t.Fatalf("creds dump after approve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("creds dump task timed out after approval")
	}

	// Verify creds dump result is real protobuf, not simulated JSON
	tasks, err := grpcClient.ListTasks(ctx, &pb.ListTasksRequest{SessionId: sessionID})
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	var credsResult *pb.TaskResult
	for _, task := range tasks.Tasks {
		if task.TaskType != pb.TaskType_TASK_CREDS_DUMP {
			continue
		}
		credsResp, err := grpcClient.GetTaskResult(ctx, &pb.GetTaskResultRequest{TaskId: task.TaskId})
		if err != nil {
			t.Fatalf("get creds result: %v", err)
		}
		credsResult = credsResp.Result
		break
	}
	if credsResult == nil || !credsResult.Success {
		t.Fatal("expected successful creds dump result")
	}
	if bytes.Contains(credsResult.Data, []byte(`"simulated":true`)) {
		t.Fatalf("creds dump returned simulated payload: %s", credsResult.Data)
	}
	credResult := &pb.CredDumpResult{}
	if err := proto.Unmarshal(credsResult.Data, credResult); err != nil {
		t.Fatalf("unmarshal cred dump result: %v", err)
	}

	close(sim.done)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", addr)
}

func newGRPCClient(t *testing.T, ts *server.Teamserver, addr string) (pb.ErebusC2Client, *tls.Config) {
	t.Helper()
	_, certPEM, keyPEM, err := ts.CA.GenerateClientCert("e2e-operator")
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ts.CA.Cert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewErebusC2Client(conn), tlsConfig
}

func newHTTPSClient(tlsConfig *tls.Config) *http.Client {
	tr := tlsConfig.Clone()
	tr.InsecureSkipVerify = true
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tr},
		Timeout:   30 * time.Second,
	}
}

type implantSim struct {
	t              *testing.T
	secret         []byte
	implantID      string
	sessionID      string
	sessionKey     []byte
	httpClient     *http.Client
	baseURL        string
	done           chan struct{}
	pendingResults []*pb.TaskResult
}

func (s *implantSim) register(ctx context.Context) (string, []byte) {
	ts := time.Now().Unix()
	reg := &pb.Register{
		ImplantId: s.implantID,
		Hostname:  "e2e-host",
		Username:  "e2e-user",
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(s.secret, s.implantID, ts),
	}
	body, _ := proto.Marshal(reg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/register", bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.t.Fatalf("register http: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("register status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	regResp := &pb.RegisterResponse{}
	if err := proto.Unmarshal(data, regResp); err != nil {
		s.t.Fatal(err)
	}
	if !regResp.Success || regResp.SessionId == "" {
		s.t.Fatalf("bad register response: %+v", regResp)
	}
	sessionKey, err := zcrypto.AESDecrypt(s.secret, regResp.EncryptedSessionKey)
	if err != nil {
		s.t.Fatal(err)
	}
	return regResp.SessionId, sessionKey
}

func (s *implantSim) beaconLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		ts := time.Now().Unix()
		beacon := &pb.Beacon{
			ImplantId: s.implantID,
			SessionId: s.sessionID,
			Timestamp: ts,
			Hmac:      zcrypto.ComputeHMAC(s.secret, s.implantID, ts),
		}
		if len(s.pendingResults) > 0 && s.sessionKey != nil {
			payload := &pb.BeaconResultsPayload{Results: s.pendingResults}
			s.pendingResults = nil
			plain, _ := proto.Marshal(payload)
			enc, err := zcrypto.AESEncrypt(s.sessionKey, plain)
			if err != nil {
				s.t.Errorf("encrypt results: %v", err)
				continue
			}
			beacon.EncryptedResults = enc
		}

		body, _ := proto.Marshal(beacon)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/beacon", bytes.NewReader(body))
		if err != nil {
			return
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		beaconResp := &pb.BeaconResponse{}
		if err := proto.Unmarshal(data, beaconResp); err != nil {
			continue
		}
		tasks := beaconResp.Tasks
		if len(beaconResp.EncryptedTasks) > 0 && s.sessionKey != nil {
			plain, err := zcrypto.AESDecrypt(s.sessionKey, beaconResp.EncryptedTasks)
			if err != nil {
				s.t.Errorf("decrypt tasks: %v", err)
				continue
			}
			payload := &pb.BeaconTasksPayload{}
			if err := proto.Unmarshal(plain, payload); err != nil {
				s.t.Errorf("unmarshal tasks: %v", err)
				continue
			}
			tasks = payload.Tasks
		}
		for _, task := range tasks {
			s.pendingResults = append(s.pendingResults, s.executeTask(task))
		}

		sleep := time.Duration(beaconResp.NextCheckinMs) * time.Millisecond
		if sleep <= 0 {
			sleep = 200 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-time.After(sleep):
		}
	}
}

func (s *implantSim) executeTask(task *pb.Task) *pb.TaskResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch task.TaskType {
	case pb.TaskType_TASK_SHELL:
		shellTask := &pb.ShellTask{}
		if err := proto.Unmarshal(task.Data, shellTask); err != nil {
			return failResult(task.TaskId, err, start)
		}
		result := implanttasks.RunShell(ctx, shellTask.Command, shellTask.Args)
		data, _ := proto.Marshal(result)
		return &pb.TaskResult{
			TaskId:          task.TaskId,
			Success:         result.ExitCode == 0,
			Data:            data,
			ExecutionTimeMs: time.Since(start).Milliseconds(),
		}
	case pb.TaskType_TASK_EXIT:
		return &pb.TaskResult{TaskId: task.TaskId, Success: true, ExecutionTimeMs: time.Since(start).Milliseconds()}
	case pb.TaskType_TASK_CREDS_DUMP:
		result := &pb.CredDumpResult{
			Method: "lsass",
			Credentials: []*pb.Credential{
				{Type: "simulated", Source: "e2e", Value: "ok"},
			},
		}
		data, err := proto.Marshal(result)
		if err != nil {
			return failResult(task.TaskId, err, start)
		}
		return &pb.TaskResult{
			TaskId:          task.TaskId,
			Success:         true,
			Data:            data,
			ExecutionTimeMs: time.Since(start).Milliseconds(),
		}
	default:
		return &pb.TaskResult{
			TaskId:          task.TaskId,
			Success:         true,
			Data:            []byte(`{"simulated":true}`),
			ExecutionTimeMs: time.Since(start).Milliseconds(),
		}
	}
}

func failResult(taskID string, err error, start time.Time) *pb.TaskResult {
	return &pb.TaskResult{
		TaskId:          taskID,
		Success:         false,
		Error:           err.Error(),
		ExecutionTimeMs: time.Since(start).Milliseconds(),
	}
}