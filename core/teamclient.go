package core

import (
	"fmt"
	"sync"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server"
	"google.golang.org/grpc"
)

// TeamClient lazily connects the startup console to a running teamserver.
type TeamClient struct {
	mu     sync.Mutex
	client pb.ErebusC2Client
	conn   *grpc.ClientConn
	addr   string
}

func (tc *TeamClient) connect() (pb.ErebusC2Client, string, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.client != nil {
		return tc.client, tc.addr, nil
	}

	cfg, err := server.LoadConfig(server.ConfigPath())
	if err != nil {
		cfg = server.DefaultConfig()
	}
	if !erebuscli.GRPCReachable(cfg.GRPCAddr) {
		return nil, "", fmt.Errorf("teamserver not reachable at %s", cfg.GRPCAddr)
	}

	cert, key, ca, err := erebuscli.EnsureOperatorCerts(cfg.DataDir)
	if err != nil {
		return nil, "", err
	}

	client, conn, err := operatorcli.Connect(operatorcli.Options{
		Server:   cfg.GRPCAddr,
		CertFile: cert,
		KeyFile:  key,
		CAFile:   ca,
	})
	if err != nil {
		return nil, "", err
	}

	tc.client = client
	tc.conn = conn
	tc.addr = cfg.GRPCAddr
	return tc.client, tc.addr, nil
}

func (tc *TeamClient) Close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		_ = tc.conn.Close()
		tc.conn = nil
		tc.client = nil
	}
}