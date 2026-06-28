package operatorcli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Options configures the operator REPL connection.
type Options struct {
	Server   string
	CertFile string
	KeyFile  string
	CAFile   string
}

// Connect dials the teamserver gRPC API with mTLS.
func Connect(opts Options) (pb.ErebusC2Client, *grpc.ClientConn, error) {
	conn, err := dialGRPC(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewErebusC2Client(conn), conn, nil
}

// RunREPL connects and starts the interactive operator console.
func RunREPL(opts Options) error {
	client, conn, err := Connect(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	NewREPL(client).Run()
	return nil
}

func dialGRPC(addr, certFile, keyFile, caFile string) (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial gRPC: %w", err)
	}
	return conn, nil
}