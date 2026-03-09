package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	server := flag.String("server", "127.0.0.1:50051", "Teamserver gRPC address")
	certFile := flag.String("cert", "", "Operator client certificate PEM")
	keyFile := flag.String("key", "", "Operator client key PEM")
	caFile := flag.String("ca", "", "CA certificate PEM")
	flag.Parse()

	if *certFile == "" || *keyFile == "" || *caFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: operator -cert <cert.pem> -key <key.pem> -ca <ca.pem> [-server <addr>]")
		os.Exit(1)
	}

	conn, err := connectGRPC(*server, *certFile, *keyFile, *caFile)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewErebusC2Client(conn)

	repl := NewREPL(client)
	repl.Run()
}

func connectGRPC(addr, certFile, keyFile, caFile string) (*grpc.ClientConn, error) {
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
