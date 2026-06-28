package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
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

	if err := operatorcli.RunREPL(operatorcli.Options{
		Server:   *server,
		CertFile: *certFile,
		KeyFile:  *keyFile,
		CAFile:   *caFile,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "operator: %v\n", err)
		os.Exit(1)
	}
}