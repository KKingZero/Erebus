package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

func main() {
	configPath := flag.String("config", server.ConfigPath(), "path to server config")
	grpcAddr := flag.String("grpc", "", "gRPC listen address (overrides config)")
	listenerHost := flag.String("host", "", "default listener host (overrides config)")
	listenerPort := flag.Uint("port", 0, "default listener port (overrides config)")
	secret := flag.String("secret", "", "implant pre-shared secret (hex, overrides config)")
	debug := flag.Bool("debug", false, "enable debug mode (gRPC reflection)")
	genOperatorCert := flag.String("gen-operator-cert", "", "generate operator mTLS cert and exit")
	passphrase := flag.String("passphrase", "", "passphrase for encrypted config (overrides EREBUS_PASSPHRASE)")
	flag.Parse()

	// Handle operator cert generation
	if *genOperatorCert != "" {
		generateOperatorCert(*genOperatorCert)
		return
	}

	// Determine passphrase for encrypted config
	pp := *passphrase
	if pp == "" {
		pp = os.Getenv("EREBUS_PASSPHRASE")
	}

	// Load or create config
	var cfg *server.Config
	var err error
	if pp != "" {
		cfg, err = server.LoadEncryptedConfig(*configPath, pp)
		if err != nil {
			log.Printf("[main] encrypted config load failed: %v, trying plaintext", err)
			cfg, err = server.LoadConfig(*configPath)
		}
	} else {
		cfg, err = server.LoadConfig(*configPath)
	}
	if err != nil {
		log.Printf("[main] no config at %s, using defaults", *configPath)
		cfg = server.DefaultConfig()
	}

	// Apply CLI overrides
	if *grpcAddr != "" {
		cfg.GRPCAddr = *grpcAddr
	}
	if *listenerHost != "" && len(cfg.Listeners) > 0 {
		cfg.Listeners[0].Host = *listenerHost
	}
	if *listenerPort != 0 && len(cfg.Listeners) > 0 {
		cfg.Listeners[0].Port = uint32(*listenerPort)
	}
	if *secret != "" {
		cfg.ImplantSecret = *secret
	}
	if *debug {
		cfg.Debug = true
	}

	// Ensure data directory exists and save config
	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("create data dirs: %v", err)
	}
	if pp != "" {
		if err := cfg.SaveEncrypted(*configPath, pp); err != nil {
			log.Printf("[main] warning: save encrypted config: %v", err)
		}
	} else {
		if err := cfg.Save(*configPath); err != nil {
			log.Printf("[main] warning: save config: %v", err)
		}
	}

	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		log.Fatalf("init teamserver: %v", err)
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("start teamserver: %v", err)
	}

	log.Println("[main] Erebus teamserver running. Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ts.Stop()
	log.Println("[main] shutdown complete")
}

func generateOperatorCert(operatorName string) {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".erebus")

	certPath := filepath.Join(dataDir, "ca-cert.pem")
	keyPath := filepath.Join(dataDir, "ca-key.pem")

	ca, err := zcrypto.LoadCA(certPath, keyPath)
	if err != nil {
		log.Fatalf("load CA: %v (run teamserver first to generate CA)", err)
	}

	_, clientCertPEM, clientKeyPEM, err := ca.GenerateClientCert(operatorName)
	if err != nil {
		log.Fatalf("generate client cert: %v", err)
	}

	certOut := filepath.Join(dataDir, operatorName+"-cert.pem")
	keyOut := filepath.Join(dataDir, operatorName+"-key.pem")
	caOut := filepath.Join(dataDir, operatorName+"-ca.pem")

	if err := zcrypto.SavePEM(certOut, clientCertPEM); err != nil {
		log.Fatalf("save client cert: %v", err)
	}
	if err := zcrypto.SavePEM(keyOut, clientKeyPEM); err != nil {
		log.Fatalf("save client key: %v", err)
	}
	if err := zcrypto.SavePEM(caOut, ca.CertPEM); err != nil {
		log.Fatalf("save CA cert: %v", err)
	}

	fmt.Printf("Operator cert generated:\n  Cert: %s\n  Key:  %s\n  CA:   %s\n", certOut, keyOut, caOut)
}
