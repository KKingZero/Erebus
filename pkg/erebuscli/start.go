package erebuscli

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

// Start boots the teamserver (if needed) and launches the operator REPL.
func Start() error {
	configPath := server.ConfigPath()
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		log.Printf("[erebus] no config at %s, using defaults", configPath)
		cfg = server.DefaultConfig()
	}
	if err := cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("create data dirs: %w", err)
	}

	var ts *server.Teamserver
	if !GRPCReachable(cfg.GRPCAddr) {
		ts, err = server.NewTeamserver(cfg)
		if err != nil {
			return fmt.Errorf("init teamserver: %v", err)
		}
		if _, _, _, err := EnsureOperatorCerts(cfg.DataDir); err != nil {
			return err
		}
		// Persist after NewTeamserver so generated master_key is saved.
		if err := cfg.Save(configPath); err != nil {
			log.Printf("[erebus] warning: save config: %v", err)
		}
		if err := ts.Start(); err != nil {
			return fmt.Errorf("start teamserver: %w", err)
		}
		log.Printf("[erebus] teamserver started (gRPC=%s)", cfg.GRPCAddr)
		defer ts.Stop()

		for i := 0; i < 20 && !GRPCReachable(cfg.GRPCAddr); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	} else {
		log.Printf("[erebus] teamserver already running at %s", cfg.GRPCAddr)
		// Still refresh on-disk config if defaults were applied without a teamserver start.
		if err := cfg.Save(configPath); err != nil {
			log.Printf("[erebus] warning: save config: %v", err)
		}
	}

	cert, key, ca, err := EnsureOperatorCerts(cfg.DataDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[erebus] connecting operator to %s\n", cfg.GRPCAddr)
	return operatorcli.RunREPL(operatorcli.Options{
		Server:   cfg.GRPCAddr,
		CertFile: cert,
		KeyFile:  key,
		CAFile:   ca,
	})
}

// RunTeamserver runs the teamserver in the foreground (blocks until signal).
func RunTeamserver(configPath string, passphrase string) error {
	var cfg *server.Config
	var err error
	if passphrase != "" {
		cfg, err = server.LoadEncryptedConfig(configPath, passphrase)
		if err != nil {
			cfg, err = server.LoadConfig(configPath)
		}
	} else {
		cfg, err = server.LoadConfig(configPath)
	}
	if err != nil {
		log.Printf("[erebus] no config at %s, using defaults", configPath)
		cfg = server.DefaultConfig()
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}

	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		return err
	}
	if _, _, _, err := EnsureOperatorCerts(cfg.DataDir); err != nil {
		return err
	}
	// Persist after NewTeamserver so generated master_key is saved.
	if passphrase != "" {
		if err := cfg.SaveEncrypted(configPath, passphrase); err != nil {
			log.Printf("[erebus] warning: save encrypted config: %v", err)
		}
	} else if err := cfg.Save(configPath); err != nil {
		log.Printf("[erebus] warning: save config: %v", err)
	}
	if err := ts.Start(); err != nil {
		return err
	}

	log.Println("[erebus] teamserver running. Press Ctrl+C to stop.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ts.Stop()
	return nil
}

// DataDir returns the default erebus data directory.
func DataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".erebus")
}
