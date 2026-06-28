package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/core"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

func main() {
	// Default: interactive startup UI (banner + erebus › prompt)
	if len(os.Args) < 2 {
		runConsole([]string{})
		return
	}

	switch os.Args[1] {
	case "serve":
		if err := erebuscli.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "erebus: %v\n", err)
			os.Exit(1)
		}
	case "teamserver":
		runTeamserver(os.Args[2:])
	case "operator":
		runOperator(os.Args[2:])
	case "console":
		runConsole(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		// Support erebus -json without subcommand
		if os.Args[1] == "-json" {
			runConsole(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runConsole(args []string) {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "Enable JSON output mode for AI/programmatic control")
	_ = fs.Parse(args)
	core.NewConsole(*jsonMode).Start()
}

func runTeamserver(args []string) {
	configPath := server.ConfigPath()
	passphrase := os.Getenv("EREBUS_PASSPHRASE")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "-passphrase":
			if i+1 < len(args) {
				passphrase = args[i+1]
				i++
			}
		}
	}
	if err := erebuscli.RunTeamserver(configPath, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "erebus teamserver: %v\n", err)
		os.Exit(1)
	}
}

func runOperator(args []string) {
	serverAddr := "127.0.0.1:50051"
	cert, key, ca := erebuscli.DefaultCertPaths()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			if i+1 < len(args) {
				serverAddr = args[i+1]
				i++
			}
		case "-cert":
			if i+1 < len(args) {
				cert = args[i+1]
				i++
			}
		case "-key":
			if i+1 < len(args) {
				key = args[i+1]
				i++
			}
		case "-ca":
			if i+1 < len(args) {
				ca = args[i+1]
				i++
			}
		}
	}

	if err := operatorcli.RunREPL(operatorcli.Options{
		Server: serverAddr, CertFile: cert, KeyFile: key, CAFile: ca,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "erebus operator: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Erebus Exploitation Framework v%s

Usage:
  erebus              Interactive console (startup UI)
  erebus -json         JSON console mode
  erebus serve         Start teamserver + operator C2 session
  erebus teamserver    Run teamserver only
  erebus operator      Connect to teamserver REPL
  erebus help          Show this help

Data directory: %s
`, core.Version, erebuscli.DataDir())
}