package main

import (
	"fmt"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/core"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

func main() {
	if len(os.Args) < 2 {
		if err := erebuscli.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "erebus: %v\n", err)
			os.Exit(1)
		}
		return
	}

	switch os.Args[1] {
	case "start":
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
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
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

func runConsole(args []string) {
	jsonMode := false
	for _, a := range args {
		if a == "-json" {
			jsonMode = true
		}
	}
	core.NewConsole(jsonMode).Start()
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Erebus Exploitation Framework

Usage:
  erebus              Start teamserver (if needed) and open operator console
  erebus start        Same as erebus
  erebus teamserver   Run teamserver only
  erebus operator     Connect to teamserver REPL
  erebus console      Legacy module console (erc >)
  erebus help         Show this help

Also available as separate binaries: build/teamserver, build/operator, build/agent

Data directory: %s
`, erebuscli.DataDir())
}