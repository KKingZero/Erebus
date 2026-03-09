package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chzyer/readline"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

type REPL struct {
	cmds *Commands
	rl   *readline.Instance
}

func NewREPL(client pb.ErebusC2Client) *REPL {
	cmds := NewCommands(client)

	// Build completer from command names
	handlers := cmds.Handlers()
	names := make([]string, 0, len(handlers))
	for name := range handlers {
		names = append(names, name)
	}
	sort.Strings(names)

	var items []readline.PrefixCompleterInterface
	for _, name := range names {
		items = append(items, readline.PcItem(name))
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "erebus > ",
		AutoComplete:    readline.NewPrefixCompleter(items...),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "readline init: %v\n", err)
		os.Exit(1)
	}

	return &REPL{
		cmds: cmds,
		rl:   rl,
	}
}

func (r *REPL) Run() {
	defer r.rl.Close()

	fmt.Println("Erebus C2 Operator Console")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

	handlers := r.cmds.Handlers()

	for {
		// Update prompt with active session
		if r.cmds.sessionID != "" {
			r.rl.SetPrompt(fmt.Sprintf("erebus [%s] > ", r.cmds.sessionID[:8]))
		}

		line, err := r.rl.Readline()
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		handler, ok := handlers[cmd]
		if !ok {
			fmt.Printf("Unknown command: %s (type 'help')\n", cmd)
			continue
		}

		if err := handler(args); err != nil {
			if err == errExit {
				return
			}
			fmt.Printf("Error: %v\n", err)
		}
	}
}
