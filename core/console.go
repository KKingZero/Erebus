package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/chzyer/readline"
)

// Version is the Erebus framework version shown at startup.
const Version = "0.1.0"

const banner = `
888888 88""Yb 888888 88""Yb 88   88 .dP"Y8
88__   88__dP 88__   88__dP 88   88 Ybo."
88""   88"Yb  88""   88""Yb Y8   8P o.Y8b
888888 88  Yb 888888 88oodP YbodP  8bodP

    Exploitation Framework - Powered by AI
             by Zypheron Team
`

const promptDefault = "erebus › "
const promptModuleFmt = "erebus (%s) › "

type Console struct {
	currentModule string
	workspace     string
	session       string
	running       bool
	mode          OutputMode
	team          TeamClient
	teamBanner    bool
}

func NewConsole(jsonMode bool) *Console {
	m := OutputHuman
	if jsonMode {
		m = OutputJSON
	}
	return &Console{running: true, mode: m}
}

func (c *Console) Start() {
	if c.mode == OutputJSON {
		c.startJSON()
		return
	}
	c.startInteractive()
}

func printStartupBanner() {
	fmt.Print(banner)
	fmt.Println("Type 'help' for available commands")
	fmt.Println()
}

// startInteractive runs the human-friendly readline REPL
func (c *Console) startInteractive() {
	printStartupBanner()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.prompt(),
		HistoryFile:     erebusHistoryPath(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	for c.running {
		rl.SetPrompt(c.prompt())
		line, err := rl.Readline()
		if err != nil {
			break
		}
		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}
		c.handleCommand(input)
		if commandMayContainSecret(input) {
			scrubLastHistoryEntry(erebusHistoryPath())
		}
	}
}

// startJSON runs a line-oriented JSON mode for AI/programmatic control.
func (c *Console) startJSON() {
	emit(c.mode, Response{
		Status:  "ok",
		Command: "init",
		Message: "Erebus console ready",
		Data: map[string]interface{}{
			"version": Version,
			"mode":    "json",
		},
	})

	scanner := bufio.NewScanner(os.Stdin)
	for c.running && scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		c.handleCommand(input)
	}
}

func (c *Console) prompt() string {
	if c.currentModule != "" {
		return fmt.Sprintf(promptModuleFmt, c.currentModule)
	}
	return promptDefault
}

func (c *Console) handleCommand(input string) {
	parts := strings.Fields(input)
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "help":
		c.cmdHelp()
	case "clear":
		if c.mode == OutputHuman {
			fmt.Print("\033[H\033[2J")
			printStartupBanner()
		}
	case "use":
		c.cmdUse(args)
	case "back":
		c.cmdBack()
	case "search":
		c.cmdSearch(args)
	case "sessions":
		c.cmdSessions(args)
	case "workspace":
		c.cmdWorkspace(args)
	case "options":
		c.cmdOptions()
	case "info":
		c.cmdInfo()
	case "run", "exploit":
		c.cmdRun()
	case "loot":
		c.cmdLoot()
	case "report":
		c.cmdReport(args)
	case "ai":
		c.cmdAI(args)
	case "exit", "quit":
		emit(c.mode, Response{
			Status:  "ok",
			Command: "exit",
			Message: "\n> Exiting Erebus. Stay in the shadows.\n",
		})
		c.running = false
	default:
		emitError(c.mode, cmd, fmt.Sprintf("Unknown command: %s", cmd))
	}
}

func (c *Console) cmdHelp() {
	type HelpEntry struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}
	type CategoryEntry struct {
		Path        string `json:"path"`
		Description string `json:"description"`
	}

	commands := []HelpEntry{
		{"help", "Show this menu"},
		{"ai", "Open AI chat TUI (Normal / Plan / Auto)"},
		{"ai <message>", "Open TUI and send first message"},
		{"ai setup", "Interactive provider / API key / model wizard"},
		{"ai providers", "List LLM providers"},
		{"ai provider <name>", "Switch active LLM provider"},
		{"sessions", "List active sessions (needs teamserver)"},
		{"sessions -i <id>", "Show session details"},
		{"loot", "Show captured loot"},
		{"workspace <new|list>", "Manage engagements"},
		{"report generate", "Generate pentest report"},
		{"clear", "Clear screen"},
		{"exit", "Exit Erebus"},
	}

	var humanMsg strings.Builder
	humanMsg.WriteString("\nPrimary workflow:\n")
	humanMsg.WriteString("  1. erebus serve          Start teamserver + operator session\n")
	humanMsg.WriteString("  2. ai                    Open AI TUI — Plan path, Auto execute\n")
	humanMsg.WriteString("  3. In Auto: [a]/[d]      Approve/deny high-risk tasks in the TUI\n")
	humanMsg.WriteString("\nCommands:\n")
	for _, cmd := range commands {
		humanMsg.WriteString(fmt.Sprintf("  %-24s%s\n", cmd.Command, cmd.Description))
	}
	humanMsg.WriteString("\nOperator REPL (implant tasks):\n")
	humanMsg.WriteString("  erebus serve / erebus operator — shell, ldap-enum, kerberoast, approve\n")
	humanMsg.WriteString("\nNote: Metasploit-style use/run modules are not wired in this console;\n")
	humanMsg.WriteString("use `ai` (Auto) or the operator REPL for live tasks.\n")

	emit(c.mode, Response{
		Status:  "ok",
		Command: "help",
		Message: humanMsg.String(),
		Data: map[string]interface{}{
			"commands": commands,
		},
	})
}

func (c *Console) cmdUse(args []string) {
	emit(c.mode, Response{
		Status:  "info",
		Command: "use",
		Message: "> Module load is not available in the startup console.\n> Use `ai` (Plan/Auto) or `erebus serve` operator REPL for live tasks.",
		Data: map[string]interface{}{
			"status": "unavailable",
			"args":   args,
		},
	})
}

func (c *Console) cmdBack() {
	if c.currentModule == "" {
		emitError(c.mode, "back", "No module loaded")
		return
	}
	prev := c.currentModule
	c.currentModule = ""
	emit(c.mode, Response{
		Status:  "ok",
		Command: "back",
		Message: fmt.Sprintf("> Unloaded: %s", prev),
		Data: map[string]string{
			"unloaded": prev,
		},
	})
}

func (c *Console) cmdSearch(args []string) {
	if len(args) == 0 {
		emitError(c.mode, "search", "Usage: search <term> or search cve:<CVE-ID> or search platform:<platform>")
		return
	}
	query := strings.Join(args, " ")
	emit(c.mode, Response{
		Status:  "info",
		Command: "search",
		Message: fmt.Sprintf("> Module search is not available in the startup console.\n> Use `ai` (Plan mode) or the operator REPL.\n> Query: %s", query),
		Data: map[string]interface{}{
			"query":   query,
			"results": []interface{}{},
		},
	})
}

func (c *Console) cmdSessions(args []string) {
	client, addr, err := c.team.connect()
	if err != nil {
		emit(c.mode, Response{
			Status:  "info",
			Command: "sessions",
			Message: fmt.Sprintf("> Teamserver unavailable (%v)\n> Start with: erebus serve", err),
			Data: map[string]interface{}{
				"sessions": []interface{}{},
				"count":    0,
			},
		})
		return
	}
	c.maybeTeamBanner(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if len(args) > 0 && args[0] == "-i" {
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		if id == "" {
			emitError(c.mode, "sessions", "Usage: sessions -i <session-id>")
			return
		}
		resp, err := client.GetSession(ctx, &pb.GetSessionRequest{SessionId: id})
		if err != nil {
			emitError(c.mode, "sessions", err.Error())
			return
		}
		s := resp.Session
		msg := fmt.Sprintf("> Session %s\n  Host: %s@%s\n  OS: %s/%s  Transport: %s\n  Alive: %v  Last checkin: %d",
			s.SessionId, s.Username, s.Hostname, s.Os, s.Arch, s.Transport, s.Alive, s.LastCheckin)
		emit(c.mode, Response{
			Status:  "ok",
			Command: "sessions",
			Message: msg,
			Data:    map[string]interface{}{"session": s},
		})
		return
	}

	resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		emitError(c.mode, "sessions", err.Error())
		return
	}
	if len(resp.Sessions) == 0 {
		emit(c.mode, Response{
			Status:  "ok",
			Command: "sessions",
			Message: "> No active sessions",
			Data: map[string]interface{}{
				"sessions": []interface{}{},
				"count":    0,
			},
		})
		return
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("> %d session(s)\n", len(resp.Sessions)))
	b.WriteString(fmt.Sprintf("  %-36s %-15s %-12s %-8s %-10s %-6s\n", "SESSION", "HOSTNAME", "USER", "OS", "TRANSPORT", "ALIVE"))
	for _, s := range resp.Sessions {
		alive := "yes"
		if !s.Alive {
			alive = "no"
		}
		b.WriteString(fmt.Sprintf("  %-36s %-15s %-12s %-8s %-10s %-6s\n",
			s.SessionId, s.Hostname, s.Username, s.Os, s.Transport, alive))
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "sessions",
		Message: b.String(),
		Data: map[string]interface{}{
			"sessions": resp.Sessions,
			"count":    len(resp.Sessions),
		},
	})
}

func (c *Console) cmdWorkspace(args []string) {
	if len(args) == 0 {
		emitError(c.mode, "workspace", "Usage: workspace <new|list> [name]")
		return
	}
	switch args[0] {
	case "new":
		if len(args) < 2 {
			emitError(c.mode, "workspace", "Usage: workspace new <name>")
			return
		}
		c.workspace = args[1]
		emit(c.mode, Response{
			Status:  "ok",
			Command: "workspace",
			Message: fmt.Sprintf("> Workspace created: %s", c.workspace),
			Data: map[string]string{
				"action":    "created",
				"workspace": c.workspace,
			},
		})
	case "list":
		emit(c.mode, Response{
			Status:  "ok",
			Command: "workspace",
			Message: fmt.Sprintf("> Active workspace: %s", c.workspace),
			Data: map[string]string{
				"action":    "list",
				"workspace": c.workspace,
			},
		})
	default:
		emitError(c.mode, "workspace", fmt.Sprintf("Unknown workspace action: %s", args[0]))
	}
}

func (c *Console) cmdOptions() {
	emit(c.mode, Response{
		Status:  "info",
		Command: "options",
		Message: "> Module options are not available in the startup console.\n> Use `ai` (Auto) or `erebus serve` operator REPL for live tasks.",
		Data: map[string]string{
			"status": "unavailable",
		},
	})
}

func (c *Console) cmdInfo() {
	emit(c.mode, Response{
		Status:  "info",
		Command: "info",
		Message: "> Module info is not available in the startup console.\n> Use `ai` (Plan mode) for attack-path planning, or the operator REPL.",
		Data: map[string]string{
			"status": "unavailable",
		},
	})
}

func (c *Console) cmdRun() {
	emit(c.mode, Response{
		Status:  "info",
		Command: "run",
		Message: "> Module execution is not available in the startup console.\n> Use `ai` (Auto mode) or `erebus serve` operator REPL.",
		Data: map[string]string{
			"status": "unavailable",
		},
	})
}

func (c *Console) cmdLoot() {
	client, addr, err := c.team.connect()
	if err != nil {
		emit(c.mode, Response{
			Status:  "info",
			Command: "loot",
			Message: fmt.Sprintf("> Teamserver unavailable (%v)\n> Start with: erebus serve", err),
			Data: map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
			},
		})
		return
	}
	c.maybeTeamBanner(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.ListLoot(ctx, &pb.ListLootRequest{})
	if err != nil {
		emitError(c.mode, "loot", err.Error())
		return
	}
	if len(resp.Items) == 0 {
		emit(c.mode, Response{
			Status:  "ok",
			Command: "loot",
			Message: "> Loot database empty — run some modules first",
			Data: map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
			},
		})
		return
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("> %d loot item(s)\n", len(resp.Items)))
	for _, item := range resp.Items {
		b.WriteString(fmt.Sprintf("  [%s] %s from %s (%d bytes)\n", item.Type, item.Id, item.Source, len(item.Data)))
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "loot",
		Message: b.String(),
		Data: map[string]interface{}{
			"items": resp.Items,
			"count": len(resp.Items),
		},
	})
}

func (c *Console) cmdReport(args []string) {
	if len(args) == 0 || args[0] != "generate" {
		emitError(c.mode, "report", "Usage: report generate")
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "report",
		Message: "> Report generation is not available yet.\n> Use operator REPL loot/tasks output or export from Zypheron.",
		Data: map[string]string{
			"action": "generate",
			"status": "unavailable",
		},
	})
}

func (c *Console) maybeTeamBanner(addr string) {
	if c.teamBanner || c.mode == OutputJSON {
		return
	}
	c.teamBanner = true
	fmt.Fprintf(os.Stderr, "[erebus] connected to teamserver at %s\n", addr)
}

