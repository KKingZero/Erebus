package core

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chzyer/readline"
)

const banner = `
888888 88""Yb 888888 88""Yb 88   88 .dP"Y8
88__   88__dP 88__   88__dP 88   88 Ybo."
88""   88"Yb  88""   88""Yb Y8   8P o.Y8b
888888 88  Yb 888888 88oodP YbodP  8bodP

    Exploitation Framework - Powered by AI
             by Zypheron Team
`

type Console struct {
	currentModule string
	workspace     string
	session       string
	running       bool
	mode          OutputMode
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

// startInteractive runs the human-friendly readline REPL
func (c *Console) startInteractive() {
	fmt.Println(banner)
	fmt.Println("  Type 'help' for available commands\n")

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.prompt(),
		HistoryFile:     "/tmp/erebus_history",
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
	}
}

// startJSON runs a line-oriented JSON mode for AI/programmatic control.
// Reads one command per line from stdin, emits one JSON object per line to stdout.
func (c *Console) startJSON() {
	emit(c.mode, Response{
		Status:  "ok",
		Command: "init",
		Message: "Erebus console ready",
		Data: map[string]interface{}{
			"version": "0.1.0",
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
		return fmt.Sprintf("erc (%s) > ", c.currentModule)
	}
	return "erc > "
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
			fmt.Println(banner)
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
		if c.mode == OutputJSON {
			emitError(c.mode, cmd, fmt.Sprintf("Unknown command: %s", cmd))
			return
		}
		command := exec.Command(parts[0], parts[1:]...)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.Stdin = os.Stdin
		if err := command.Run(); err != nil {
			fmt.Printf("> Unknown command: %s\n", parts[0])
		}
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
		{"use <module>", "Load a module"},
		{"back", "Unload current module"},
		{"search <term>", "Search modules by name, CVE, platform"},
		{"info", "Show current module info"},
		{"options", "Show current module options"},
		{"run / exploit", "Execute current module"},
		{"sessions", "List active sessions"},
		{"sessions -i <id>", "Interact with a session"},
		{"workspace <new|list>", "Manage engagements"},
		{"loot", "Show captured loot"},
		{"report generate", "Generate pentest report"},
		{"ai \"<objective>\"", "AI attack planner"},
		{"clear", "Clear screen"},
		{"exit", "Exit Erebus"},
	}

	categories := []CategoryEntry{
		{"recon/passive", "Passive recon — no target interaction"},
		{"recon/active", "Active recon — touches target"},
		{"exploit/web/<name>", "Web exploitation modules"},
		{"exploit/network/<name>", "Network exploitation modules"},
		{"modules/ad/<name>", "Active Directory attacks"},
		{"modules/post/windows", "Windows post-exploitation"},
		{"modules/post/linux", "Linux post-exploitation"},
		{"modules/container/", "Container escape modules"},
		{"modules/pivot", "Pivoting and tunneling"},
	}

	var humanMsg strings.Builder
	humanMsg.WriteString("\nCore Commands:\n")
	for _, cmd := range commands {
		humanMsg.WriteString(fmt.Sprintf("  %-24s%s\n", cmd.Command, cmd.Description))
	}
	humanMsg.WriteString("\nModule Categories:\n")
	for _, cat := range categories {
		humanMsg.WriteString(fmt.Sprintf("  %-24s%s\n", cat.Path, cat.Description))
	}

	emit(c.mode, Response{
		Status:  "ok",
		Command: "help",
		Message: humanMsg.String(),
		Data: map[string]interface{}{
			"commands":   commands,
			"categories": categories,
		},
	})
}


func (c *Console) cmdUse(args []string) {
	if len(args) == 0 {
		emitError(c.mode, "use", "Usage: use <module>")
		return
	}
	c.currentModule = args[0]
	emit(c.mode, Response{
		Status:  "ok",
		Command: "use",
		Message: fmt.Sprintf("> Loaded module: %s", c.currentModule),
		Data: map[string]string{
			"module": c.currentModule,
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
		Message: fmt.Sprintf("> Searching for: %s\n> Module registry coming soon...", query),
		Data: map[string]interface{}{
			"query":   query,
			"results": []interface{}{},
		},
	})
}

func (c *Console) cmdSessions(args []string) {
	if len(args) > 0 && args[0] == "-i" {
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		emit(c.mode, Response{
			Status:  "info",
			Command: "sessions",
			Message: "> Session interaction coming soon...",
			Data: map[string]interface{}{
				"action":     "interact",
				"session_id": id,
			},
		})
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "sessions",
		Message: "> No active sessions",
		Data: map[string]interface{}{
			"sessions": []interface{}{},
			"count":    0,
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
	if c.currentModule == "" {
		emitError(c.mode, "options", "No module loaded. Use 'use <module>' first")
		return
	}

	type Option struct {
		Name        string `json:"name"`
		Value       string `json:"value"`
		Required    bool   `json:"required"`
		Description string `json:"description"`
	}

	opts := []Option{
		{"RHOST", "", true, "Target host"},
		{"LHOST", "", true, "Local host"},
		{"LPORT", "4444", true, "Local port"},
	}

	var humanMsg strings.Builder
	humanMsg.WriteString(fmt.Sprintf("> Options for: %s\n", c.currentModule))
	humanMsg.WriteString("  Name        Value     Required  Description\n")
	humanMsg.WriteString("  ----        -----     --------  -----------\n")
	for _, o := range opts {
		req := "yes"
		if !o.Required {
			req = "no"
		}
		humanMsg.WriteString(fmt.Sprintf("  %-10s  %-8s  %-8s  %s\n", o.Name, o.Value, req, o.Description))
	}

	emit(c.mode, Response{
		Status:  "ok",
		Command: "options",
		Message: humanMsg.String(),
		Data: map[string]interface{}{
			"module":  c.currentModule,
			"options": opts,
		},
	})
}

func (c *Console) cmdInfo() {
	if c.currentModule == "" {
		emitError(c.mode, "info", "No module loaded")
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "info",
		Message: fmt.Sprintf("> Module: %s\n> Full info coming soon...", c.currentModule),
		Data: map[string]string{
			"module": c.currentModule,
		},
	})
}

func (c *Console) cmdRun() {
	if c.currentModule == "" {
		emitError(c.mode, "run", "No module loaded. Use 'use <module>' first")
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "run",
		Message: fmt.Sprintf("> Executing: %s\n> Module execution engine coming soon...", c.currentModule),
		Data: map[string]string{
			"module": c.currentModule,
			"status": "pending",
		},
	})
}

func (c *Console) cmdLoot() {
	emit(c.mode, Response{
		Status:  "ok",
		Command: "loot",
		Message: "> Loot database empty — run some modules first",
		Data: map[string]interface{}{
			"items": []interface{}{},
			"count": 0,
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
		Message: "> Generating report...\n> Report engine coming soon...",
		Data: map[string]string{
			"action": "generate",
			"status": "pending",
		},
	})
}

func (c *Console) cmdAI(args []string) {
	if len(args) == 0 {
		emitError(c.mode, "ai", "Usage: ai \"<objective>\"")
		return
	}
	objective := strings.Join(args, " ")
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: fmt.Sprintf("> AI planning attack for: %s\n> AI engine coming soon...", objective),
		Data: map[string]string{
			"objective": objective,
			"status":    "pending",
		},
	})
}
