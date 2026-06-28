package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func main() {
	configPath := flag.String("config", agent.DefaultConfigPath, "Agent config YAML path")
	objective := flag.String("objective", "", "Attack objective for the AI agent")
	sessionID := flag.String("session", "", "Primary implant session ID")
	jsonMode := flag.Bool("json", false, "Emit one JSON object per step")
	watch := flag.Bool("watch", false, "Wait for new sessions when -session not set")
	dryRun := flag.String("dry-run", "", "Run a single tool without LLM (e.g. net_ifconfig)")
	flag.Parse()

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client, err := agent.Connect(cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if err := client.StartSubscribe(ctx); err != nil {
		log.Fatalf("subscribe: %v", err)
	}

	sid := *sessionID
	if sid == "" && *watch {
		sid, err = waitForSession(ctx, client, *objective)
		if err != nil {
			log.Fatalf("watch: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[agent] selected session %s\n", sid)
	}

	if *dryRun != "" {
		if sid == "" {
			log.Fatal("-session required for -dry-run")
		}
		exec := &agent.Executor{Client: client}
		fullArgs := fmt.Sprintf(`{"session_id":%q}`, sid)
		if *dryRun == "run_shell" {
			fullArgs = fmt.Sprintf(`{"session_id":%q,"command":"whoami"}`, sid)
		}
		result, err := exec.RunTool(ctx, *dryRun, fullArgs, sid)
		if err != nil {
			log.Fatalf("dry-run: %v", err)
		}
		fmt.Println(result)
		return
	}

	if *objective == "" {
		log.Fatal("-objective is required (or use -dry-run for smoke test)")
	}

	err = agent.Run(ctx, cfg, agent.RunOptions{
		Objective: *objective,
		SessionID: sid,
		JSONMode:  *jsonMode,
		OnApproval: func(id, risk, desc string) {
			msg := fmt.Sprintf("[APPROVAL REQUIRED] id=%s risk=%s desc=%s — run: operator → pending → approve %s",
				id, risk, desc, id)
			if *jsonMode {
				agent.EmitJSON(agent.StepOutput{Message: msg})
			} else {
				fmt.Fprintln(os.Stderr, msg)
			}
		},
		OnStep: func(out agent.StepOutput) {
			if *jsonMode {
				agent.EmitJSON(out)
				return
			}
			if out.Done {
				fmt.Printf("\n[done] %s\n", out.Message)
			} else if out.Error != "" {
				fmt.Printf("[step %d] %s FAILED: %s\n", out.Step, out.Tool, out.Error)
			} else if out.Tool != "" {
				fmt.Printf("[step %d] %s (%s): %s\n", out.Step, out.Tool, out.Risk, truncate(out.Result, 200))
			} else if out.Message != "" {
				fmt.Printf("[step %d] %s\n", out.Step, out.Message)
			}
		},
	})
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
}

func waitForSession(ctx context.Context, client *agent.Client, objective string) (string, error) {
	if objective == "" {
		objective = "initial enumeration"
	}
	fmt.Fprintf(os.Stderr, "[agent] watching for new sessions (objective: %s)...\n", objective)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case ev := <-client.EventChannel():
			if ev.Type == pb.EventType_EVENT_SESSION_NEW && ev.SessionId != "" {
				return ev.SessionId, nil
			}
		case <-ticker.C:
			resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{})
			if err != nil {
				continue
			}
			for _, s := range resp.Sessions {
				if s.Alive {
					return s.SessionId, nil
				}
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}