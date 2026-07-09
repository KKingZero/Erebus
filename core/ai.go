package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
)

func (c *Console) runAI(objective string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	llmCfg, err := llm.Load(llm.DefaultConfigPath)
	if err != nil {
		emitError(c.mode, "ai", err.Error())
		return
	}

	// Full autonomous agent when teamserver + agent config are available.
	if ran, runErr := c.tryAgentLoop(ctx, objective, llmCfg); ran {
		if runErr != nil {
			emitError(c.mode, "ai", runErr.Error())
		}
		return
	}

	// Advisory mode: chat with Ollama / configured LLM.
	client := llm.NewClient(llmCfg)
	reply, err := client.Chat(ctx, llm.ErebusSystemPrompt, objective)
	if err != nil {
		hint := providerHint(llmCfg, err)
		msg := err.Error()
		if hint != "" {
			msg = fmt.Sprintf("%v\n%s", err, hint)
		}
		emitError(c.mode, "ai", msg)
		return
	}

	msg := fmt.Sprintf("> AI (%s / %s)\n%s", client.Provider(), client.Model(), strings.TrimSpace(reply))
	emit(c.mode, Response{
		Status:  "ok",
		Command: "ai",
		Message: msg,
		Data: map[string]interface{}{
			"objective": objective,
			"provider":  client.Provider(),
			"model":     client.Model(),
			"reply":     reply,
			"mode":      "advisory",
		},
	})
}

func (c *Console) tryAgentLoop(ctx context.Context, objective string, llmCfg llm.Config) (bool, error) {
	agentCfg, ok := agentAvailable(llmCfg)
	if !ok {
		return false, nil
	}

	fmt.Fprintf(os.Stderr, "[erebus] teamserver detected — running autonomous agent (%s / %s)\n",
		llmCfg.Provider, llmCfg.Model)

	emit(c.mode, Response{
		Status:  "info",
		Command: "ai",
		Message: fmt.Sprintf("> Starting autonomous agent (%s / %s) for: %s\n> High-risk actions require `erebus serve` + approve in another terminal",
			llmCfg.Provider, llmCfg.Model, objective),
		Data: map[string]string{
			"objective": objective,
			"mode":      "autonomous",
			"provider":  llmCfg.Provider,
		},
	})

	err := agent.Run(ctx, agentCfg, agent.RunOptions{
		Objective: objective,
		OnApproval: func(id, risk, desc string) (agent.ApprovalAction, string) {
			// Non-TUI path: notify and wait for external approver (or dual-seat auto if wired later).
			fmt.Fprintf(os.Stderr, "[approval] id=%s risk=%s — approve in AI TUI (preferred) or: operator → pending → approve %s (%s)\n",
				id, risk, id, desc)
			return agent.ApprovalExternal, ""
		},
		OnStep: func(step agent.StepOutput) {
			if c.mode == OutputJSON {
				EmitJSONStep(step)
				return
			}
			if step.Done {
				fmt.Printf("\n[done] %s\n", step.Message)
			} else if step.Error != "" {
				fmt.Printf("[step %d] %s FAILED: %s\n", step.Step, step.Tool, step.Error)
			} else if step.Tool != "" {
				fmt.Printf("[step %d] %s (%s): %s\n", step.Step, step.Tool, step.Risk, truncateAI(step.Result, 300))
			} else if step.Message != "" {
				fmt.Printf("[step %d] %s\n", step.Step, step.Message)
			}
		},
	})
	return true, err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func providerHint(cfg llm.Config, err error) string {
	switch cfg.Provider {
	case "ollama":
		return "Hint: ensure Ollama is running (`ollama serve`) and the model is pulled (`ollama pull " + cfg.Model + "`)."
	case "openai", "anthropic", "bedrock", "kimi", "gemini":
		return "Hint: set your API key with `ai key " + cfg.Provider + "` or env var. Run `ai providers` to see options."
	default:
		return ""
	}
}

func truncateAI(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}