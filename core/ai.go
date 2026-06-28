package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
)

const aiSystemPrompt = `You are Erebus, an AI offensive security assistant for authorized penetration tests and red team exercises.

You help operators plan AD and cloud attack paths, interpret recon results, and suggest next steps.
Be concise, actionable, and note opsec considerations. If the user greets you or asks general questions, respond helpfully while staying in scope of authorized security testing.

When the teamserver is not connected, provide planning guidance only — do not claim to have executed commands on targets.`

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
	reply, err := client.Chat(ctx, aiSystemPrompt, objective)
	if err != nil {
		hint := ollamaHint(llmCfg, err)
		emitError(c.mode, "ai", fmt.Sprintf("%v\n%s", err, hint))
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
	agentCfg, err := agent.LoadConfigOptional(agent.DefaultConfigPath)
	if err != nil {
		return false, nil
	}
	cert, key, ca := erebuscli.DefaultCertPaths()
	if !fileExists(cert) || !fileExists(key) || !fileExists(ca) {
		return false, nil
	}
	agentCfg.Cert, agentCfg.Key, agentCfg.CA = cert, key, ca
	if !erebuscli.GRPCReachable(agentCfg.Server) {
		return false, nil
	}

	agentCfg.LLM = agent.LLMConfig{
		BaseURL: llmCfg.BaseURL,
		APIKey:  llmCfg.APIKey,
		Model:   llmCfg.Model,
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

	err = agent.Run(ctx, agentCfg, agent.RunOptions{
		Objective: objective,
		OnApproval: func(id, risk, desc string) {
			fmt.Fprintf(os.Stderr, "[approval] id=%s risk=%s — run: erebus operator → pending → approve %s (%s)\n",
				id, risk, id, desc)
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

func ollamaHint(cfg llm.Config, err error) string {
	if cfg.Provider != "ollama" {
		return ""
	}
	return "Hint: ensure Ollama is running (`ollama serve`) and the model is pulled (`ollama pull " + cfg.Model + "`). Config: ~/.erebus/llm.yaml"
}

func truncateAI(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}