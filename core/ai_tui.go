package core

import (
	"fmt"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/core/aitui"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
)

func (c *Console) runAITUI(initialMsg string) {
	if c.mode == OutputJSON {
		if initialMsg != "" {
			c.runAI(initialMsg)
		} else {
			emitError(c.mode, "ai", "JSON mode: use ai \"<objective>\" for one-shot chat")
		}
		return
	}

	llmCfg, err := llm.Load(llm.DefaultConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ai: %v\n", err)
		return
	}
	if llmCfg.Provider == string(llm.ProviderOllama) {
		if resolved, err := llm.ResolveOllamaModel(llmCfg); err == nil {
			llmCfg = resolved
		}
	}

	var agentCfg *agent.Config
	if ac, ok := agentAvailable(llmCfg); ok {
		agentCfg = ac
	}

	mode, err := aitui.Run(aitui.Options{
		LLMCfg:     llmCfg,
		AgentCfg:   agentCfg,
		InitialMsg: initialMsg,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ai tui: %v\n", err)
		return
	}
	if mode == aitui.QuitAll {
		c.running = false
	}
}