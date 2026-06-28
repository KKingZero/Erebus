package core

import (
	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
)

// agentAvailable returns a ready agent config when teamserver and mTLS certs are present.
func agentAvailable(llmCfg llm.Config) (*agent.Config, bool) {
	agentCfg, err := agent.LoadConfigOptional(agent.DefaultConfigPath)
	if err != nil {
		return nil, false
	}
	cert, key, ca := erebuscli.DefaultCertPaths()
	if !fileExists(cert) || !fileExists(key) || !fileExists(ca) {
		return nil, false
	}
	agentCfg.Cert, agentCfg.Key, agentCfg.CA = cert, key, ca
	if !erebuscli.GRPCReachable(agentCfg.Server) {
		return nil, false
	}
	agentCfg.LLM = agent.LLMConfig{
		BaseURL: llmCfg.BaseURL,
		APIKey:  llmCfg.APIKey,
		Model:   llmCfg.Model,
	}
	return agentCfg, true
}