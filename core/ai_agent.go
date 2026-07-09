package core

import (
	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/llm"
)

// agentAvailable returns a ready agent config when teamserver and mTLS certs are present.
// Requires operator + approver seats so Auto mode can dual-control approve in-process.
func agentAvailable(llmCfg llm.Config) (*agent.Config, bool) {
	cert, key, ca := erebuscli.DefaultCertPaths()
	if !fileExists(cert) || !fileExists(key) || !fileExists(ca) {
		return nil, false
	}
	apCert, apKey := erebuscli.DefaultApproverCertPaths()
	if !fileExists(apCert) || !fileExists(apKey) {
		// Without approver seat, in-TUI [a]/[d] cannot satisfy dual-control.
		return nil, false
	}

	agentCfg, err := agent.LoadConfigOptional(agent.DefaultConfigPath)
	if err != nil {
		// First-run / demo: synthesize defaults when agent.yaml is missing.
		agentCfg = &agent.Config{
			Server: "127.0.0.1:50051",
		}
		agentCfg.Autonomy.MaxSteps = 50
	}
	agentCfg.Cert, agentCfg.Key, agentCfg.CA = cert, key, ca
	if agentCfg.ApproverCert == "" {
		agentCfg.ApproverCert, agentCfg.ApproverKey = apCert, apKey
	}
	if !fileExists(agentCfg.ApproverCert) || !fileExists(agentCfg.ApproverKey) {
		return nil, false
	}
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
