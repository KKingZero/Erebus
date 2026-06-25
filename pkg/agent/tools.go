package agent

import (
	openai "github.com/sashabaranov/go-openai"
)

// OpenAITools returns function tool definitions for the LLM.
func OpenAITools() []openai.Tool {
	defs := []struct {
		name   string
		desc   string
		params map[string]any
	}{
		{"list_sessions", "List all implant sessions", map[string]any{"type": "object", "properties": map[string]any{}}},
		{"get_session", "Get session details", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string", "description": "Session ID"},
			},
			"required": []string{"session_id"},
		}},
		{"list_loot", "List loot items", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string", "description": "Optional session filter"},
			},
		}},
		{"run_shell", "Run shell command on implant", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"command":    map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "command"},
		}},
		{"net_ifconfig", "Network interfaces on implant", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
			},
			"required": []string{"session_id"},
		}},
		{"process_list", "List processes on implant", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
			},
			"required": []string{"session_id"},
		}},
		{"portscan", "TCP port scan from implant", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"target":     map[string]any{"type": "string"},
				"ports":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
			},
			"required": []string{"session_id", "target"},
		}},
		{"ldap_enum", "LDAP AD enumeration", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id":  map[string]any{"type": "string"},
				"query_type":  map[string]any{"type": "string", "description": "e.g. kerberoastable, domain_admins, domain_controllers"},
				"domain":      map[string]any{"type": "string"},
				"target_dc":   map[string]any{"type": "string"},
				"username":    map[string]any{"type": "string"},
				"password":    map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "query_type", "domain", "target_dc"},
		}},
		{"kerberoast", "Kerberoast attack", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"target_dc":  map[string]any{"type": "string"},
				"username":   map[string]any{"type": "string"},
				"password":   map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "domain", "target_dc", "username", "password"},
		}},
		{"asreproast", "AS-REP roast attack", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"target_dc":  map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "domain", "target_dc"},
		}},
		{"creds_dump", "Dump credentials", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"method":     map[string]any{"type": "string", "enum": []string{"lsass", "sam", "browser"}},
			},
			"required": []string{"session_id", "method"},
		}},
		{"lateral_move", "Lateral movement", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"method":     map[string]any{"type": "string", "enum": []string{"wmi", "winrm", "psexec"}},
				"target":     map[string]any{"type": "string"},
				"command":    map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"username":   map[string]any{"type": "string"},
				"password":   map[string]any{"type": "string"},
				"ntlm_hash":  map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "method", "target"},
		}},
		{"persist", "Install persistence", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id":   map[string]any{"type": "string"},
				"method":       map[string]any{"type": "string"},
				"name":         map[string]any{"type": "string"},
				"payload_path": map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "method"},
		}},
		{"privesc", "Privilege escalation", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"method":     map[string]any{"type": "string"},
				"command":    map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "method"},
		}},
		{"mission_complete", "Signal that the objective is achieved or cannot proceed", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"summary": map[string]any{"type": "string"},
			},
			"required": []string{"summary"},
		}},
	}

	tools := make([]openai.Tool, 0, len(defs))
	for _, d := range defs {
		tools = append(tools, openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        d.name,
				Description: d.desc,
				Parameters:  d.params,
			},
		})
	}
	return tools
}