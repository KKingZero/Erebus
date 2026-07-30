package agent

// ToolSchemas returns OpenAI function parameter schemas keyed by tool name.
func ToolSchemas() map[string]map[string]any {
	return map[string]map[string]any{
		"list_sessions": {"type": "object", "properties": map[string]any{}},
		"get_session": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string", "description": "Session ID"},
			},
			"required": []string{"session_id"},
		},
		"list_loot": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string", "description": "Optional session filter"},
			},
		},
		"run_shell": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"command":    map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "command"},
		},
		"net_ifconfig": {
			"type": "object",
			"properties": map[string]any{"session_id": map[string]any{"type": "string"}},
			"required":   []string{"session_id"},
		},
		"process_list": {
			"type": "object",
			"properties": map[string]any{"session_id": map[string]any{"type": "string"}},
			"required":   []string{"session_id"},
		},
		"process_kill": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"pid":        map[string]any{"type": "integer"},
			},
			"required": []string{"session_id", "pid"},
		},
		"portscan": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"target":     map[string]any{"type": "string"},
				"ports":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
			},
			"required": []string{"session_id", "target"},
		},
		"file_download": {
			"type": "object",
			"properties": map[string]any{
				"session_id":   map[string]any{"type": "string"},
				"remote_path":  map[string]any{"type": "string", "description": "Relative path from implant cwd (no absolute paths or ..)"},
			},
			"required": []string{"session_id", "remote_path"},
		},
		"file_upload": {
			"type": "object",
			"properties": map[string]any{
				"session_id":   map[string]any{"type": "string"},
				"local_path":   map[string]any{"type": "string", "description": "Path on operator host"},
				"remote_path":  map[string]any{"type": "string", "description": "Relative path from implant cwd (no absolute paths or ..)"},
			},
			"required": []string{"session_id", "local_path", "remote_path"},
		},
		"cloud_harvest": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"provider":   map[string]any{"type": "string", "description": "azure, aws, gcp, imds, or all"},
				"method":     map[string]any{"type": "string", "description": "cli, imds, managed_identity, or all"},
			},
			"required": []string{"session_id"},
		},
		"smb": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"action":     map[string]any{"type": "string", "description": "list_shares, list_dir, or download"},
				"host":       map[string]any{"type": "string"},
				"share":      map[string]any{"type": "string"},
				"path":       map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"username":   map[string]any{"type": "string"},
				"password":   map[string]any{"type": "string"},
				"ntlm_hash":  map[string]any{"type": "string"},
				"anonymous":  map[string]any{"type": "boolean"},
			},
			"required": []string{"session_id", "host"},
		},
		"screenshot": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"monitor":    map[string]any{"type": "integer"},
				"quality":    map[string]any{"type": "integer"},
			},
			"required": []string{"session_id"},
		},
		"socks_start": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"port":       map[string]any{"type": "integer"},
			},
			"required": []string{"session_id"},
		},
		"socks_stop": {
			"type": "object",
			"properties": map[string]any{"session_id": map[string]any{"type": "string"}},
			"required":   []string{"session_id"},
		},
		"ldap_enum": {
			"type": "object",
			"properties": map[string]any{
				"session_id":     map[string]any{"type": "string"},
				"query_type":     map[string]any{"type": "string", "description": "kerberoastable, asrep_roastable, interesting, secrets, users, dcs, rbcd, groups, admins, computers, ..."},
				"domain":         map[string]any{"type": "string"},
				"target_dc":      map[string]any{"type": "string"},
				"username":       map[string]any{"type": "string"},
				"password":       map[string]any{"type": "string"},
				"ntlm_hash":      map[string]any{"type": "string", "description": "NT or LM:NT hash for pass-the-hash LDAP bind"},
				"custom_filter":  map[string]any{"type": "string"},
				"attributes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"session_id", "query_type", "domain", "target_dc"},
		},
		"kerberoast": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"target_dc":  map[string]any{"type": "string"},
				"username":   map[string]any{"type": "string"},
				"password":   map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "domain", "target_dc", "username", "password"},
		},
		"asreproast": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"domain":     map[string]any{"type": "string"},
				"target_dc":  map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "domain", "target_dc"},
		},
		"creds_dump": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"method":     map[string]any{"type": "string", "enum": []string{"lsass", "sam", "browser"}},
			},
			"required": []string{"session_id", "method"},
		},
		"lateral_move": {
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
		},
		"persist": {
			"type": "object",
			"properties": map[string]any{
				"session_id":   map[string]any{"type": "string"},
				"method":       map[string]any{"type": "string"},
				"name":         map[string]any{"type": "string"},
				"payload_path": map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "method"},
		},
		"privesc": {
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"method":     map[string]any{"type": "string"},
				"command":    map[string]any{"type": "string"},
			},
			"required": []string{"session_id", "method"},
		},
		"mission_complete": {
			"type": "object",
			"properties": map[string]any{
				"summary": map[string]any{"type": "string"},
			},
			"required": []string{"summary"},
		},
	}
}