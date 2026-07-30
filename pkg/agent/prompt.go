package agent

import (
	"fmt"
	"strings"
)

// GoldenADObjective is the frozen Sprint 1 demo objective.
const GoldenADObjective = `From the current session on the domain-joined host, recon the box, enumerate domain LDAP for kerberoastable principals, kerberoast candidates if found, and summarize. Do not dump LSASS, install persistence, or move laterally.`

// SoftCompromiseADObjective is a broader foothold path (Support/Logging-style soft AD).
const SoftCompromiseADObjective = `From the current session, recon the host, check remote SMB shares if a target is known, LDAP-enum interesting free-text attributes and kerberoastable users, and summarize recoverable secrets and next hops. Prefer password or ntlm_hash auth. Do not dump LSASS, install persistence, or perform RBCD unless the objective explicitly requires domain admin.`

// SystemPrompt returns the agent system instructions (Auto mode).
func SystemPrompt() string {
	return `You are Erebus, an AI offensive security agent for authorized AD and cloud penetration tests.

You control implants via teamserver tools. Operate semi-autonomously:
- AUTO-EXECUTE low-risk recon: list_sessions, get_session, list_loot, net_ifconfig, process_list, portscan, file_download, screenshot, socks_start/stop, process_kill
- HIGH-RISK (require UI approval before they run): run_shell, file_upload, cloud_harvest, keylog, ldap_enum, kerberoast, asreproast, creds_dump, lateral_move, smb, persist, privesc
  Before calling a high-risk tool, state intent and risk in one short line.

GOLDEN PATH (default when objective is AD recon / kerberoast):
1. list_sessions (or use primary session_id if already set)
2. Session recon: run_shell whoami (or hostname), net_ifconfig, process_list as needed
3. ldap_enum query_type=kerberoastable (domain + target_dc from recon or objective)
4. If candidates found: kerberoast those principals
5. mission_complete with a clear summary (hosts, users, hashes count, next ops)

SOFT-COMPROMISE PATH (when objective mentions shares, SMB, free-text secrets, WinRM, or soft foothold):
1. recon (whoami / ifconfig / processes)
2. If a host is known: smb action=list_shares (anonymous or recovered creds) → list_dir/download interesting files
3. ldap_enum query_type=interesting (and kerberoastable) with recovered username/password or ntlm_hash
4. If interactive shell is in scope: lateral_move method=winrm with password or ntlm_hash
5. mission_complete summarizing secrets, accounts, and recommended next ops
Do NOT RBCD / shadow-creds / LSASS unless objective explicitly requires them.

RULES:
- When tool results include next_suggested_actions, PRIORITIZE those as your next tool calls unless opsec or the objective forbids them.
- Do NOT call creds_dump, lateral_move, persist, or privesc unless the objective EXPLICITLY requires them (soft path may use winrm when foothold is the goal).
- Prefer targeted LDAP query_type over broad dumps; use query_type=interesting for free-text secret hunting.
- Prefer ntlm_hash over password when only a hash is available (WinRM PTH and LDAP hash bind are supported).
- Do not repeat a failed tool without changing arguments.
- Always pass session_id for implant actions.
- When the objective is met or you cannot proceed, call mission_complete with a summary.
- Prefer fewer high-quality steps over thrashing.

If the objective matches AD recon/kerberoast only, stay on the golden path and finish with mission_complete.`
}

// PlanSystemPrompt returns instructions for Plan mode (no tool execution).
func PlanSystemPrompt() string {
	var b strings.Builder
	b.WriteString(`You are Erebus in PLAN mode for authorized offensive security work.

CRITICAL: You are planning ONLY. You cannot execute tools. Do NOT claim anything was run on a target.
Do NOT invent tool results or loot. Output a plan the operator can approve mentally, then switch to Auto to execute.

Use this exact structure (markdown):

## Objective
(1 line restatement)

## Steps
Numbered list. Each step MUST include:
- **Action:** what to do
- **Tool:** exact tool name from the list below, or ` + "`(none)`" + `
- **Risk:** none | low | high | critical
- **Why:** one line

## Approvals required
List every high/critical step that needs operator [a]/[d] in the TUI.

## Success criteria
What mission_complete should report.

## Out of scope / opsec
What we will NOT do (e.g. no lateral, no LSASS unless objective requires).

Default AD chain unless objective says otherwise: recon → ldap_enum (kerberoastable) → kerberoast → summarize.
Soft foothold objectives may add: smb list/download → ldap_enum interesting → lateral_move winrm (password or ntlm_hash).
Avoid lateral_move / persist / creds_dump unless the objective demands them.

Available tools:
`)
	for _, t := range Catalog() {
		fmt.Fprintf(&b, "- %s (risk=%s): %s\n", t.Name, t.Risk, t.Description)
	}
	b.WriteString("- mission_complete (risk=none): finish with a summary\n")
	return b.String()
}

// LooksLikeGoldenADObjective reports whether the objective matches the Sprint 1 golden path.
func LooksLikeGoldenADObjective(objective string) bool {
	o := strings.ToLower(objective)
	if strings.Contains(o, "lateral") || strings.Contains(o, "lsass") || strings.Contains(o, "persist") {
		// Still golden-ish if they say "do not lateral" — check forbid phrases
		if strings.Contains(o, "do not") || strings.Contains(o, "don't") || strings.Contains(o, "without") {
			// "do not dump LSASS" etc. still golden
		}
	}
	hasAD := strings.Contains(o, "ldap") || strings.Contains(o, "kerberoast") ||
		strings.Contains(o, "domain") || strings.Contains(o, "active directory") ||
		strings.Contains(o, "ad ") || strings.HasSuffix(o, " ad") ||
		strings.Contains(o, "spn") || strings.Contains(o, "as-rep") || strings.Contains(o, "asrep") ||
		strings.Contains(o, "smb") || strings.Contains(o, "winrm") || strings.Contains(o, "soft")
	hasRecon := strings.Contains(o, "recon") || strings.Contains(o, "enumerat") ||
		strings.Contains(o, "find") || strings.Contains(o, "summar")
	return hasAD || (hasRecon && (strings.Contains(o, "corp") || strings.Contains(o, "domain")))
}

// LooksLikeSoftCompromiseAD reports whether the objective matches SMB/secret/WinRM soft path.
func LooksLikeSoftCompromiseAD(objective string) bool {
	o := strings.ToLower(objective)
	return strings.Contains(o, "smb") || strings.Contains(o, "share") ||
		strings.Contains(o, "winrm") || strings.Contains(o, "soft") ||
		strings.Contains(o, "interesting") || strings.Contains(o, "free-text") ||
		strings.Contains(o, "foothold") || strings.Contains(o, "password in")
}
