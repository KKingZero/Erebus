package agent

import (
	"fmt"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

// InterpretResult returns a compact LLM-friendly summary of a task result.
func InterpretResult(taskType pb.TaskType, result *pb.TaskResult) string {
	if result == nil {
		return "no result"
	}
	if !result.Success {
		return fmt.Sprintf("FAILED: %s", result.Error)
	}
	if len(result.Data) == 0 {
		return "OK (empty data)"
	}

	var summary string
	var actions []string

	switch taskType {
	case pb.TaskType_TASK_SHELL:
		r := &pb.ShellResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			out := strings.TrimSpace(r.Stdout)
			if len(out) > 2000 {
				out = out[:2000] + "...(truncated)"
			}
			summary = fmt.Sprintf("shell exit=%d stdout=%q stderr=%q", r.ExitCode, out, strings.TrimSpace(r.Stderr))
		}
	case pb.TaskType_TASK_NET_IFCONFIG:
		r := &pb.NetIfconfigResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("ifconfig: %d interfaces", len(r.Interfaces))
		}
	case pb.TaskType_TASK_PROCESS_LIST:
		r := &pb.ProcessListResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("processes: %d running", len(r.Processes))
		}
	case pb.TaskType_TASK_PROCESS_KILL:
		r := &pb.ProcessKillResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("process_kill success=%v", r.Success)
		}
	case pb.TaskType_TASK_NET_PORTSCAN:
		r := &pb.NetPortscanResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			open := 0
			for _, p := range r.Ports {
				if p.Open {
					open++
				}
			}
			summary = fmt.Sprintf("portscan: %d open / %d probed", open, len(r.Ports))
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_FILE_DOWNLOAD:
		r := &pb.FileDownloadResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("file_download: %s (%d bytes)", r.Filename, len(r.Data))
		}
	case pb.TaskType_TASK_FILE_UPLOAD:
		r := &pb.FileUploadResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("file_upload success=%v", r.Success)
		}
	case pb.TaskType_TASK_SCREENSHOT:
		r := &pb.ScreenshotResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("screenshot: %dx%d format=%s (%d bytes)", r.Width, r.Height, r.Format, len(r.ImageData))
		}
	case pb.TaskType_TASK_SOCKS_START:
		r := &pb.SocksStartResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("socks_start success=%v port=%d", r.Success, r.Port)
		}
	case pb.TaskType_TASK_SOCKS_STOP:
		r := &pb.SocksStopResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("socks_stop success=%v", r.Success)
		}
	case pb.TaskType_TASK_MODULE:
		// Try SMB first (shares/files), then cloud harvest.
		smb := &pb.SMBClientResult{}
		if proto.Unmarshal(result.Data, smb) == nil && (smb.Action != "" || len(smb.Names) > 0 || len(smb.FileData) > 0) {
			summary = fmt.Sprintf("smb %s host=%s share=%s names=%d bytes=%d",
				smb.Action, smb.Host, smb.Share, len(smb.Names), len(smb.FileData))
			actions = smb.NextSuggestedActions
			break
		}
		r := &pb.CloudHarvestResult{}
		if proto.Unmarshal(result.Data, r) == nil && (len(r.Tokens) > 0 || len(r.Credentials) > 0 || r.Metadata != "") {
			summary = fmt.Sprintf("cloud_harvest provider=%s tokens=%d creds=%d", r.Provider, len(r.Tokens), len(r.Credentials))
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_LDAP_ENUM:
		r := &pb.LDAPEnumResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("ldap %s@%s: %d entries (query=%s)", r.Domain, r.Dc, r.TotalResults, r.QueryType)
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_KERBEROAST:
		r := &pb.KerberoastResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("kerberoast: %d hashes", len(r.Hashes))
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_ASREPROAST:
		r := &pb.ASREPRoastResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("asreproast: %d hashes", len(r.Hashes))
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_CREDS_DUMP:
		r := &pb.CredDumpResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("creds_dump %s: %d credentials", r.Method, len(r.Credentials))
			actions = r.NextSuggestedActions
		}
	case pb.TaskType_TASK_LATERAL_MOVE:
		r := &pb.LateralMoveResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("lateral %s -> %s success=%v output=%s", r.Method, r.Target, r.Success, truncate(r.Output, 500))
		}
	case pb.TaskType_TASK_PERSIST:
		r := &pb.PersistResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("persist %s success=%v %s", r.Method, r.Success, r.Details)
		}
	case pb.TaskType_TASK_PRIVESC:
		r := &pb.PrivescResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			summary = fmt.Sprintf("privesc %s success=%v integrity=%s pid=%d", r.Method, r.Success, r.NewIntegrity, r.NewPid)
		}
	}

	if summary == "" {
		summary = fmt.Sprintf("OK data=%d bytes", len(result.Data))
	}
	return formatWithActions(summary, actions)
}

func formatWithActions(summary string, actions []string) string {
	if len(actions) == 0 {
		return summary
	}
	return summary + "\nnext_suggested_actions: " + strings.Join(actions, "; ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FormatSessions summarizes session list for the LLM.
func FormatSessions(sessions []*pb.SessionInfo) string {
	if len(sessions) == 0 {
		return "no active sessions"
	}
	var b strings.Builder
	for _, s := range sessions {
		fmt.Fprintf(&b, "- %s: %s@%s (%s/%s) alive=%v last=%d\n",
			s.SessionId, s.Username, s.Hostname, s.Os, s.Arch, s.Alive, s.LastCheckin)
	}
	return b.String()
}