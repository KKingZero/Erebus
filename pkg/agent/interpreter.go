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

	switch taskType {
	case pb.TaskType_TASK_SHELL:
		r := &pb.ShellResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			out := strings.TrimSpace(r.Stdout)
			if len(out) > 2000 {
				out = out[:2000] + "...(truncated)"
			}
			return fmt.Sprintf("shell exit=%d stdout=%q stderr=%q", r.ExitCode, out, strings.TrimSpace(r.Stderr))
		}
	case pb.TaskType_TASK_NET_IFCONFIG:
		r := &pb.NetIfconfigResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("ifconfig: %d interfaces", len(r.Interfaces))
		}
	case pb.TaskType_TASK_PROCESS_LIST:
		r := &pb.ProcessListResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("processes: %d running", len(r.Processes))
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
			return fmt.Sprintf("portscan: %d open / %d probed", open, len(r.Ports))
		}
	case pb.TaskType_TASK_LDAP_ENUM:
		r := &pb.LDAPEnumResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("ldap %s@%s: %d entries (query=%s)", r.Domain, r.Dc, r.TotalResults, r.QueryType)
		}
	case pb.TaskType_TASK_KERBEROAST:
		r := &pb.KerberoastResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("kerberoast: %d hashes", len(r.Hashes))
		}
	case pb.TaskType_TASK_ASREPROAST:
		r := &pb.ASREPRoastResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("asreproast: %d hashes", len(r.Hashes))
		}
	case pb.TaskType_TASK_CREDS_DUMP:
		r := &pb.CredDumpResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("creds_dump %s: %d credentials", r.Method, len(r.Credentials))
		}
	case pb.TaskType_TASK_LATERAL_MOVE:
		r := &pb.LateralMoveResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("lateral %s -> %s success=%v output=%s", r.Method, r.Target, r.Success, truncate(r.Output, 500))
		}
	case pb.TaskType_TASK_PERSIST:
		r := &pb.PersistResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("persist %s success=%v %s", r.Method, r.Success, r.Details)
		}
	case pb.TaskType_TASK_PRIVESC:
		r := &pb.PrivescResult{}
		if proto.Unmarshal(result.Data, r) == nil {
			return fmt.Sprintf("privesc %s success=%v integrity=%s pid=%d", r.Method, r.Success, r.NewIntegrity, r.NewPid)
		}
	}

	return fmt.Sprintf("OK data=%d bytes", len(result.Data))
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