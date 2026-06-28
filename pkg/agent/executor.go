package agent

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// Executor runs tool calls against the C2 client.
type Executor struct {
	Client *Client
	OnApproval func(approvalID, risk, description string)
}

// RunTool executes a named tool with JSON arguments.
func (e *Executor) RunTool(ctx context.Context, name, argsJSON string, defaultSession string) (string, error) {
	if name == "mission_complete" {
		args, err := ParseToolArgs(argsJSON)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("MISSION_COMPLETE: %s", str(args, "summary")), nil
	}

	tool, ok := LookupTool(name)
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}

	args, err := ParseToolArgs(argsJSON)
	if err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}

	switch name {
	case "list_sessions":
		resp, err := e.Client.ListSessions(ctx, &pb.ListSessionsRequest{})
		if err != nil {
			return "", err
		}
		return FormatSessions(resp.Sessions), nil

	case "get_session":
		sid := str(args, "session_id")
		if sid == "" {
			return "", fmt.Errorf("session_id required")
		}
		resp, err := e.Client.GetSession(ctx, &pb.GetSessionRequest{SessionId: sid})
		if err != nil {
			return "", err
		}
		s := resp.Session
		return fmt.Sprintf("%s: %s@%s %s/%s alive=%v", s.SessionId, s.Username, s.Hostname, s.Os, s.Arch, s.Alive), nil

	case "list_loot":
		resp, err := e.Client.ListLoot(ctx, &pb.ListLootRequest{SessionId: str(args, "session_id")})
		if err != nil {
			return "", err
		}
		if len(resp.Items) == 0 {
			return "no loot", nil
		}
		var b strings.Builder
		for _, item := range resp.Items {
			fmt.Fprintf(&b, "- %s type=%s source=%s bytes=%d\n", item.Id, item.Type, item.Source, len(item.Data))
		}
		return b.String(), nil
	}

	sessionID := str(args, "session_id")
	if sessionID == "" {
		sessionID = defaultSession
	}
	if sessionID == "" {
		return "", fmt.Errorf("session_id required for %s", name)
	}

	if tool.BuildData == nil {
		return "", fmt.Errorf("tool %s has no task builder", name)
	}

	data, err := tool.BuildData(args)
	if err != nil {
		return "", err
	}

	done := make(chan struct{})
	if RequiresApproval(tool) {
		e.watchApproval(ctx, sessionID, done)
	}
	result, err := e.Client.Execute(ctx, sessionID, tool.TaskType, data, 120000)
	close(done)
	if err != nil {
		return "", err
	}
	return InterpretResult(tool.TaskType, result), nil
}

func (e *Executor) watchApproval(ctx context.Context, sessionID string, done <-chan struct{}) {
	if e.OnApproval == nil {
		return
	}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case ev := <-e.Client.EventChannel():
				if ev.Type != pb.EventType_EVENT_APPROVAL_REQUIRED {
					continue
				}
				if ev.SessionId != "" && ev.SessionId != sessionID {
					continue
				}
				pending, err := e.Client.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
				if err != nil || len(pending.Approvals) == 0 {
					continue
				}
				for _, a := range pending.Approvals {
					if a.SessionId == sessionID {
						e.OnApproval(a.Id, a.RiskLevel, a.TaskDescription)
						return
					}
				}
				last := pending.Approvals[len(pending.Approvals)-1]
				e.OnApproval(last.Id, last.RiskLevel, last.TaskDescription)
				return
			}
		}
	}()
}