package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// ApprovalAction tells the executor how to handle a high-risk task gate.
type ApprovalAction int

const (
	// ApprovalExternal leaves the gate pending for another process to Approve/Deny.
	ApprovalExternal ApprovalAction = iota
	// ApprovalGrant submits Approve via the approver seat.
	ApprovalGrant
	// ApprovalDeny submits Deny via the approver seat.
	ApprovalDeny
)

// Executor runs tool calls against the C2 client.
type Executor struct {
	Client *Client
	// OnApproval is called when a high-risk task needs approval.
	// Return ApprovalGrant/Deny for in-process dual-control, or ApprovalExternal
	// to wait for an outside operator.
	OnApproval func(approvalID, risk, description string) (ApprovalAction, string)
	// OnLog is optional operator-visible diagnostics (approve failures, seat issues).
	OnLog func(string)
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

func (e *Executor) logf(format string, args ...any) {
	if e.OnLog == nil {
		return
	}
	e.OnLog(fmt.Sprintf(format, args...))
}

func (e *Executor) watchApproval(ctx context.Context, sessionID string, done <-chan struct{}) {
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
				target := e.findPendingForSession(ctx, sessionID)
				if target == nil {
					// Event can race ahead of the pending map; keep waiting for a match.
					continue
				}
				e.handleApproval(ctx, target)
				return
			}
		}
	}()
}

// findPendingForSession retries briefly so ListPending can catch up with the event.
func (e *Executor) findPendingForSession(ctx context.Context, sessionID string) *pb.ApprovalRequest {
	listClient := e.Client.Approver()
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(50 * time.Millisecond):
			}
		}
		pending, err := listClient.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err != nil || pending == nil || len(pending.Approvals) == 0 {
			continue
		}
		for _, a := range pending.Approvals {
			if a.SessionId == sessionID {
				return a
			}
		}
		// Never fall back to another session's pending request.
	}
	return nil
}

func (e *Executor) handleApproval(ctx context.Context, a *pb.ApprovalRequest) {
	if e.OnApproval == nil {
		return
	}
	action, reason := e.OnApproval(a.Id, a.RiskLevel, a.TaskDescription)
	switch action {
	case ApprovalGrant, ApprovalDeny:
		if !e.Client.HasApproverSeat() {
			e.logf("approval %s: no distinct approver mTLS seat — cannot Grant/Deny in-process (set approver_cert/approver_key or use external approve)", a.Id)
			return
		}
		if action == ApprovalGrant {
			if _, err := e.Client.Approver().Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err != nil {
				e.logf("approve failed for %s: %v — denying to unblock task", a.Id, err)
				// Unblock ExecuteTask so the agent does not hang until timeout.
				denyReason := fmt.Sprintf("approve RPC failed: %v", err)
				if _, derr := e.Client.Approver().Deny(ctx, &pb.DenyRequest{ApprovalId: a.Id, Reason: denyReason}); derr != nil {
					e.logf("deny-after-approve-fail also failed for %s: %v", a.Id, derr)
				}
			}
			return
		}
		if reason == "" {
			reason = "denied by operator"
		}
		if _, err := e.Client.Approver().Deny(ctx, &pb.DenyRequest{ApprovalId: a.Id, Reason: reason}); err != nil {
			e.logf("deny failed for %s: %v", a.Id, err)
		}
	case ApprovalExternal:
		// Caller only notified; external operator must approve/deny.
	}
}
