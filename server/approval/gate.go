package approval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

const defaultApprovalTimeout = 30 * time.Minute

// Gate manages pending approval requests for high-risk operations.
type Gate struct {
	mu       sync.RWMutex
	pending  map[string]*PendingApproval
	onEvent  func(event *pb.Event)
	policy   *Policy
}

// PendingApproval tracks a queued approval request.
type PendingApproval struct {
	Request  *pb.ApprovalRequest
	ResultCh chan bool
}

// NewGate creates a new approval gate with default policy.
func NewGate(onEvent func(event *pb.Event)) *Gate {
	return &Gate{
		pending: make(map[string]*PendingApproval),
		onEvent: onEvent,
		policy:  DefaultPolicy(),
	}
}

// RequiresApproval checks if a task type needs operator approval.
func (g *Gate) RequiresApproval(taskType pb.TaskType) bool {
	return g.policy.RequiresApproval(taskType)
}

// RequiresModuleApproval checks if a TASK_MODULE target needs operator approval.
func (g *Gate) RequiresModuleApproval(moduleName string) bool {
	return g.policy.RequiresModuleApproval(moduleName)
}

// RequestApproval queues a task for approval and blocks until approved/denied or ctx expires.
func (g *Gate) RequestApproval(ctx context.Context, sessionID string, taskType pb.TaskType, description string) (bool, error) {
	return g.requestApproval(ctx, sessionID, taskType, description, g.policy.RiskLevel(taskType))
}

// RequestModuleApproval queues a high-risk module for approval with the module risk level.
func (g *Gate) RequestModuleApproval(ctx context.Context, sessionID, moduleName, description string) (bool, error) {
	return g.requestApproval(ctx, sessionID, pb.TaskType_TASK_MODULE, description, g.policy.ModuleRiskLevel(moduleName))
}

func (g *Gate) requestApproval(ctx context.Context, sessionID string, taskType pb.TaskType, description, riskLevel string) (bool, error) {
	id, err := crypto.RandomID(8)
	if err != nil {
		return false, err
	}

	req := &pb.ApprovalRequest{
		Id:              id,
		SessionId:       sessionID,
		TaskDescription: description,
		TaskType:        taskType,
		RiskLevel:       riskLevel,
		RequestedAt:     time.Now().Unix(),
	}

	resultCh := make(chan bool, 1)

	g.mu.Lock()
	g.pending[id] = &PendingApproval{
		Request:  req,
		ResultCh: resultCh,
	}
	g.mu.Unlock()

	if g.onEvent != nil {
		g.onEvent(&pb.Event{
			Type:      pb.EventType_EVENT_APPROVAL_REQUIRED,
			Timestamp: time.Now().Unix(),
			SessionId: sessionID,
			Message:   fmt.Sprintf("[%s] %s requires approval: %s", req.RiskLevel, taskType, description),
		})
	}

	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, defaultApprovalTimeout)
		defer cancel()
	}

	select {
	case approved := <-resultCh:
		return approved, nil
	case <-waitCtx.Done():
		g.mu.Lock()
		delete(g.pending, id)
		g.mu.Unlock()
		if g.onEvent != nil {
			g.onEvent(&pb.Event{
				Type:      pb.EventType_EVENT_LOG,
				Timestamp: time.Now().Unix(),
				SessionId: sessionID,
				Message:   fmt.Sprintf("approval timed out [%s] %s: %s", riskLevel, taskType, description),
			})
		}
		return false, waitCtx.Err()
	}
}

// Approve approves a pending request.
func (g *Gate) Approve(approvalID string) error {
	g.mu.Lock()
	pa, ok := g.pending[approvalID]
	if !ok {
		g.mu.Unlock()
		return fmt.Errorf("approval request not found: %s", approvalID)
	}
	delete(g.pending, approvalID)
	g.mu.Unlock()

	pa.ResultCh <- true
	return nil
}

// Deny denies a pending request.
func (g *Gate) Deny(approvalID string) error {
	g.mu.Lock()
	pa, ok := g.pending[approvalID]
	if !ok {
		g.mu.Unlock()
		return fmt.Errorf("approval request not found: %s", approvalID)
	}
	delete(g.pending, approvalID)
	g.mu.Unlock()

	pa.ResultCh <- false
	return nil
}

// ListPending returns all pending approval requests.
func (g *Gate) ListPending() []*pb.ApprovalRequest {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var requests []*pb.ApprovalRequest
	for _, pa := range g.pending {
		requests = append(requests, pa.Request)
	}
	return requests
}