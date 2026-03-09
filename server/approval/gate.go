package approval

import (
	"fmt"
	"sync"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

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

// RequestApproval queues a task for approval and blocks until approved/denied.
func (g *Gate) RequestApproval(sessionID string, taskType pb.TaskType, description string) (bool, error) {
	id, err := crypto.RandomID(8)
	if err != nil {
		return false, err
	}

	req := &pb.ApprovalRequest{
		Id:              id,
		SessionId:       sessionID,
		TaskDescription: description,
		TaskType:        taskType,
		RiskLevel:       g.policy.RiskLevel(taskType),
		RequestedAt:     time.Now().Unix(),
	}

	resultCh := make(chan bool, 1)

	g.mu.Lock()
	g.pending[id] = &PendingApproval{
		Request:  req,
		ResultCh: resultCh,
	}
	g.mu.Unlock()

	// Emit event
	if g.onEvent != nil {
		g.onEvent(&pb.Event{
			Type:      pb.EventType_EVENT_APPROVAL_REQUIRED,
			Timestamp: time.Now().Unix(),
			SessionId: sessionID,
			Message:   fmt.Sprintf("[%s] %s requires approval: %s", req.RiskLevel, taskType, description),
		})
	}

	// Wait for operator decision
	approved := <-resultCh

	g.mu.Lock()
	delete(g.pending, id)
	g.mu.Unlock()

	return approved, nil
}

// Approve approves a pending request.
func (g *Gate) Approve(approvalID string) error {
	g.mu.RLock()
	pa, ok := g.pending[approvalID]
	g.mu.RUnlock()

	if !ok {
		return fmt.Errorf("approval request not found: %s", approvalID)
	}

	pa.ResultCh <- true
	return nil
}

// Deny denies a pending request.
func (g *Gate) Deny(approvalID string) error {
	g.mu.RLock()
	pa, ok := g.pending[approvalID]
	g.mu.RUnlock()

	if !ok {
		return fmt.Errorf("approval request not found: %s", approvalID)
	}

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
