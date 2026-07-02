package approval

import (
	"context"
	"testing"
	"time"
)

func TestRequestModuleApprovalRiskLevel(t *testing.T) {
	g := NewGate(nil)
	done := make(chan string, 1)
	go func() {
		_, _ = g.RequestModuleApproval(context.Background(), "sess-1", "creds_dump", "dump creds", "requester-a")
		done <- ""
	}()

	time.Sleep(50 * time.Millisecond)
	pending := g.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].RiskLevel != "critical" {
		t.Fatalf("expected critical risk, got %q", pending[0].RiskLevel)
	}
	_ = g.Approve(pending[0].Id, "approver-b")
	<-done
}