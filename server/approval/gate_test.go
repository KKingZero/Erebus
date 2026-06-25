package approval

import (
	"context"
	"testing"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func TestRequestApprovalApprove(t *testing.T) {
	g := NewGate(nil)
	done := make(chan bool, 1)
	go func() {
		approved, err := g.RequestApproval(context.Background(), "sess-1", pb.TaskType_TASK_INJECT, "inject test")
		if err != nil {
			t.Errorf("request: %v", err)
			done <- false
			return
		}
		done <- approved
	}()

	time.Sleep(50 * time.Millisecond)
	pending := g.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if err := g.Approve(pending[0].Id); err != nil {
		t.Fatal(err)
	}
	if !<-done {
		t.Fatal("expected approval")
	}
}

func TestRequestApprovalDeny(t *testing.T) {
	g := NewGate(nil)
	done := make(chan bool, 1)
	go func() {
		approved, err := g.RequestApproval(context.Background(), "sess-1", pb.TaskType_TASK_CREDS_DUMP, "creds dump")
		if err != nil {
			t.Errorf("request: %v", err)
			done <- true
			return
		}
		done <- approved
	}()

	time.Sleep(50 * time.Millisecond)
	pending := g.ListPending()
	if err := g.Deny(pending[0].Id); err != nil {
		t.Fatal(err)
	}
	if <-done {
		t.Fatal("expected denial")
	}
}

func TestApproveDuplicateRejected(t *testing.T) {
	g := NewGate(nil)
	done := make(chan struct{})
	go func() {
		_, _ = g.RequestApproval(context.Background(), "sess-1", pb.TaskType_TASK_INJECT, "inject")
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	pending := g.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	id := pending[0].Id
	if err := g.Approve(id); err != nil {
		t.Fatal(err)
	}
	if err := g.Approve(id); err == nil {
		t.Fatal("expected error on duplicate approve")
	}
	<-done
}

func TestRequestApprovalTimeoutEvent(t *testing.T) {
	var gotEvent *pb.Event
	g := NewGate(func(e *pb.Event) { gotEvent = e })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := g.RequestApproval(ctx, "sess-1", pb.TaskType_TASK_CREDS_DUMP, "creds dump")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if gotEvent == nil || gotEvent.Type != pb.EventType_EVENT_LOG {
		t.Fatalf("expected timeout log event, got %+v", gotEvent)
	}
}