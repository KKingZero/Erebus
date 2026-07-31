package autoharvest

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"google.golang.org/protobuf/proto"
)

type fakeDispatcher struct {
	mu    sync.Mutex
	calls []pb.TaskType
}

func (f *fakeDispatcher) Dispatch(_ context.Context, _ string, taskType pb.TaskType, _ []byte, _ int64, _ bool) (string, *pb.TaskResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, taskType)
	return "task-1", nil, nil
}

func (f *fakeDispatcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeDispatcher) types() []pb.TaskType {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pb.TaskType, len(f.calls))
	copy(out, f.calls)
	return out
}

func TestLowRiskDispatchesWithoutApproval(t *testing.T) {
	gate := approval.NewGate(nil)
	disp := &fakeDispatcher{}
	h := New(&AutoHarvestConfig{Enabled: true}, disp, nil, gate)

	ht := HarvestTask{Name: "process_list", TaskType: pb.TaskType_TASK_PROCESS_LIST}
	h.dispatchNow("sess-1", ht)

	if disp.count() != 1 {
		t.Fatalf("expected 1 dispatch, got %d", disp.count())
	}
	if len(gate.ListPending()) != 0 {
		t.Fatal("low-risk must not create pending approvals")
	}
}

func TestHighRiskShellRequiresApproval(t *testing.T) {
	gate := approval.NewGate(nil)
	disp := &fakeDispatcher{}
	h := New(&AutoHarvestConfig{Enabled: true}, disp, nil, gate)

	shellData, _ := proto.Marshal(&pb.ShellTask{Command: "id"})
	ht := HarvestTask{Name: "whoami", TaskType: pb.TaskType_TASK_SHELL, Data: shellData}

	done := make(chan struct{})
	go func() {
		need := approval.CheckTaskApproval(gate, ht.TaskType, ht.Data)
		if !need.Needed {
			t.Error("shell should need approval")
		}
		h.dispatchWithApproval("sess-1", ht, need)
		close(done)
	}()

	// Wait for pending approval
	var pending []*pb.ApprovalRequest
	for i := 0; i < 50; i++ {
		pending = gate.ListPending()
		if len(pending) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending approval, got %d", len(pending))
	}
	if disp.count() != 0 {
		t.Fatal("must not dispatch before approval")
	}

	if err := gate.Approve(pending[0].Id, "approver-b"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for approved dispatch")
	}
	if disp.count() != 1 {
		t.Fatalf("expected dispatch after approve, got %d", disp.count())
	}
	if disp.types()[0] != pb.TaskType_TASK_SHELL {
		t.Fatalf("dispatched %v", disp.types())
	}
}

func TestHighRiskCloudModuleRequiresApproval(t *testing.T) {
	gate := approval.NewGate(nil)
	need := approval.CheckTaskApproval(gate, pb.TaskType_TASK_MODULE, mustMod("cloud"))
	if !need.Needed || need.ModuleName != "cloud" {
		t.Fatalf("cloud module should need approval: %+v", need)
	}
	need = approval.CheckTaskApproval(gate, pb.TaskType_TASK_NET_IFCONFIG, nil)
	if need.Needed {
		t.Fatal("net_ifconfig should be low-risk")
	}
}

func TestHighRiskDeniedDoesNotDispatch(t *testing.T) {
	gate := approval.NewGate(nil)
	disp := &fakeDispatcher{}
	h := New(&AutoHarvestConfig{Enabled: true}, disp, nil, gate)

	ht := HarvestTask{Name: "whoami", TaskType: pb.TaskType_TASK_SHELL, Data: nil}
	done := make(chan struct{})
	go func() {
		need := approval.CheckTaskApproval(gate, ht.TaskType, ht.Data)
		h.dispatchWithApproval("sess-1", ht, need)
		close(done)
	}()

	var pending []*pb.ApprovalRequest
	for i := 0; i < 50; i++ {
		pending = gate.ListPending()
		if len(pending) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatal("expected pending")
	}
	if err := gate.Deny(pending[0].Id, "denier-b", "no"); err != nil {
		t.Fatal(err)
	}
	<-done
	if disp.count() != 0 {
		t.Fatal("denied task must not dispatch")
	}
}

func mustMod(name string) []byte {
	b, err := proto.Marshal(&pb.ModuleTask{ModuleName: name})
	if err != nil {
		panic(err)
	}
	return b
}
