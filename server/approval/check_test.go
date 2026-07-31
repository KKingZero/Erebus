package approval

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func TestCheckTaskApproval(t *testing.T) {
	g := NewGate(nil)

	if need := CheckTaskApproval(g, pb.TaskType_TASK_PROCESS_LIST, nil); need.Needed {
		t.Fatal("process_list should not need approval")
	}
	if need := CheckTaskApproval(g, pb.TaskType_TASK_SHELL, nil); !need.Needed {
		t.Fatal("shell should need approval")
	}

	data, _ := proto.Marshal(&pb.ModuleTask{ModuleName: "cloud"})
	need := CheckTaskApproval(g, pb.TaskType_TASK_MODULE, data)
	if !need.Needed || need.ModuleName != "cloud" {
		t.Fatalf("cloud module: %+v", need)
	}

	if need := CheckTaskApproval(nil, pb.TaskType_TASK_SHELL, nil); need.Needed {
		t.Fatal("nil gate → no approval required")
	}
}
