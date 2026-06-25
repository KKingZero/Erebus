package approval

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func TestRequiresModuleApproval(t *testing.T) {
	p := DefaultPolicy()
	if !p.RequiresModuleApproval("creds_dump") {
		t.Fatal("creds_dump should require approval")
	}
	if p.RequiresModuleApproval("shell") {
		t.Fatal("shell should not require approval")
	}
}

func TestModuleNameFromTaskData(t *testing.T) {
	data, err := proto.Marshal(&pb.ModuleTask{ModuleName: "persist", Config: nil})
	if err != nil {
		t.Fatal(err)
	}
	if got := ModuleNameFromTaskData(data); got != "persist" {
		t.Fatalf("got %q want persist", got)
	}
}

func TestRequiresApprovalDirectTasks(t *testing.T) {
	p := DefaultPolicy()
	if !p.RequiresApproval(pb.TaskType_TASK_INJECT) {
		t.Fatal("inject should require approval")
	}
	if p.RequiresApproval(pb.TaskType_TASK_SHELL) {
		t.Fatal("shell should not require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_KERBEROAST) {
		t.Fatal("kerberoast should require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_LDAP_ENUM) {
		t.Fatal("ldap_enum should require approval")
	}
}