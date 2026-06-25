package tasks

import (
	"context"
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
)

type stubModule struct {
	name string
}

func (m *stubModule) Name() string        { return m.name }
func (m *stubModule) Description() string { return "stub" }
func (m *stubModule) Execute(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("ok"), nil
}

func TestExecuteTypedModuleTaskTypes(t *testing.T) {
	reg := plugin.NewRegistry()
	for _, name := range []string{
		"creds_dump", "ldap_enum", "kerberoast", "asreproast",
		"lateral_move", "persist", "privesc",
	} {
		reg.Register(&stubModule{name: name})
	}

	e := NewExecutor(reg)
	types := []pb.TaskType{
		pb.TaskType_TASK_CREDS_DUMP,
		pb.TaskType_TASK_LDAP_ENUM,
		pb.TaskType_TASK_KERBEROAST,
		pb.TaskType_TASK_ASREPROAST,
		pb.TaskType_TASK_LATERAL_MOVE,
		pb.TaskType_TASK_PERSIST,
		pb.TaskType_TASK_PRIVESC,
	}

	for _, tt := range types {
		result := e.Execute(&pb.Task{TaskId: "t1", TaskType: tt, Data: []byte{}})
		if !result.Success {
			t.Fatalf("%s failed: %s", tt, result.Error)
		}
		if string(result.Data) != "ok" {
			t.Fatalf("%s unexpected data: %q", tt, result.Data)
		}
	}
}