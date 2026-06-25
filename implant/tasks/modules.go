package tasks

import (
	"context"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// taskTypeModules maps dedicated proto task types to compiled-in module names.
var taskTypeModules = map[pb.TaskType]string{
	pb.TaskType_TASK_CREDS_DUMP:   "creds_dump",
	pb.TaskType_TASK_LDAP_ENUM:    "ldap_enum",
	pb.TaskType_TASK_KERBEROAST:   "kerberoast",
	pb.TaskType_TASK_ASREPROAST:   "asreproast",
	pb.TaskType_TASK_LATERAL_MOVE: "lateral_move",
	pb.TaskType_TASK_PERSIST:      "persist",
	pb.TaskType_TASK_PRIVESC:      "privesc",
}

func (e *Executor) executeTypedModule(ctx context.Context, taskType pb.TaskType, data []byte) ([]byte, error) {
	name, ok := taskTypeModules[taskType]
	if !ok {
		return nil, errUnsupportedTaskType(taskType)
	}
	return e.Registry.Execute(ctx, name, data)
}

func errUnsupportedTaskType(taskType pb.TaskType) error {
	return &unsupportedTaskError{taskType: taskType}
}

type unsupportedTaskError struct {
	taskType pb.TaskType
}

func (e *unsupportedTaskError) Error() string {
	return "unsupported task type: " + e.taskType.String()
}