package tasks

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func executeInject(ctx context.Context, data []byte) ([]byte, error) {
	task := &pb.InjectTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal inject task: %w", err)
	}

	result, err := performInjection(ctx, task)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}
