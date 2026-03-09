package tasks

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func executePELoad(ctx context.Context, data []byte) ([]byte, error) {
	task := &pb.PELoadTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal PE load task: %w", err)
	}

	result, err := performPELoad(ctx, task)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}
