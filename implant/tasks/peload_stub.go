//go:build !windows

package tasks

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func performPELoad(_ context.Context, _ *pb.PELoadTask) (*pb.PELoadResult, error) {
	return nil, fmt.Errorf("PE loading not supported on this platform")
}
