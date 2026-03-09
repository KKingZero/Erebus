//go:build !windows

package persist

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func persistSchTask(_ context.Context, _ *pb.PersistConfig) (*pb.PersistResult, error) {
	return nil, fmt.Errorf("scheduled task persistence not supported on this platform")
}

func persistRegistry(_ context.Context, _ *pb.PersistConfig) (*pb.PersistResult, error) {
	return nil, fmt.Errorf("registry persistence not supported on this platform")
}

func persistService(_ context.Context, _ *pb.PersistConfig) (*pb.PersistResult, error) {
	return nil, fmt.Errorf("service persistence not supported on this platform")
}
