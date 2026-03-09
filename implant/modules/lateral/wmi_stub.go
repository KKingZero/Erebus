//go:build !windows

package lateral

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func moveWMI(_ context.Context, _ *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	return nil, fmt.Errorf("WMI lateral movement not supported on this platform")
}

func moveDCOM(_ context.Context, _ *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	return nil, fmt.Errorf("DCOM lateral movement not supported on this platform")
}
