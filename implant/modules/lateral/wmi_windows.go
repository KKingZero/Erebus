//go:build windows

package lateral

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func moveWMI(ctx context.Context, cfg *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target required")
	}
	if cfg.Command == "" {
		return nil, fmt.Errorf("command required")
	}

	output, err := wmiRunCommand(ctx, cfg)
	if err != nil {
		return &pb.LateralMoveResult{
			Method:  "wmi",
			Target:  cfg.Target,
			Success: false,
			Output:  err.Error(),
		}, nil
	}

	return &pb.LateralMoveResult{
		Method:  "wmi",
		Target:  cfg.Target,
		Success: true,
		Output:  output,
	}, nil
}

func moveDCOM(ctx context.Context, cfg *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	return nil, fmt.Errorf("DCOM execution not yet implemented - use wmi method instead")
}