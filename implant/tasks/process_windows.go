//go:build windows

package tasks

import (
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
)

func listProcesses() ([]*pb.ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snap, &entry)
	if err != nil {
		return nil, err
	}

	var procs []*pb.ProcessInfo
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, &pb.ProcessInfo{
			Pid:  entry.ProcessID,
			Ppid: entry.ParentProcessID,
			Name: name,
		})

		err = windows.Process32Next(snap, &entry)
		if err != nil {
			break
		}
	}
	return procs, nil
}
