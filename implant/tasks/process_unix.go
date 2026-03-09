//go:build !windows

package tasks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func listProcesses() ([]*pb.ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []*pb.ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		info := &pb.ProcessInfo{Pid: uint32(pid)}

		// Read /proc/[pid]/stat for name, ppid
		statData, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err == nil {
			parseProcStat(string(statData), info)
		}

		// Read /proc/[pid]/cmdline
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && len(cmdline) > 0 {
			// Replace null bytes with spaces
			info.CommandLine = strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " ")
		}

		// Read /proc/[pid]/status for user info and memory
		statusData, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err == nil {
			parseProcStatus(string(statusData), info)
		}

		procs = append(procs, info)
	}
	return procs, nil
}

func parseProcStat(stat string, info *pb.ProcessInfo) {
	// Format: pid (name) state ppid ...
	start := strings.IndexByte(stat, '(')
	end := strings.LastIndexByte(stat, ')')
	if start < 0 || end < 0 || end <= start {
		return
	}
	info.Name = stat[start+1 : end]

	// Fields after ")"
	fields := strings.Fields(stat[end+2:])
	if len(fields) >= 2 {
		ppid, _ := strconv.ParseUint(fields[1], 10, 32)
		info.Ppid = uint32(ppid)
	}
}

func parseProcStatus(status string, info *pb.ProcessInfo) {
	for _, line := range strings.Split(status, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Uid":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				info.User = fields[0]
			}
		case "VmRSS":
			// Value like "12345 kB"
			fields := strings.Fields(val)
			if len(fields) > 0 {
				kb, _ := strconv.ParseUint(fields[0], 10, 64)
				info.MemoryBytes = kb * 1024
			}
		}
	}
}
