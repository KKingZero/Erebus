package tasks

import (
	"context"
	"io"
	"os/exec"
	"runtime"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

const maxOutputBytes = 10 << 20 // 10 MB

// limitWriter wraps a writer and stops after max bytes.
type limitWriter struct {
	w       io.Writer
	n       int64
	max     int64
	overrun bool
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.max - lw.n
	if remaining <= 0 {
		lw.overrun = true
		return len(p), nil // discard silently
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		lw.overrun = true
	}
	n, err := lw.w.Write(p)
	lw.n += int64(n)
	return n, err
}

// RunShell executes a shell command and returns structured output.
func RunShell(ctx context.Context, command string, args []string) *pb.ShellResult {
	var cmd *exec.Cmd

	if len(args) > 0 {
		cmd = exec.CommandContext(ctx, command, args...)
	} else {
		// Use platform shell
		switch runtime.GOOS {
		case "windows":
			cmd = exec.CommandContext(ctx, "cmd.exe", "/C", command)
		default:
			cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
		}
	}

	var stdoutBuf, stderrBuf []byte
	stdoutPipe := &limitWriter{w: &sliceWriter{buf: &stdoutBuf}, max: maxOutputBytes}
	stderrPipe := &limitWriter{w: &sliceWriter{buf: &stderrBuf}, max: maxOutputBytes}
	cmd.Stdout = stdoutPipe
	cmd.Stderr = stderrPipe

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	stdout := string(stdoutBuf)
	stderr := string(stderrBuf)
	if stdoutPipe.overrun {
		stdout += "\n[output truncated at 10MB]"
	}
	if stderrPipe.overrun {
		stderr += "\n[output truncated at 10MB]"
	}

	return &pb.ShellResult{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: int32(exitCode),
	}
}

// sliceWriter appends to a byte slice.
type sliceWriter struct {
	buf *[]byte
}

func (sw *sliceWriter) Write(p []byte) (int, error) {
	*sw.buf = append(*sw.buf, p...)
	return len(p), nil
}
