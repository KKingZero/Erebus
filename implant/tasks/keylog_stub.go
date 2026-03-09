//go:build !windows

package tasks

import "fmt"

func startKeylogger(_ bool) error {
	return fmt.Errorf("keylogger not supported on this platform")
}

func stopKeylogger() {}
