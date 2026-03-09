//go:build !windows

package tasks

import (
	"context"
	"fmt"
)

func executeScreenshot(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("screenshot not supported on this platform")
}
