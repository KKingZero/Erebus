//go:build !windows

package tasks

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func performInjection(_ context.Context, _ *pb.InjectTask) (*pb.InjectResult, error) {
	return nil, fmt.Errorf("process injection not supported on this platform")
}
