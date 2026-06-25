//go:build !windows

package lateral

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func psexecStartService(_ context.Context, _ *pb.LateralMoveConfig, _, _ string) error {
	return fmt.Errorf("psexec remote service start requires windows")
}