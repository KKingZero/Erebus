//go:build !windows

package lateral

import (
	"context"

	"github.com/hirochachacha/go-smb2"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func psexecCleanup(_ context.Context, _ *pb.LateralMoveConfig, _ *smb2.Share, _, _ string) {}