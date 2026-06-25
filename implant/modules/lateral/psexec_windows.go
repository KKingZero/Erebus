//go:build windows

package lateral

import (
	"context"

	"github.com/hirochachacha/go-smb2"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func psexecCleanup(ctx context.Context, cfg *pb.LateralMoveConfig, share *smb2.Share, serviceName, svcPath string) {
	_ = wmiDeleteService(ctx, cfg, serviceName)
	_ = share.Remove(svcPath)
}