//go:build !windows

package cloud

import (
	"context"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func harvestAADConnect(_ context.Context) *pb.CloudHarvestResult {
	return nil
}
