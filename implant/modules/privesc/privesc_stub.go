//go:build !windows

package privesc

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func privescToken(_ context.Context, _ *pb.PrivescConfig) (*pb.PrivescResult, error) {
	return nil, fmt.Errorf("token privilege escalation not supported on this platform")
}

func privescUACFodhelper(_ context.Context, _ *pb.PrivescConfig) (*pb.PrivescResult, error) {
	return nil, fmt.Errorf("UAC bypass not supported on this platform")
}

func privescUACEventvwr(_ context.Context, _ *pb.PrivescConfig) (*pb.PrivescResult, error) {
	return nil, fmt.Errorf("UAC bypass not supported on this platform")
}
