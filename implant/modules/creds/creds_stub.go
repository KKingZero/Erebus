//go:build !windows

package creds

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func dumpLSASS(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	return nil, fmt.Errorf("LSASS dumping not supported on this platform")
}

func dumpSAM(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	return nil, fmt.Errorf("SAM dumping not supported on this platform")
}

func dumpBrowser(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	return nil, fmt.Errorf("browser credential dumping not supported on this platform")
}
