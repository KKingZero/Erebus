package transport

import (
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// Transport is the interface for implant communication channels.
type Transport interface {
	Register(reg *pb.Register) (*pb.RegisterResponse, error)
	Beacon(beacon *pb.Beacon) (*pb.BeaconResponse, error)
}
