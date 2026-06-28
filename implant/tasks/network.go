package tasks

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

func executeNetIfconfig(_ context.Context, _ []byte) ([]byte, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var netIfaces []*pb.NetInterface
	for _, iface := range ifaces {
		ni := &pb.NetInterface{
			Name: iface.Name,
			Mac:  iface.HardwareAddr.String(),
			Mtu:  uint32(iface.MTU),
			Up:   iface.Flags&net.FlagUp != 0,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addresses = append(ni.Addresses, addr.String())
			}
		}

		netIfaces = append(netIfaces, ni)
	}

	result := &pb.NetIfconfigResult{Interfaces: netIfaces}
	return proto.Marshal(result)
}

func executeNetPortscan(ctx context.Context, data []byte) ([]byte, error) {
	task := &pb.NetPortscanTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal portscan task: %w", err)
	}

	if task.Target == "" {
		return nil, fmt.Errorf("target required")
	}
	if len(task.Ports) == 0 {
		return nil, fmt.Errorf("at least one port required")
	}

	timeout := time.Duration(task.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	threads := int(task.Threads)
	if threads <= 0 {
		threads = 10
	}
	if threads > 100 {
		threads = 100
	}

	var (
		results []*pb.PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, port := range task.Ports {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p uint32) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(task.Target, fmt.Sprintf("%d", p))
			pr := &pb.PortResult{
				Host: task.Target,
				Port: p,
			}

			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				pr.Open = true
				// Try banner grab (100ms read timeout)
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				if n > 0 {
					pr.Service = string(buf[:n])
				}
				conn.Close()
			}

			mu.Lock()
			results = append(results, pr)
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	result := &pb.NetPortscanResult{Ports: results}
	result.NextSuggestedActions = suggestions.ForPortscan(result)
	return proto.Marshal(result)
}
