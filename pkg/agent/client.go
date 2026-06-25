package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client wraps the ErebusC2 gRPC API for the AI agent.
type Client struct {
	pb.ErebusC2Client
	conn *grpc.ClientConn

	eventMu sync.Mutex
	events  []*pb.Event
	eventCh chan *pb.Event
	stopSub context.CancelFunc
}

// Connect dials the teamserver with mTLS.
func Connect(cfg *Config) (*Client, error) {
	conn, err := dialGRPC(cfg.Server, cfg.Cert, cfg.Key, cfg.CA)
	if err != nil {
		return nil, err
	}
	return &Client{
		ErebusC2Client: pb.NewErebusC2Client(conn),
		conn:           conn,
		eventCh:        make(chan *pb.Event, 64),
	}, nil
}

func dialGRPC(addr, certFile, keyFile, caFile string) (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsConfig)
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

// Close shuts down subscriptions and the gRPC connection.
func (c *Client) Close() error {
	if c.stopSub != nil {
		c.stopSub()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// StartSubscribe begins streaming teamserver events into eventCh.
func (c *Client) StartSubscribe(ctx context.Context) error {
	subCtx, cancel := context.WithCancel(ctx)
	c.stopSub = cancel

	stream, err := c.Subscribe(subCtx, &pb.SubscribeRequest{})
	if err != nil {
		cancel()
		return fmt.Errorf("subscribe: %w", err)
	}

	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					select {
					case c.eventCh <- &pb.Event{
						Type:    pb.EventType_EVENT_LOG,
						Message: fmt.Sprintf("event stream ended: %v", err),
					}:
					default:
					}
				}
				return
			}
			c.eventMu.Lock()
			c.events = append(c.events, ev)
			if len(c.events) > 200 {
				c.events = c.events[len(c.events)-200:]
			}
			c.eventMu.Unlock()
			select {
			case c.eventCh <- ev:
			case <-subCtx.Done():
				return
			}
		}
	}()
	return nil
}

// Events returns a copy of buffered events.
func (c *Client) Events() []*pb.Event {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	out := make([]*pb.Event, len(c.events))
	copy(out, c.events)
	return out
}

// EventChannel exposes the live event stream.
func (c *Client) EventChannel() <-chan *pb.Event {
	return c.eventCh
}

// Execute waits for a task result when wait is true.
func (c *Client) Execute(ctx context.Context, sessionID string, taskType pb.TaskType, data []byte, timeoutMs int64) (*pb.TaskResult, error) {
	resp, err := c.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: sessionID,
		TaskType:  taskType,
		Data:      data,
		TimeoutMs: timeoutMs,
		Wait:      true,
	})
	if err != nil {
		return nil, err
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("task %s returned no result", resp.TaskId)
	}
	return resp.Result, nil
}