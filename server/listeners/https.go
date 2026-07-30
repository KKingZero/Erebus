package listeners

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
	"github.com/KKingZero/erebus-exploit-framwork/server/tasks"
	"google.golang.org/protobuf/proto"
)

// BeaconHandler processes Register and Beacon messages from implants.
type BeaconHandler struct {
	Sessions      *sessions.Manager
	Dispatcher    *tasks.Dispatcher
	Secret        []byte         // Legacy fleet-wide PSK (fallback when ResolveSecret is nil)
	ResolveSecret SecretResolver // Per-implant secret lookup (preferred)
	Socks         SocksBridge    // optional reverse SOCKS hub
	OnEvent       tasks.EventCallback
	ReplayCache   *zcrypto.ReplayCache
}

// HTTPSListener is an HTTPS listener for implant callbacks.
type HTTPSListener struct {
	id             string
	name           string
	host           string
	port           uint32
	server         *http.Server
	handler        *BeaconHandler
	tlsCert        tls.Certificate
	startedAt      time.Time
	active         bool
	reverseProxy   bool
	trustedProxies map[string]bool
	mu             sync.Mutex
}

func NewHTTPSListener(config *pb.ListenerConfig, handler *BeaconHandler, ca *zcrypto.CertificateAuthority) (*HTTPSListener, error) {
	hosts := []string{config.Host}
	if config.Host == "" || config.Host == "0.0.0.0" {
		hosts = []string{"localhost", "127.0.0.1"}
	}

	// M14: Do NOT include CDN domain in certificate SANs — it leaks domain
	// fronting intent. The CDN domain is only used for Host header / TLS SNI
	// on the implant side, not in the server certificate.

	tlsCert, _, err := ca.GenerateServerCert(hosts)
	if err != nil {
		return nil, fmt.Errorf("generate server cert: %w", err)
	}

	id := config.Id
	if id == "" {
		var err2 error
		id, err2 = zcrypto.RandomID(8)
		if err2 != nil {
			return nil, fmt.Errorf("generate listener ID: %w", err2)
		}
	}

	// Build trusted proxy set
	trustedProxies := make(map[string]bool)
	for _, p := range config.TrustedProxies {
		trustedProxies[p] = true
	}

	return &HTTPSListener{
		id:             id,
		name:           config.Name,
		host:           config.Host,
		port:           config.Port,
		handler:        handler,
		tlsCert:        tlsCert,
		reverseProxy:   config.ReverseProxy,
		trustedProxies: trustedProxies,
	}, nil
}

func (l *HTTPSListener) ID() string                    { return l.id }
func (l *HTTPSListener) Name() string                  { return l.name }
func (l *HTTPSListener) Protocol() pb.ListenerProtocol { return pb.ListenerProtocol_LISTENER_HTTPS }
func (l *HTTPSListener) Address() string               { return fmt.Sprintf("%s:%d", l.host, l.port) }

func (l *HTTPSListener) Status() *pb.ListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &pb.ListenerStatus{
		Id:        l.id,
		Name:      l.name,
		Protocol:  pb.ListenerProtocol_LISTENER_HTTPS,
		Address:   l.Address(),
		Active:    l.active,
		StartedAt: l.startedAt.Unix(),
	}
}

func (l *HTTPSListener) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", l.handleRegister)
	mux.HandleFunc("/beacon", l.handleBeacon)
	// Catch-all returns 404 for anything else (no fingerprinting)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	l.server = &http.Server{
		Addr:    l.Address(),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{l.tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	ln, err := net.Listen("tcp", l.Address())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	tlsLn := tls.NewListener(ln, l.server.TLSConfig)

	l.mu.Lock()
	l.active = true
	l.startedAt = time.Now()
	l.mu.Unlock()

	go func() {
		log.Printf("[https] listener started on %s", l.Address())
		if err := l.server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[https] serve error: %v", err)
		}
		l.mu.Lock()
		l.active = false
		l.mu.Unlock()
	}()

	return nil
}

func (l *HTTPSListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server == nil || !l.active {
		return nil
	}
	l.active = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.server.Shutdown(ctx)
}

// resolveRemoteAddr extracts the real client IP when behind a reverse proxy.
// Only trusts X-Forwarded-For if reverse proxy mode is enabled and the direct
// connection comes from a trusted proxy address.
func (l *HTTPSListener) resolveRemoteAddr(r *http.Request) string {
	if !l.reverseProxy {
		return r.RemoteAddr
	}

	// C3: If reverseProxy is enabled but no trusted proxies configured,
	// ignore X-Forwarded-For entirely to prevent IP spoofing.
	if len(l.trustedProxies) == 0 {
		return r.RemoteAddr
	}

	// Validate the direct connection is from a trusted proxy
	directIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !l.trustedProxies[directIP] {
		return r.RemoteAddr
	}

	// Use the rightmost untrusted IP from X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return r.RemoteAddr
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		if len(l.trustedProxies) > 0 && l.trustedProxies[ip] {
			continue
		}
		return ip
	}
	return r.RemoteAddr
}

func (l *HTTPSListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	reg := &pb.Register{}
	if err := proto.Unmarshal(body, reg); err != nil {
		// Silent drop — no fingerprinting
		http.NotFound(w, r)
		return
	}

	resp, err := HandleRegister(l.handler, reg, "https", l.resolveRemoteAddr(r))
	if err != nil {
		if err != ErrBeaconAuth {
			log.Printf("[https] register error: %v", err)
		}
		http.NotFound(w, r)
		return
	}

	data, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (l *HTTPSListener) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	beacon := &pb.Beacon{}
	if err := proto.Unmarshal(body, beacon); err != nil {
		http.NotFound(w, r)
		return
	}

	resp, err := HandleBeacon(l.handler, beacon)
	if err != nil {
		if err != ErrBeaconAuth {
			log.Printf("[https] beacon error: %v", err)
		}
		http.NotFound(w, r)
		return
	}

	data, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
