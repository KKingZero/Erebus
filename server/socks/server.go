package socks

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// Server implements a SOCKS5 proxy server on the teamserver side.
// Operator tools connect to this proxy, and traffic is tunneled through
// the implant's beacon channel.
type Server struct {
	mu       sync.Mutex
	listener net.Listener
	running  bool
	port     uint32
	conns    map[uint32]net.Conn
	nextID   uint32
}

// NewServer creates a new SOCKS server.
func NewServer() *Server {
	return &Server{
		conns: make(map[uint32]net.Conn),
	}
}

// Start starts the SOCKS5 server on the specified port.
func (s *Server) Start(port uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("SOCKS server already running on port %d", s.port)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.listener = ln
	s.port = port
	s.running = true

	go s.acceptLoop()

	log.Printf("[socks-server] started on %s", addr)
	return nil
}

// Stop stops the SOCKS5 server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all active connections
	for id, conn := range s.conns {
		conn.Close()
		delete(s.conns, id)
	}

	log.Printf("[socks-server] stopped")
	return nil
}

// IsRunning returns whether the server is currently running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return
			}
			log.Printf("[socks-server] accept error: %v", err)
			continue
		}

		s.mu.Lock()
		s.nextID++
		connID := s.nextID
		s.conns[connID] = conn
		s.mu.Unlock()

		go s.handleConn(connID, conn)
	}
}

func (s *Server) handleConn(id uint32, conn net.Conn) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, id)
		s.mu.Unlock()
	}()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth required
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[5+domainLen+1])
		target = fmt.Sprintf("%s:%d", domain, port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// In a full implementation, this would tunnel the connection through
	// the implant's beacon protocol. For now, connect directly.
	remote, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, remote)
	}()
	wg.Wait()
}
