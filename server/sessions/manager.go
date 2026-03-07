package sessions

import (
	"fmt"
	"sync"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
)

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by session_id
	byImplant map[string]string  // implant_id -> session_id
	store    *db.Store
}

func NewManager(store *db.Store) *Manager {
	return &Manager{
		sessions:  make(map[string]*Session),
		byImplant: make(map[string]string),
		store:     store,
	}
}

func (m *Manager) Register(sess *Session) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if implant already has a session
	if existingID, ok := m.byImplant[sess.ImplantID]; ok {
		if existing, ok2 := m.sessions[existingID]; ok2 && existing.IsAlive() {
			existing.UpdateCheckin()
			return existingID, nil
		}
	}

	sessionID, err := crypto.RandomID(16)
	if err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}

	sess.SessionID = sessionID
	m.sessions[sessionID] = sess
	m.byImplant[sess.ImplantID] = sessionID

	if m.store != nil {
		if err := m.store.CreateSession(&db.SessionRow{
			SessionID:      sess.SessionID,
			ImplantID:      sess.ImplantID,
			Hostname:       sess.Hostname,
			Username:       sess.Username,
			OS:             sess.OS,
			Arch:           sess.Arch,
			PID:            sess.PID,
			IntegrityLevel: sess.IntegrityLevel,
			Transport:      sess.Transport,
			RemoteAddr:     sess.RemoteAddr,
			RegisteredAt:   sess.RegisteredAt,
			LastCheckin:     sess.LastCheckin,
			Alive:          true,
		}); err != nil {
			return "", fmt.Errorf("persist session: %w", err)
		}
	}

	return sessionID, nil
}

func (m *Manager) Get(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

func (m *Manager) GetByImplant(implantID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sid, ok := m.byImplant[implantID]
	if !ok {
		return nil, false
	}
	s, ok := m.sessions[sid]
	return s, ok
}

func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

func (m *Manager) Kill(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	s.Kill()
	if m.store != nil {
		return m.store.KillSession(sessionID)
	}
	return nil
}

func (m *Manager) UpdateCheckin(sessionID string) {
	m.mu.RLock()
	s, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return
	}
	s.UpdateCheckin()
	if m.store != nil {
		m.store.UpdateSessionCheckin(sessionID)
	}
}

// Reaper marks sessions as dead if they haven't checked in within timeout.
func (m *Manager) Reaper(timeout time.Duration) {
	// Collect stale sessions under read lock
	m.mu.RLock()
	var stale []*Session
	for _, s := range m.sessions {
		s.mu.RLock()
		if s.Alive && time.Since(s.LastCheckin) > timeout {
			stale = append(stale, s)
		}
		s.mu.RUnlock()
	}
	m.mu.RUnlock()

	// Kill outside lock to avoid holding manager lock during DB writes
	for _, s := range stale {
		s.Kill()
		if m.store != nil {
			m.store.KillSession(s.SessionID)
		}
	}
}
