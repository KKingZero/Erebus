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

// RecoverSessions loads alive sessions from the database into memory.
func (m *Manager) RecoverSessions() error {
	if m.store == nil {
		return nil
	}

	rows, err := m.store.ListSessions()
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var recovered int
	for _, row := range rows {
		if !row.Alive {
			continue
		}
		sess := &Session{
			SessionID:      row.SessionID,
			ImplantID:      row.ImplantID,
			Hostname:       row.Hostname,
			Username:       row.Username,
			OS:             row.OS,
			Arch:           row.Arch,
			PID:            row.PID,
			IntegrityLevel: row.IntegrityLevel,
			Transport:      row.Transport,
			RemoteAddr:     row.RemoteAddr,
			RegisteredAt:   row.RegisteredAt,
			LastCheckin:     row.LastCheckin,
			Alive:          true,
		}
		if row.SessionKey != nil {
			sess.SessionKey = row.SessionKey
		}
		m.sessions[row.SessionID] = sess
		m.byImplant[row.ImplantID] = row.SessionID
		recovered++
	}

	if recovered > 0 {
		fmt.Printf("[sessions] recovered %d sessions from database\n", recovered)
	}
	return nil
}

// RegisterOrReconnect creates a new session or rotates the session key on reconnect.
func (m *Manager) RegisterOrReconnect(sess *Session) (sessionID string, isReconnect bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existingID, ok := m.byImplant[sess.ImplantID]; ok {
		if existing, ok2 := m.sessions[existingID]; ok2 && existing.IsAlive() {
			existing.UpdateCheckin()
			existing.SessionKey = sess.SessionKey
			existing.Hostname = sess.Hostname
			existing.Username = sess.Username
			existing.PID = sess.PID
			existing.RemoteAddr = sess.RemoteAddr
			existing.IntegrityLevel = sess.IntegrityLevel
			if m.store != nil {
				if err := m.store.UpdateSessionKey(existingID, sess.SessionKey); err != nil {
					return "", false, fmt.Errorf("update session key: %w", err)
				}
				if err := m.store.UpdateSessionMetadata(existingID, sess.Hostname, sess.Username, int(sess.PID), sess.RemoteAddr); err != nil {
					return "", false, fmt.Errorf("update session metadata: %w", err)
				}
			}
			return existingID, true, nil
		}
	}

	m.pruneImplantSessions(sess.ImplantID)

	newID, err := crypto.RandomID(16)
	if err != nil {
		return "", false, fmt.Errorf("generate session ID: %w", err)
	}

	sess.SessionID = newID
	m.sessions[newID] = sess
	m.byImplant[sess.ImplantID] = newID

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
			SessionKey:     sess.SessionKey,
		}); err != nil {
			return "", false, fmt.Errorf("persist session: %w", err)
		}
	}

	return newID, false, nil
}

// pruneImplantSessions removes stale in-memory sessions for an implant before a new registration.
func (m *Manager) pruneImplantSessions(implantID string) {
	for sid, s := range m.sessions {
		if s.ImplantID == implantID {
			delete(m.sessions, sid)
		}
	}
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
