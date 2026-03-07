package listeners

import (
	"fmt"
	"log"
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// Listener is the interface for all listener types.
type Listener interface {
	ID() string
	Name() string
	Protocol() pb.ListenerProtocol
	Address() string
	Start() error
	Stop() error
	Status() *pb.ListenerStatus
}

// Manager manages the lifecycle of listeners.
type Manager struct {
	mu        sync.RWMutex
	listeners map[string]Listener
}

func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]Listener),
	}
}

func (m *Manager) Add(l Listener) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.listeners[l.ID()]; exists {
		return fmt.Errorf("listener already exists: %s", l.ID())
	}
	m.listeners[l.ID()] = l
	return nil
}

func (m *Manager) Start(id string) error {
	m.mu.RLock()
	l, ok := m.listeners[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}
	log.Printf("[listeners] starting %s (%s)", l.Name(), l.Address())
	return l.Start()
}

func (m *Manager) Stop(id string) error {
	m.mu.RLock()
	l, ok := m.listeners[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}
	log.Printf("[listeners] stopping %s", l.Name())
	return l.Stop()
}

func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.listeners[id]
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}
	l.Stop()
	delete(m.listeners, id)
	return nil
}

func (m *Manager) Get(id string) (Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.listeners[id]
	return l, ok
}

func (m *Manager) List() []*pb.ListenerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*pb.ListenerStatus
	for _, l := range m.listeners {
		result = append(result, l.Status())
	}
	return result
}

func (m *Manager) StopAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, l := range m.listeners {
		if err := l.Stop(); err != nil {
			log.Printf("[listeners] error stopping %s: %v", l.Name(), err)
		}
	}
}
