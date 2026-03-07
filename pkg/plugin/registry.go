package plugin

import (
	"context"
	"fmt"
	"sync"
)

// Registry holds compiled-in modules.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry creates a new module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Global is the default global registry.
var Global = NewRegistry()

// Register adds a module to the registry.
func (r *Registry) Register(m Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules[m.Name()] = m
}

// Execute runs a module by name.
func (r *Registry) Execute(ctx context.Context, name string, config []byte) ([]byte, error) {
	r.mu.RLock()
	m, ok := r.modules[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return m.Execute(ctx, config)
}

// List returns all registered module names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	return names
}

// Get returns a module by name.
func (r *Registry) Get(name string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[name]
	return m, ok
}
