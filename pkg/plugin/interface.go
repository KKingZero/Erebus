package plugin

import "context"

// Module is the interface for compiled-in implant modules.
type Module interface {
	Name() string
	Description() string
	Execute(ctx context.Context, config []byte) ([]byte, error)
}

// ImplantModule extends Module with implant-side lifecycle hooks.
type ImplantModule interface {
	Module
	Init() error
	Cleanup() error
}
