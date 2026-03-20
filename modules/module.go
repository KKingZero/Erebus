package modules

import "context"

// RiskTier defines the risk level of a module
type RiskTier int

const (
	LOW      RiskTier = 1
	MEDIUM   RiskTier = 2
	HIGH     RiskTier = 3
	CRITICAL RiskTier = 4
)

// Platform defines the target platform
type Platform string

const (
	PlatformWeb        Platform = "web"
	PlatformWindows    Platform = "windows"
	PlatformLinux      Platform = "linux"
	PlatformNetwork    Platform = "network"
	PlatformAD         Platform = "AD"
	PlatformCloud      Platform = "cloud"
	PlatformRecon      Platform = "recon"
	PlatformContainers Platform = "containers"
)

// AgentContext holds all info about the current target/session
type AgentContext struct {
	Target    string
	LHOST     string
	LPORT     int
	SessionID string
	Options   map[string]string
	Ctx       context.Context
}

// ModuleResult holds the output of a module execution
type ModuleResult struct {
	Success  bool
	Output   string
	Loot     []LootItem
	Sessions []string
	Error    error
}

// LootItem represents captured data
type LootItem struct {
	Type  string // hash, credential, token, file, screenshot
	Value string
	Host  string
	User  string
}

// ErebusModule is the interface every module must implement
type ErebusModule interface {
	Name() string
	Description() string
	CVE() string
	ATTACKTag() string
	RiskTier() RiskTier
	Platform() Platform
	Options() map[string]string
	Execute(ctx AgentContext) (ModuleResult, error)
}
