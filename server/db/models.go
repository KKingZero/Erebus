package db

import "time"

type SessionRow struct {
	SessionID      string
	ImplantID      string
	Hostname       string
	Username       string
	OS             string
	Arch           string
	PID            uint32
	IntegrityLevel string
	Transport      string
	RemoteAddr     string
	RegisteredAt   time.Time
	LastCheckin     time.Time
	Alive          bool
	SessionKey     []byte
}

type TaskRow struct {
	TaskID         string
	SessionID      string
	TaskType       int32
	Data           []byte
	TimeoutMs      int64
	CreatedAt      time.Time
	CompletedAt    *time.Time
	Success        *bool
	ResultData     []byte
	ResultError    string
	ExecutionTimeMs int64
}

type ListenerRow struct {
	ID        string
	Name      string
	Protocol  int32
	Host      string
	Port      uint32
	Active    bool
	StartedAt time.Time
}

type BuildRow struct {
	ID         string
	CreatedAt  time.Time
	Operator   string
	OS         string
	Arch       string
	Transport  string
	Callbacks  string // JSON array
	SecretHash string // bcrypt of implant secret
	Evasion    string // JSON config snapshot
	Garbled    bool
}

type LootRow struct {
	ID        string
	Type      string
	Source    string
	SessionID string
	Data      []byte
	Tags      string // comma-separated tags (e.g. "auto-harvest,cloud")
	CreatedAt time.Time
}

type AutoHarvestTaskRow struct {
	ID        string
	SessionID string
	TaskID    string
	TaskType  string
	Status    string // "pending", "completed", "failed"
	CreatedAt time.Time
}
