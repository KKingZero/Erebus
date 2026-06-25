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
	s.Alive = true
}

func (s *Session) IsAlive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Alive
}

func (s *Session) Kill() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Alive = false
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
