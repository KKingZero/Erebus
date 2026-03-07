package tasks

import (
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// ResultWaiter allows blocking until a task result arrives.
type ResultWaiter struct {
	C      chan *pb.TaskResult
	TaskID string
}

// PendingTasks tracks tasks awaiting results and waiters.
type PendingTasks struct {
	mu      sync.RWMutex
	waiters map[string]*ResultWaiter
}

func NewPendingTasks() *PendingTasks {
	return &PendingTasks{
		waiters: make(map[string]*ResultWaiter),
	}
}

func (p *PendingTasks) AddWaiter(taskID string) *ResultWaiter {
	w := &ResultWaiter{
		C:      make(chan *pb.TaskResult, 1),
		TaskID: taskID,
	}
	p.mu.Lock()
	p.waiters[taskID] = w
	p.mu.Unlock()
	return w
}

func (p *PendingTasks) Resolve(taskID string, result *pb.TaskResult) {
	p.mu.Lock()
	w, ok := p.waiters[taskID]
	if ok {
		delete(p.waiters, taskID)
	}
	p.mu.Unlock()
	if ok {
		w.C <- result
		close(w.C)
	}
}

func (p *PendingTasks) Remove(taskID string) {
	p.mu.Lock()
	w, ok := p.waiters[taskID]
	if ok {
		delete(p.waiters, taskID)
		close(w.C)
	}
	p.mu.Unlock()
}
