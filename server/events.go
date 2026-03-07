package server

import (
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// EventBus fans out events to multiple subscribers.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[int]chan *pb.Event
	nextID      int
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[int]chan *pb.Event),
	}
}

// Subscribe returns a channel that receives events and an unsubscribe function.
func (eb *EventBus) Subscribe() (<-chan *pb.Event, func()) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	id := eb.nextID
	eb.nextID++
	ch := make(chan *pb.Event, 64)
	eb.subscribers[id] = ch
	unsub := func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()
		delete(eb.subscribers, id)
		close(ch)
	}
	return ch, unsub
}

// Publish sends an event to all subscribers (non-blocking).
func (eb *EventBus) Publish(event *pb.Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for _, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			// Drop if subscriber is slow
		}
	}
}
