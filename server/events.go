package server

import (
	"log"
	"sync"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

const (
	eventBufferSize     = 256
	importantPublishWait = 2 * time.Second
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
	ch := make(chan *pb.Event, eventBufferSize)
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

// PublishImportant tries harder to deliver events (approvals). Blocks up to
// importantPublishWait per subscriber; logs if still dropped.
func (eb *EventBus) PublishImportant(event *pb.Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for id, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			timer := time.NewTimer(importantPublishWait)
			select {
			case ch <- event:
				timer.Stop()
			case <-timer.C:
				log.Printf("[events] dropped important event type=%v for subscriber %d", event.GetType(), id)
			}
		}
	}
}
