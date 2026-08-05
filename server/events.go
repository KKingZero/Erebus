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

// snapshotSubscribers copies active channels under the lock so publish work
// never holds RLock while blocking on slow/full subscribers.
func (eb *EventBus) snapshotSubscribers() []struct {
	id int
	ch chan *pb.Event
} {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	out := make([]struct {
		id int
		ch chan *pb.Event
	}, 0, len(eb.subscribers))
	for id, ch := range eb.subscribers {
		out = append(out, struct {
			id int
			ch chan *pb.Event
		}{id: id, ch: ch})
	}
	return out
}

// Publish sends an event to all subscribers (non-blocking).
func (eb *EventBus) Publish(event *pb.Event) {
	subs := eb.snapshotSubscribers()
	for _, s := range subs {
		select {
		case s.ch <- event:
		default:
			// Drop if subscriber is slow
		}
	}
}

// PublishImportant tries harder to deliver events (approvals). Snapshots
// subscribers under lock, then waits up to importantPublishWait per channel
// without holding the bus lock (so abandoned Subscribe streams cannot stall
// concurrent approval publishing / Subscribe setup).
func (eb *EventBus) PublishImportant(event *pb.Event) {
	subs := eb.snapshotSubscribers()
	// Bound total wait so N slow subscribers cannot stall for N * wait.
	deadline := time.Now().Add(importantPublishWait)
	for _, s := range subs {
		select {
		case s.ch <- event:
			continue
		default:
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			log.Printf("[events] dropped important event type=%v for subscriber %d (global deadline)", event.GetType(), s.id)
			continue
		}
		timer := time.NewTimer(remain)
		select {
		case s.ch <- event:
			timer.Stop()
		case <-timer.C:
			log.Printf("[events] dropped important event type=%v for subscriber %d", event.GetType(), s.id)
		}
	}
}
