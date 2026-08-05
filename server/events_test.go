package server

import (
	"sync"
	"testing"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func TestPublishImportant_DoesNotHoldLockWhileWaiting(t *testing.T) {
	eb := NewEventBus()
	// Full subscriber that never drains.
	ch, unsub := eb.Subscribe()
	defer unsub()
	for i := 0; i < eventBufferSize; i++ {
		eb.Publish(&pb.Event{Type: pb.EventType_EVENT_LOG})
	}
	// Ensure channel is full.
	select {
	case <-ch:
		// drained one — refill
		eb.Publish(&pb.Event{Type: pb.EventType_EVENT_LOG})
	default:
	}

	// Concurrent Subscribe must complete while PublishImportant waits on full channel.
	done := make(chan struct{})
	go func() {
		eb.PublishImportant(&pb.Event{Type: pb.EventType_EVENT_APPROVAL_REQUIRED})
		close(done)
	}()

	// Give PublishImportant a moment to enter wait on full channel.
	time.Sleep(20 * time.Millisecond)

	var mu sync.Mutex
	subscribed := false
	go func() {
		_, unsub2 := eb.Subscribe()
		unsub2()
		mu.Lock()
		subscribed = true
		mu.Unlock()
	}()

	// Subscribe must not block for the full importantPublishWait if lock is released.
	deadline := time.After(500 * time.Millisecond)
	for {
		mu.Lock()
		ok := subscribed
		mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Subscribe blocked while PublishImportant waited on full channel (lock held?)")
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case <-done:
	case <-time.After(importantPublishWait + time.Second):
		t.Fatal("PublishImportant did not return")
	}
}

func TestPublish_NonBlocking(t *testing.T) {
	eb := NewEventBus()
	_, unsub := eb.Subscribe()
	defer unsub()
	for i := 0; i < eventBufferSize+10; i++ {
		eb.Publish(&pb.Event{Type: pb.EventType_EVENT_LOG})
	}
	// Must not block even when full.
	done := make(chan struct{})
	go func() {
		eb.Publish(&pb.Event{Type: pb.EventType_EVENT_LOG})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on full channel")
	}
}
