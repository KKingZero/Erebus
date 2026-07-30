package crypto

import (
	"fmt"
	"sync"
	"time"
)

// ReplayCache rejects duplicate HMAC timestamps within a TTL window.
type ReplayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time // key: implantID|timestamp
}

// NewReplayCache creates a cache with the given TTL.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{
		ttl:  ttl,
		seen: make(map[string]time.Time),
	}
}

// CheckAndRecord returns an error if the timestamp was already seen within TTL.
// With millisecond timestamps, each beacon can share the same wall second safely.
func (c *ReplayCache) CheckAndRecord(implantID string, timestamp int64) error {
	key := fmt.Sprintf("%s|%d", implantID, timestamp)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistic prune (bounded cost when map stays small under TTL).
	if len(c.seen) > 256 {
		for k, t := range c.seen {
			if now.Sub(t) > c.ttl {
				delete(c.seen, k)
			}
		}
	}

	if _, ok := c.seen[key]; ok {
		return fmt.Errorf("replay detected for implant %s at timestamp %d", implantID, timestamp)
	}
	c.seen[key] = now
	return nil
}