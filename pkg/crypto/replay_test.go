package crypto

import (
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicate(t *testing.T) {
	c := NewReplayCache(60 * time.Second)
	if err := c.CheckAndRecord("implant-1", 100); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("implant-1", 100); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func TestReplayCacheAllowsDifferentTimestamps(t *testing.T) {
	c := NewReplayCache(60 * time.Second)
	if err := c.CheckAndRecord("implant-1", 100); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("implant-1", 101); err != nil {
		t.Fatal(err)
	}
}

func TestReplayCacheAllowsSubSecondMillis(t *testing.T) {
	c := NewReplayCache(60 * time.Second)
	// Two beacons in the same wall second (ms timestamps differ).
	base := time.Now().UnixMilli()
	if err := c.CheckAndRecord("implant-1", base); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("implant-1", base+1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("implant-1", base); err == nil {
		t.Fatal("expected replay on same ms")
	}
}