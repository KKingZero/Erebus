package listeners

import (
	"fmt"
	"testing"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/dnstransport"
)

func TestIngestChunkEnforcesLabelCap(t *testing.T) {
	l := &DNSListener{chunks: make(map[string]*chunkBuffer)}

	// Fill to max labels with incomplete reassemblies (total=2, only seq=0).
	for i := 0; i < maxDNSChunkLabels; i++ {
		parsed := &dnstransport.ParsedQuery{
			Seq:          0,
			Total:        2,
			Data:         "AA",
			SessionLabel: fmt.Sprintf("lab%02d", i),
		}
		if out := l.ingestChunk(parsed, "1.2.3.4:53"); out != nil {
			t.Fatalf("unexpected payload for incomplete buffer %d", i)
		}
	}
	if len(l.chunks) != maxDNSChunkLabels {
		t.Fatalf("expected %d labels, got %d", maxDNSChunkLabels, len(l.chunks))
	}

	// One more new label must be dropped.
	extra := &dnstransport.ParsedQuery{Seq: 0, Total: 2, Data: "BB", SessionLabel: "overflow"}
	if out := l.ingestChunk(extra, "1.2.3.4:53"); out != nil {
		t.Fatal("expected drop of overflow label")
	}
	if _, ok := l.chunks["overflow"]; ok {
		t.Fatal("overflow label should not be stored")
	}
	if len(l.chunks) != maxDNSChunkLabels {
		t.Fatalf("label count changed after overflow: %d", len(l.chunks))
	}
}

func TestIngestChunkDropsTotalMismatch(t *testing.T) {
	l := &DNSListener{chunks: make(map[string]*chunkBuffer)}
	p1 := &dnstransport.ParsedQuery{Seq: 0, Total: 2, Data: "AA", SessionLabel: "s1"}
	l.ingestChunk(p1, "1.1.1.1:53")
	if len(l.chunks) != 1 {
		t.Fatal("expected one buffer")
	}
	// Different total for same label resets/drops prior state then may re-create.
	p2 := &dnstransport.ParsedQuery{Seq: 0, Total: 3, Data: "BB", SessionLabel: "s1"}
	l.ingestChunk(p2, "1.1.1.1:53")
	buf := l.chunks["s1"]
	if buf == nil {
		t.Fatal("expected new buffer after total change")
	}
	if buf.total != 3 {
		t.Fatalf("total=%d want 3", buf.total)
	}
	if len(buf.chunks) != 1 {
		t.Fatalf("expected single chunk after reset, got %d", len(buf.chunks))
	}
}

func TestIngestChunkRejectsOutOfRangeSeq(t *testing.T) {
	l := &DNSListener{chunks: make(map[string]*chunkBuffer)}
	// Simulate a bypass of ParseQueryName (should still no-op).
	p := &dnstransport.ParsedQuery{Seq: 5, Total: 3, Data: "AA", SessionLabel: "s1"}
	if out := l.ingestChunk(p, "1.1.1.1:53"); out != nil {
		t.Fatal("expected nil for out-of-range seq")
	}
	if len(l.chunks) != 0 {
		t.Fatal("out-of-range seq must not allocate state")
	}
}
