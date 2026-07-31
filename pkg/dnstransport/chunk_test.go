package dnstransport

import (
	"strings"
	"testing"
)

func TestBuildAndParseQueryName(t *testing.T) {
	domain := "c2.example.com."
	session := "reg"
	qname := BuildQueryName(1, 3, "abc123", session, domain)

	parsed, err := ParseQueryName(stringsTrimDomain(qname, domain))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Seq != 1 || parsed.Total != 3 || parsed.Data != "abc123" || parsed.SessionLabel != session {
		t.Fatalf("unexpected parsed query: %+v", parsed)
	}
}

func TestParseQueryNameRejectsSeqOutOfRange(t *testing.T) {
	// seq=3, total=3 → seq must be < total
	if _, err := ParseQueryName("003.003.abc.sess"); err == nil {
		t.Fatal("expected error for seq >= total")
	}
	// seq=0, total=1 is valid
	if _, err := ParseQueryName("000.001.abc.sess"); err != nil {
		t.Fatalf("boundary seq=0 total=1 should be ok: %v", err)
	}
	// seq=2, total=3 is valid
	if _, err := ParseQueryName("002.003.abc.sess"); err != nil {
		t.Fatalf("boundary seq=total-1 should be ok: %v", err)
	}
}

func TestParseQueryNameRejectsOversizedSession(t *testing.T) {
	long := strings.Repeat("a", MaxLabelLen+1)
	name := "000.001.abc." + long
	if _, err := ParseQueryName(name); err == nil {
		t.Fatal("expected error for oversized session label")
	}
}

func TestMaxDataLabelLen(t *testing.T) {
	if n := MaxDataLabelLen("reg", "c2.example.com."); n <= 0 || n > MaxLabelLen {
		t.Fatalf("unexpected max label len: %d", n)
	}
}

func stringsTrimDomain(qname, domain string) string {
	return stringsTrimSuffix(qname, domain)
}

func stringsTrimSuffix(s, suffix string) string {
	if len(suffix) > 0 && len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}