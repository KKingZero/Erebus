package dnstransport

import "testing"

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