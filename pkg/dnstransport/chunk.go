package dnstransport

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	SeqLabelWidth   = 3
	TotalLabelWidth = 3
	MaxLabelLen     = 63
)

// MaxDataLabelLen returns the max base32 chars per chunk label for a session/domain.
func MaxDataLabelLen(sessionLabel, domain string) int {
	// FQDN: <seq>.<total>.<data>.<session>.<domain>
	overhead := SeqLabelWidth + 1 + TotalLabelWidth + 1 + 1 + len(sessionLabel) + len(domain)
	maxTotal := 253 - overhead
	if maxTotal > MaxLabelLen {
		return MaxLabelLen
	}
	if maxTotal <= 0 {
		return 0
	}
	return maxTotal
}

// BuildQueryName builds an indexed chunk query: <seq>.<total>.<data>.<session>.<domain>
func BuildQueryName(seq, total int, data, sessionLabel, domain string) string {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	return fmt.Sprintf("%0*d.%0*d.%s.%s%s", SeqLabelWidth, seq, TotalLabelWidth, total, data, sessionLabel, domain)
}

// ParsedQuery holds decoded fields from a DNS chunk query name.
type ParsedQuery struct {
	Seq          int
	Total        int
	Data         string
	SessionLabel string
}

// ParseQueryName parses <seq>.<total>.<data>.<session> from a name with domain suffix stripped.
func ParseQueryName(name string) (*ParsedQuery, error) {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) < 4 {
		return nil, fmt.Errorf("dns chunk query too short")
	}

	seq, err := strconv.Atoi(parts[0])
	if err != nil || seq < 0 {
		return nil, fmt.Errorf("invalid seq label")
	}
	total, err := strconv.Atoi(parts[1])
	if err != nil || total <= 0 || total > 999 {
		return nil, fmt.Errorf("invalid total label")
	}
	// Reject out-of-range sequence numbers before any reassembly state is allocated.
	if seq >= total {
		return nil, fmt.Errorf("seq %d out of range for total %d", seq, total)
	}
	data := parts[2]
	if len(data) > MaxLabelLen {
		return nil, fmt.Errorf("data label too long")
	}
	sessionLabel := parts[3]
	if sessionLabel == "" || len(sessionLabel) > MaxLabelLen {
		return nil, fmt.Errorf("invalid session label")
	}

	return &ParsedQuery{
		Seq:          seq,
		Total:        total,
		Data:         data,
		SessionLabel: sessionLabel,
	}, nil
}