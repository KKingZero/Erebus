package ad

import (
	"strings"
	"testing"
)

func TestBuildLDAPFilterDomainAdmins(t *testing.T) {
	baseDN := "DC=corp,DC=local"
	filter, err := BuildLDAPFilter("domain_admins", baseDN)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filter, baseDN) {
		t.Fatalf("filter missing base DN: %s", filter)
	}
	if strings.Contains(filter, "DC=*") {
		t.Fatalf("filter still contains wildcard DN: %s", filter)
	}
}

func TestBuildLDAPFilterInteresting(t *testing.T) {
	filter, err := BuildLDAPFilter("interesting", "DC=support,DC=htb")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filter, "info=*") {
		t.Fatalf("interesting filter missing info: %s", filter)
	}
	// secrets is an alias
	f2, err := BuildLDAPFilter("secrets", "DC=support,DC=htb")
	if err != nil {
		t.Fatal(err)
	}
	if f2 != filter {
		t.Fatalf("secrets should match interesting filter")
	}
}

func TestNormalizeLDAPHash(t *testing.T) {
	nt := "603fc24ee01a9409f83c9d1d701485c5"
	if got := normalizeLDAPHash("aad3b435b51404eeaad3b435b51404ee:" + nt); got != nt {
		t.Fatalf("got %q", got)
	}
	if got := normalizeLDAPHash(nt); got != nt {
		t.Fatalf("got %q", got)
	}
}