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