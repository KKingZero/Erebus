package suggestions

import (
	"strings"
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func TestForLDAPEnumKerberoastable(t *testing.T) {
	actions := ForLDAPEnum(&pb.LDAPEnumResult{
		Domain:       "corp.local",
		Dc:           "dc01.corp.local",
		QueryType:    "kerberoastable",
		TotalResults: 2,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName":         {Values: []string{"svc_sql"}},
				"servicePrincipalName":   {Values: []string{"MSSQLSvc/dc01.corp.local"}},
			},
		}},
	})
	if len(actions) == 0 {
		t.Fatal("expected actions")
	}
	if !strings.Contains(actions[0], "kerberoast") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForLDAPEnumEmpty(t *testing.T) {
	actions := ForLDAPEnum(&pb.LDAPEnumResult{
		QueryType:    "kerberoastable",
		TotalResults: 0,
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "asrep") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForKerberoast(t *testing.T) {
	actions := ForKerberoast(&pb.KerberoastResult{
		Hashes: []*pb.KerberoastHash{{SamAccountName: "svc"}},
	})
	if !strings.Contains(actions[0], "hashcat") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForCredDumpNTLM(t *testing.T) {
	actions := ForCredDump(&pb.CredDumpResult{
		Credentials: []*pb.Credential{{Type: "ntlm", Username: "admin"}},
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "lateral_move") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForPortscan(t *testing.T) {
	actions := ForPortscan(&pb.NetPortscanResult{
		Ports: []*pb.PortResult{{Host: "10.0.0.5", Port: 445, Open: true}},
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "lateral_move") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestCap(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e", "f"}
	out := Cap(in)
	if len(out) != maxActions {
		t.Fatalf("cap len %d want %d", len(out), maxActions)
	}
}