package smb

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func TestParseNTHash(t *testing.T) {
	nt := "603fc24ee01a9409f83c9d1d701485c5"
	b, err := parseNTHash(nt)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("len=%d", len(b))
	}
	// LM empty + NT
	if b[0] != 0xaa || b[16] != 0x60 {
		t.Fatalf("unexpected bytes: %x", b)
	}

	lmnt := "aad3b435b51404eeaad3b435b51404ee:" + nt
	b2, err := parseNTHash(lmnt)
	if err != nil {
		t.Fatal(err)
	}
	if len(b2) != 32 {
		t.Fatalf("len=%d", len(b2))
	}
}

func TestSMBInitiatorAnonymous(t *testing.T) {
	init, err := smbInitiator(&pb.SMBClientConfig{Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	if init == nil {
		t.Fatal("nil initiator")
	}
}

func TestNormalizeSharePath(t *testing.T) {
	if got := normalizeSharePath(`\foo\bar`); got != "foo/bar" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeSharePath(""); got != "." {
		t.Fatalf("got %q", got)
	}
}
