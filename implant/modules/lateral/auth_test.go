package lateral

import "testing"

func TestNormalizeNTHashHex(t *testing.T) {
	nt := "603fc24ee01a9409f83c9d1d701485c5"
	got, err := normalizeNTHashHex(nt)
	if err != nil {
		t.Fatal(err)
	}
	if got != nt {
		t.Fatalf("got %q", got)
	}

	lmnt := "aad3b435b51404eeaad3b435b51404ee:" + nt
	got, err = normalizeNTHashHex(lmnt)
	if err != nil {
		t.Fatal(err)
	}
	if got != lmnt {
		t.Fatalf("got %q", got)
	}

	concat := "aad3b435b51404eeaad3b435b51404ee" + nt
	got, err = normalizeNTHashHex(concat)
	if err != nil {
		t.Fatal(err)
	}
	if got != lmnt {
		t.Fatalf("got %q want %q", got, lmnt)
	}

	if _, err := normalizeNTHashHex("deadbeef"); err == nil {
		t.Fatal("expected error for short hash")
	}
}

func TestParseDomainUser(t *testing.T) {
	d, u := parseDomainUser(`LOGGING\msa_health$`, "logging.htb")
	if d != "LOGGING" || u != "msa_health$" {
		t.Fatalf("got %q %q", d, u)
	}
	d, u = parseDomainUser("user@corp.local", "")
	if d != "corp.local" || u != "user" {
		t.Fatalf("got %q %q", d, u)
	}
	d, u = parseDomainUser("bob", "CORP")
	if d != "CORP" || u != "bob" {
		t.Fatalf("got %q %q", d, u)
	}
}

func TestFormatDomainUser(t *testing.T) {
	if got := formatDomainUser("LOGGING", "msa_health$"); got != `LOGGING\msa_health$` {
		t.Fatalf("got %q", got)
	}
	if got := formatDomainUser("LOGGING", `LOGGING\msa_health$`); got != `LOGGING\msa_health$` {
		t.Fatalf("got %q", got)
	}
}

func TestMarshalAuthenticateMessage_RoundTripShape(t *testing.T) {
	// Smoke: TYPE3 header is NTLMSSP\0 + type 3
	msg, err := marshalAuthenticateMessage("user", "DOMAIN", []byte{1, 2}, []byte{3, 4, 5}, 0xE20882B7)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) < 64 {
		t.Fatalf("short message %d", len(msg))
	}
	if string(msg[0:8]) != "NTLMSSP\x00" {
		t.Fatalf("bad signature %q", msg[0:8])
	}
	if msg[8] != 3 {
		t.Fatalf("bad type %d", msg[8])
	}
}
