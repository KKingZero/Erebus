package lateral

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestNtlmSecuritySession_WrapUnwrapRoundTrip(t *testing.T) {
	// ESS + Seal + Sign + KeyExch + 128 — typical WinRM negotiation.
	flags := ntlmFlagUnicode | ntlmFlagSign | ntlmFlagSeal | ntlmFlagExtendedSessionSecurity |
		ntlmFlag128 | ntlmFlagKeyExch | ntlmFlagAlwaysSign
	key := bytes.Repeat([]byte{0x55}, 16)

	client, err := newClientSecuritySession(flags, key)
	if err != nil {
		t.Fatal(err)
	}
	// Server-side session with swapped directions.
	server, err := newServerSecuritySession(flags, key)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte(`<?xml version="1.0"?><s:Envelope>hello</s:Envelope>`)
	sealed, sig, err := client.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, plain) {
		t.Fatal("expected ciphertext != plaintext when Seal set")
	}
	if len(sig) != 16 {
		t.Fatalf("sig len %d", len(sig))
	}

	out, err := server.Unwrap(sealed, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("unwrap mismatch: %q vs %q", out, plain)
	}

	// Server response
	resp := []byte(`<s:Envelope>ok</s:Envelope>`)
	sealed2, sig2, err := server.Wrap(resp)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := client.Unwrap(sealed2, sig2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out2, resp) {
		t.Fatalf("client unwrap mismatch")
	}
}

func TestBuildParseEncryptedWinRMBody(t *testing.T) {
	flags := ntlmFlagUnicode | ntlmFlagSign | ntlmFlagSeal | ntlmFlagExtendedSessionSecurity |
		ntlmFlag128 | ntlmFlagKeyExch
	key := bytes.Repeat([]byte{0xaa}, 16)
	client, err := newClientSecuritySession(flags, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerSecuritySession(flags, key)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte(`<?xml version="1.0"?><Envelope>test-soap</Envelope>`)
	body, ct, err := buildEncryptedWinRMBody(plain, client)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ct, winrmSPNEGOProtocol) {
		t.Fatalf("content-type %q", ct)
	}
	if !bytes.Contains(body, []byte(winrmMIMEBoundary)) {
		t.Fatal("missing MIME boundary")
	}
	if !bytes.Contains(body, []byte("OriginalContent:")) {
		t.Fatal("missing OriginalContent")
	}

	// Decrypt with server session by parsing the encrypted stream the way WinRM does.
	// Re-use parse path: need matching session (server receives client-sealed).
	// parseEncryptedWinRMBody uses session.Unwrap — so pass server session.
	got, err := parseEncryptedWinRMBody(body, ct, server)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestNewNegotiateMessageSeal_Flags(t *testing.T) {
	msg, err := newNegotiateMessageSeal("CORP", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) < 32 || string(msg[0:8]) != "NTLMSSP\x00" {
		t.Fatalf("bad negotiate %x", msg[:min(16, len(msg))])
	}
	if msg[8] != 1 {
		t.Fatalf("type %d", msg[8])
	}
	flags := binary.LittleEndian.Uint32(msg[12:16])
	for _, f := range []uint32{ntlmFlagSeal, ntlmFlagSign, ntlmFlagKeyExch, ntlmFlag128, ntlmFlagExtendedSessionSecurity} {
		if flags&f == 0 {
			t.Fatalf("missing flag 0x%x in 0x%x", f, flags)
		}
	}
}

func TestCanSeal(t *testing.T) {
	if canSeal(0) {
		t.Fatal("zero flags should not seal")
	}
	if !canSeal(ntlmFlagSeal) {
		t.Fatal("seal flag")
	}
	// Permissive: Sign-only still attempts SPNEGO encryption path.
	if !canSeal(ntlmFlagSign) {
		t.Fatal("sign-only should count as canSeal (permissive)")
	}
	if !canSeal(ntlmFlagSeal | ntlmFlagSign) {
		t.Fatal("seal+sign should seal")
	}
}

func TestIsEncryptionRejected(t *testing.T) {
	if !isEncryptionRejected(415, nil) {
		t.Fatal("415")
	}
	if !isEncryptionRejected(500, []byte("AllowUnencrypted is false")) {
		t.Fatal("body encrypt hint")
	}
	if isEncryptionRejected(500, []byte("command not found")) {
		t.Fatal("unrelated 500")
	}
}

func TestLooksLikeSOAP(t *testing.T) {
	if !looksLikeSOAP([]byte(`<?xml version="1.0"?><s:Envelope>`)) {
		t.Fatal("soap")
	}
	if looksLikeSOAP([]byte(`not xml`)) {
		t.Fatal("plain")
	}
}

func TestNewClientSecuritySession_RequiresESS(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	// Seal without ESS must fail.
	if _, err := newClientSecuritySession(ntlmFlagSeal|ntlmFlagSign, key); err == nil {
		t.Fatal("expected error without ESS")
	}
	flags := ntlmFlagSeal | ntlmFlagSign | ntlmFlagExtendedSessionSecurity | ntlmFlag128 | ntlmFlagKeyExch
	if _, err := newClientSecuritySession(flags, key); err != nil {
		t.Fatal(err)
	}
}

func TestMarshalAuthenticateMessage_MICLayout(t *testing.T) {
	// TargetInfo with MsvAvFlags = MIC provided (id=6, len=4, value=0x2).
	ti := make([]byte, 0, 12)
	// AvFlags
	ti = append(ti, 6, 0, 4, 0) // id=6, len=4
	flagBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagBytes, msvAvFlagMICProvided)
	ti = append(ti, flagBytes...)
	// EOL
	ti = append(ti, 0, 0, 0, 0)

	neg := make([]byte, 32)
	copy(neg[0:8], []byte("NTLMSSP\x00"))
	chl := make([]byte, 48)
	copy(chl[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(chl[8:12], 2)
	exported := bytes.Repeat([]byte{0x55}, 16)
	encKey := bytes.Repeat([]byte{0x66}, 16)

	msg, err := marshalAuthenticateMessageMIC(
		"bob", "CORP",
		[]byte{1}, []byte{2, 3}, encKey,
		ntlmFlagUnicode|ntlmFlagSeal|ntlmFlagSign|ntlmFlagExtendedSessionSecurity|ntlmFlagKeyExch|ntlmFlag128,
		exported, neg, chl, ti,
	)
	if err != nil {
		t.Fatal(err)
	}
	// fixed(64) + version(8) + mic(16) = 88 before payloads
	if len(msg) < 88 {
		t.Fatalf("short MIC TYPE3: %d", len(msg))
	}
	flags := binary.LittleEndian.Uint32(msg[60:64])
	if flags&ntlmFlagVersion == 0 {
		t.Fatal("VERSION flag should be set when MIC present")
	}
	// Version at 64: major 10, revision 0x0f
	if msg[64] != 10 || msg[71] != 0x0f {
		t.Fatalf("bad version bytes: %x", msg[64:72])
	}
	// MIC should be non-zero after compute
	mic := msg[72:88]
	if bytes.Equal(mic, make([]byte, 16)) {
		t.Fatal("MIC still all zeros")
	}
	// First payload offset (Lm) should be 88
	if binary.LittleEndian.Uint32(msg[16:20]) != 88 {
		t.Fatalf("lm offset %d want 88", binary.LittleEndian.Uint32(msg[16:20]))
	}
}

func TestHashNegotiator_ResetClearsSession(t *testing.T) {
	n := &hashNegotiator{
		complete: true,
		session:  &ntlmSecuritySession{flags: ntlmFlagSeal},
	}
	n.reset()
	if n.complete || n.session != nil {
		t.Fatal("reset should clear complete and session")
	}
}

func TestMarshalAuthenticateMessage_WithSessionKey(t *testing.T) {
	encKey := bytes.Repeat([]byte{0x11}, 16)
	msg, err := marshalAuthenticateMessageMIC("bob", "CORP", []byte{1}, []byte{2, 3}, encKey, 0xE20882B7, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg[0:8]) != "NTLMSSP\x00" || msg[8] != 3 {
		t.Fatal("bad TYPE3 header")
	}
	// EncryptedRandomSessionKey Len at offset 52
	if binary.LittleEndian.Uint16(msg[52:54]) != 16 {
		t.Fatalf("enc session key len %d", binary.LittleEndian.Uint16(msg[52:54]))
	}
}

// newServerSecuritySession is the server-side counterpart for unit tests only.
func newServerSecuritySession(flags uint32, exportedSessionKey []byte) (*ntlmSecuritySession, error) {
	if len(exportedSessionKey) != 16 {
		return nil, errors.New("exported session key must be 16 bytes")
	}
	outSealKey := ntlmSealKey(flags, exportedSessionKey, serverSealingMagic)
	inSealKey := ntlmSealKey(flags, exportedSessionKey, clientSealingMagic)
	outC, err := rc4.NewCipher(outSealKey)
	if err != nil {
		return nil, err
	}
	inC, err := rc4.NewCipher(inSealKey)
	if err != nil {
		return nil, err
	}
	return &ntlmSecuritySession{
		flags:      flags,
		outSignKey: ntlmSignKey(exportedSessionKey, serverSigningMagic),
		inSignKey:  ntlmSignKey(exportedSessionKey, clientSigningMagic),
		outSeal:    outC,
		inSeal:     inC,
	}, nil
}
