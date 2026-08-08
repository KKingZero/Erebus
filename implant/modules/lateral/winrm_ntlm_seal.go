package lateral

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// WinRM NTLM message encryption (HTTP-SPNEGO-session-encrypted), matching
// masterzen/winrm Encryption + pywinrm encryption.py / MS-NLMP signing & sealing.
// Used by the NT-hash (PTH) transport so AllowUnencrypted=false hosts work.

const (
	winrmMIMEBoundary   = "--Encrypted Boundary"
	winrmSPNEGOProtocol = "application/HTTP-SPNEGO-session-encrypted"
	winrmSOAPContent    = "application/soap+xml;charset=UTF-8"
)

// NTLMSSP negotiate flags (subset used for sealing).
const (
	ntlmFlagUnicode                 uint32 = 1 << 0
	ntlmFlagOEM                     uint32 = 1 << 1
	ntlmFlagRequestTarget           uint32 = 1 << 2
	ntlmFlagSign                    uint32 = 1 << 4
	ntlmFlagSeal                    uint32 = 1 << 5
	ntlmFlagDatagram                uint32 = 1 << 6
	ntlmFlagLMKey                   uint32 = 1 << 7
	ntlmFlagNTLM                    uint32 = 1 << 9
	ntlmFlagAnonymous               uint32 = 1 << 11
	ntlmFlagOEMDomainSupplied       uint32 = 1 << 12
	ntlmFlagOEMWorkstationSupplied  uint32 = 1 << 13
	ntlmFlagAlwaysSign              uint32 = 1 << 15
	ntlmFlagTargetTypeDomain        uint32 = 1 << 16
	ntlmFlagTargetTypeServer        uint32 = 1 << 17
	ntlmFlagExtendedSessionSecurity uint32 = 1 << 19
	ntlmFlagIdentify                uint32 = 1 << 20
	ntlmFlagNonNTSessionKey         uint32 = 1 << 22
	ntlmFlagTargetInfo              uint32 = 1 << 23
	ntlmFlagVersion                 uint32 = 1 << 25
	ntlmFlag128                     uint32 = 1 << 29
	ntlmFlagKeyExch                 uint32 = 1 << 30
	ntlmFlag56                      uint32 = 1 << 31
)

// defaultSealNegotiateFlags matches bodgit/ntlmssp defaultClientFlags (seal path).
func defaultSealNegotiateFlags() uint32 {
	return ntlmFlagUnicode |
		ntlmFlagRequestTarget |
		ntlmFlagSign |
		ntlmFlagSeal |
		ntlmFlagNTLM |
		ntlmFlagAlwaysSign |
		ntlmFlagExtendedSessionSecurity |
		ntlmFlagTargetInfo |
		ntlmFlag128 |
		ntlmFlagKeyExch |
		ntlmFlag56
}

var (
	clientSigningMagic = append([]byte("session key to client-to-server signing key magic constant"), 0x00)
	serverSigningMagic = append([]byte("session key to server-to-client signing key magic constant"), 0x00)
	clientSealingMagic = append([]byte("session key to client-to-server sealing key magic constant"), 0x00)
	serverSealingMagic = append([]byte("session key to server-to-client sealing key magic constant"), 0x00)
)

// ntlmSecuritySession holds MS-NLMP signing/sealing state after TYPE3.
type ntlmSecuritySession struct {
	flags                              uint32
	outSeq, inSeq                      uint32
	outSignKey, inSignKey              []byte
	outSeal, inSeal                    *rc4.Cipher
}

func newClientSecuritySession(flags uint32, exportedSessionKey []byte) (*ntlmSecuritySession, error) {
	if len(exportedSessionKey) != 16 {
		return nil, fmt.Errorf("exported session key must be 16 bytes, got %d", len(exportedSessionKey))
	}
	// WinRM always negotiates ESS; non-ESS seal is intentionally unsupported.
	if flags&ntlmFlagExtendedSessionSecurity == 0 {
		return nil, errors.New("NTLM sealing requires extended session security")
	}
	outSealKey := ntlmSealKey(flags, exportedSessionKey, clientSealingMagic)
	inSealKey := ntlmSealKey(flags, exportedSessionKey, serverSealingMagic)
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
		outSignKey: ntlmSignKey(exportedSessionKey, clientSigningMagic),
		inSignKey:  ntlmSignKey(exportedSessionKey, serverSigningMagic),
		outSeal:    outC,
		inSeal:     inC,
	}, nil
}

func ntlmSignKey(exported, constant []byte) []byte {
	return hashMD5(concat(exported, constant))
}

func ntlmSealKey(flags uint32, exported, constant []byte) []byte {
	switch {
	case flags&ntlmFlagExtendedSessionSecurity != 0 && flags&ntlmFlag128 != 0:
		return hashMD5(concat(exported, constant))
	case flags&ntlmFlagExtendedSessionSecurity != 0 && flags&ntlmFlag56 != 0:
		return hashMD5(concat(exported[:7], constant))
	case flags&ntlmFlagExtendedSessionSecurity != 0:
		return hashMD5(concat(exported[:5], constant))
	default:
		return append([]byte(nil), exported...)
	}
}

func hashMD5(b []byte) []byte {
	h := md5.Sum(b)
	return h[:]
}

// Wrap seals (and signs) a plaintext message. Returns sealed ciphertext and 16-byte signature.
func (s *ntlmSecuritySession) Wrap(plain []byte) (sealed, signature []byte, err error) {
	if s == nil {
		return nil, nil, errors.New("nil security session")
	}
	m := append([]byte(nil), plain...)
	switch {
	case s.flags&ntlmFlagSeal != 0:
		out := make([]byte, len(m))
		s.outSeal.XORKeyStream(out, m)
		m = out
		fallthrough
	case s.flags&ntlmFlagSign != 0:
		sig, err := s.calculateSignature(plain, s.outSignKey, s.outSeq, s.outSeal)
		if err != nil {
			return nil, nil, err
		}
		s.outSeq++
		return m, sig, nil
	default:
		return m, nil, nil
	}
}

// Unwrap verifies signature and decrypts a sealed message.
func (s *ntlmSecuritySession) Unwrap(sealed, signature []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil security session")
	}
	m := append([]byte(nil), sealed...)
	switch {
	case s.flags&ntlmFlagSeal != 0:
		out := make([]byte, len(m))
		s.inSeal.XORKeyStream(out, m)
		m = out
		fallthrough
	case s.flags&ntlmFlagSign != 0:
		expected, err := s.calculateSignature(m, s.inSignKey, s.inSeq, s.inSeal)
		if err != nil {
			return nil, err
		}
		// Compare checksum + sequence portions (ESS: checksum at [4:12], seq at [12:16])
		offset := 8
		if s.flags&ntlmFlagExtendedSessionSecurity != 0 {
			offset = 4
		}
		if len(signature) < 16 || len(expected) < 16 {
			return nil, errors.New("ntlm signature too short")
		}
		if !bytes.Equal(signature[offset:12], expected[offset:12]) {
			return nil, errors.New("ntlm checksum mismatch")
		}
		if !bytes.Equal(signature[12:16], expected[12:16]) {
			return nil, errors.New("ntlm sequence mismatch")
		}
		s.inSeq++
		return m, nil
	default:
		return m, nil
	}
}

func (s *ntlmSecuritySession) calculateSignature(message, signingKey []byte, seq uint32, handle *rc4.Cipher) ([]byte, error) {
	if s.flags&ntlmFlagExtendedSessionSecurity == 0 {
		return nil, errors.New("non-ESS NTLM signatures not supported")
	}
	buf := make([]byte, 0, 16)
	// signature version = 1
	ver := make([]byte, 4)
	binary.LittleEndian.PutUint32(ver, 1)
	buf = append(buf, ver...)

	seqNum := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqNum, seq)

	checksum := hmacMD5(signingKey, concat(seqNum, message))[:8]
	if s.flags&ntlmFlagKeyExch != 0 {
		enc := make([]byte, 8)
		handle.XORKeyStream(enc, checksum)
		checksum = enc
	}
	buf = append(buf, checksum...)
	buf = append(buf, seqNum...)
	return buf, nil
}

func encryptRC4Key(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// buildEncryptedWinRMBody wraps sealed SOAP in the WinRM multipart/encrypted envelope
// (same layout as masterzen/winrm Encryption.encryptMessage).
func buildEncryptedWinRMBody(plain []byte, session *ntlmSecuritySession) ([]byte, string, error) {
	if session == nil {
		return nil, "", errors.New("no security session for seal")
	}
	if session.flags&ntlmFlagSeal == 0 && session.flags&ntlmFlagSign == 0 {
		return nil, "", errors.New("negotiated flags lack sign/seal")
	}
	sealed, sig, err := session.Wrap(plain)
	if err != nil {
		return nil, "", fmt.Errorf("ntlm wrap: %w", err)
	}
	// wire: signatureLength(4 LE) || signature || sealed
	stream := new(bytes.Buffer)
	if err := binary.Write(stream, binary.LittleEndian, uint32(len(sig))); err != nil {
		return nil, "", err
	}
	stream.Write(sig)
	stream.Write(sealed)

	payload := bytes.Join([][]byte{
		[]byte(winrmMIMEBoundary),
		[]byte("\r\n"),
		[]byte("\tContent-Type: " + winrmSPNEGOProtocol + "\r\n"),
		[]byte(fmt.Sprintf("\tOriginalContent: type=%s;Length=%d\r\n", winrmSOAPContent, len(plain))),
		[]byte(winrmMIMEBoundary),
		[]byte("\r\n"),
		[]byte("\tContent-Type: application/octet-stream\r\n"),
		stream.Bytes(),
	}, nil)
	payload = append(payload, []byte(winrmMIMEBoundary)...)
	payload = append(payload, []byte("--\r\n")...)

	ct := fmt.Sprintf(`multipart/encrypted;protocol="%s";boundary="Encrypted Boundary"`, winrmSPNEGOProtocol)
	return payload, ct, nil
}

// parseEncryptedWinRMBody decrypts a WinRM multipart encrypted response.
// Permissive: plain SOAP responses (no SPNEGO protocol / no boundary) are returned as-is.
// Length mismatches are ignored when unwrap succeeds (some hosts pad or mis-report Length=).
func parseEncryptedWinRMBody(body []byte, contentType string, session *ntlmSecuritySession) ([]byte, error) {
	if session == nil {
		return body, nil
	}
	looksEncrypted := strings.Contains(contentType, winrmSPNEGOProtocol) ||
		strings.Contains(contentType, "multipart/encrypted") ||
		bytes.Contains(body, []byte("Encrypted Boundary"))
	if !looksEncrypted {
		// Plain SOAP (AllowUnencrypted or non-encrypted response).
		return body, nil
	}

	parts := splitMIMEEncrypted(body)
	var out []byte
	for i := 0; i+1 < len(parts); i += 2 {
		header := parts[i]
		payload := parts[i+1]

		// Expected plaintext length from OriginalContent (advisory only).
		expectedLen := -1
		if idx := bytes.Index(header, []byte("Length=")); idx >= 0 {
			rest := header[idx+len("Length="):]
			rest = bytes.TrimSpace(rest)
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if j > 0 {
				if n, err := strconv.Atoi(string(rest[:j])); err == nil {
					expectedLen = n
				}
			}
		}

		closing := []byte(winrmMIMEBoundary + "--\r\n")
		if bytes.HasSuffix(payload, closing) {
			payload = payload[:len(payload)-len(closing)]
		}
		// Tolerate with or without leading tab on Content-Type line.
		encryptedData := bytes.ReplaceAll(payload, []byte("\tContent-Type: application/octet-stream\r\n"), nil)
		encryptedData = bytes.ReplaceAll(encryptedData, []byte("Content-Type: application/octet-stream\r\n"), nil)
		if len(encryptedData) < 4 {
			return nil, errors.New("encrypted payload too short")
		}
		sigLen := int(binary.LittleEndian.Uint32(encryptedData[:4]))
		if sigLen == 0 || 4+sigLen > len(encryptedData) {
			return nil, fmt.Errorf("invalid signature length %d", sigLen)
		}
		sig := encryptedData[4 : 4+sigLen]
		cipherText := encryptedData[4+sigLen:]
		plain, err := session.Unwrap(cipherText, sig)
		if err != nil {
			return nil, fmt.Errorf("ntlm unwrap: %w", err)
		}
		// Length= is advisory; only reject if wildly off and non-SOAP-looking.
		if expectedLen >= 0 && len(plain) != expectedLen {
			if !looksLikeSOAP(plain) {
				return nil, fmt.Errorf("decrypted length %d != expected %d", len(plain), expectedLen)
			}
		}
		out = append(out, plain...)
	}
	if len(out) == 0 {
		// Encrypted CT but unparseable MIME — fall back to raw body for caller soft-handle.
		if looksLikeSOAP(body) {
			return body, nil
		}
		return nil, errors.New("no encrypted parts in response")
	}
	return out, nil
}

func looksLikeSOAP(b []byte) bool {
	s := string(b)
	if len(s) > 512 {
		s = s[:512]
	}
	ls := strings.ToLower(s)
	return strings.Contains(ls, "envelope") || strings.Contains(ls, "soap") || strings.Contains(ls, "<?xml")
}

func splitMIMEEncrypted(body []byte) [][]byte {
	// Split on "--Encrypted Boundary\r\n" and drop empty segments.
	sep := []byte(winrmMIMEBoundary + "\r\n")
	raw := bytes.Split(body, sep)
	var parts [][]byte
	for _, p := range raw {
		if len(p) == 0 {
			continue
		}
		// Final "--\r\n" only segment
		if bytes.Equal(bytes.TrimSpace(p), []byte("--")) || bytes.HasPrefix(p, []byte("--")) {
			continue
		}
		parts = append(parts, p)
	}
	return parts
}

// canSeal reports whether we should attempt WinRM SPNEGO message encryption.
// Permissive: Seal or Sign is enough to try (Sign-only still builds a session;
// hosts that need real encryption almost always grant Seal as well).
func canSeal(flags uint32) bool {
	return flags&ntlmFlagSeal != 0 || flags&ntlmFlagSign != 0
}
