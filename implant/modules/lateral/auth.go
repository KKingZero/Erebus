package lateral

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func formatDomainUser(domain, user string) string {
	if user == "" || domain == "" {
		return user
	}
	if strings.Contains(user, `\`) || strings.Contains(user, `@`) {
		return user
	}
	return domain + `\` + user
}

func parseNTLMHash(hashHex string) ([]byte, error) {
	hashHex, err := normalizeNTHashHex(hashHex)
	if err != nil {
		return nil, err
	}
	// go-smb2 expects 32 raw bytes: LM(16)+NT(16) from 64 hex chars.
	if strings.Contains(hashHex, ":") {
		parts := strings.SplitN(hashHex, ":", 2)
		hashHex = parts[0] + parts[1]
	}
	if len(hashHex) == 32 {
		hashHex = "aad3b435b51404eeaad3b435b51404ee" + hashHex
	}
	if len(hashHex) != 64 {
		return nil, fmt.Errorf("NTLM hash must be 32 or 64 hex characters")
	}
	return hex.DecodeString(hashHex)
}

// normalizeNTHashHex accepts NT (32 hex), LM:NT (64 hex with colon), or 64 hex LM+NT.
// Returns a string suitable for ntlmssp.ProcessChallengeWithHash (NT or LM:NT).
func normalizeNTHashHex(hashHex string) (string, error) {
	hashHex = strings.TrimSpace(hashHex)
	if hashHex == "" {
		return "", fmt.Errorf("empty NTLM hash")
	}
	// Drop optional "nthash:" / "aad3...:" prefixes handled via colon split in ProcessChallengeWithHash.
	if strings.Contains(hashHex, ":") {
		parts := strings.Split(hashHex, ":")
		// LM:NT form — keep full string for ProcessChallengeWithHash
		if len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			return strings.ToLower(hashHex), nil
		}
		// take last segment if LM:NT or emptyLM:NT
		hashHex = parts[len(parts)-1]
	}
	hashHex = strings.ToLower(hashHex)
	if len(hashHex) == 64 {
		// concatenated LM+NT without colon
		return hashHex[:32] + ":" + hashHex[32:], nil
	}
	if len(hashHex) != 32 {
		return "", fmt.Errorf("NTLM hash must be 32 hex (NT) or 64 hex / LM:NT")
	}
	if _, err := hex.DecodeString(hashHex); err != nil {
		return "", fmt.Errorf("invalid NTLM hash hex: %w", err)
	}
	return hashHex, nil
}

// parseDomainUser splits DOMAIN\user or user@domain, falling back to domain arg.
func parseDomainUser(username, domain string) (dom, user string) {
	user = username
	dom = domain
	if strings.Contains(username, `\`) {
		parts := strings.SplitN(username, `\`, 2)
		return parts[0], parts[1]
	}
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		return parts[1], parts[0]
	}
	return dom, user
}

func smbInitiator(user, password, domain, ntlmHash string) (*smbAuth, error) {
	auth := &smbAuth{User: user, Domain: domain, Password: password}
	if ntlmHash != "" {
		h, err := parseNTLMHash(ntlmHash)
		if err != nil {
			return nil, err
		}
		auth.Hash = h
		auth.Password = ""
	} else if password == "" {
		return nil, fmt.Errorf("password or ntlm_hash required")
	}
	if user == "" {
		return nil, fmt.Errorf("username required")
	}
	return auth, nil
}

type smbAuth struct {
	User     string
	Domain   string
	Password string
	Hash     []byte
}