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
	hashHex = strings.TrimSpace(hashHex)
	if hashHex == "" {
		return nil, fmt.Errorf("empty NTLM hash")
	}
	if len(hashHex) == 32 {
		hashHex = "aad3b435b51404eeaad3b435b51404ee" + hashHex
	}
	if len(hashHex) != 64 {
		return nil, fmt.Errorf("NTLM hash must be 32 or 64 hex characters")
	}
	return hex.DecodeString(hashHex)
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