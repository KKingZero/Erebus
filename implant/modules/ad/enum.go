package ad

import (
	"context"
	"fmt"
	"strings"

	ldaplib "github.com/go-ldap/ldap/v3"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&LDAPEnumModule{})
}

type LDAPEnumModule struct{}

func (m *LDAPEnumModule) Name() string        { return "ldap_enum" }
func (m *LDAPEnumModule) Description() string { return "LDAP Active Directory enumeration" }

func (m *LDAPEnumModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.LDAPEnumConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal LDAP config: %w", err)
	}

	result, err := runLDAPEnum(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}

func runLDAPEnum(_ context.Context, cfg *pb.LDAPEnumConfig) (*pb.LDAPEnumResult, error) {
	if cfg.TargetDc == "" {
		return nil, fmt.Errorf("target_dc required")
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	// Connect to LDAP
	addr := cfg.TargetDc
	if !strings.Contains(addr, ":") {
		addr = addr + ":389"
	}

	conn, err := ldaplib.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// Authenticate: prefer NTLM hash (PTH), else simple bind with password.
	if cfg.NtlmHash != "" {
		if cfg.Username == "" {
			return nil, fmt.Errorf("username required with ntlm_hash")
		}
		domain, user := splitLDAPUser(cfg.Username, cfg.Domain)
		hash := normalizeLDAPHash(cfg.NtlmHash)
		if err := conn.NTLMBindWithHash(domain, user, hash); err != nil {
			return nil, fmt.Errorf("LDAP NTLM bind (hash): %w", err)
		}
	} else if cfg.Username != "" && cfg.Password != "" {
		bindDN := cfg.Username
		if !strings.Contains(bindDN, "=") {
			// Convert DOMAIN\user or user@domain to UPN-style for simple bind
			user := cfg.Username
			if strings.Contains(user, `\`) {
				parts := strings.SplitN(user, `\`, 2)
				user = parts[1]
			}
			bindDN = fmt.Sprintf("%s@%s", user, cfg.Domain)
		}
		if err := conn.Bind(bindDN, cfg.Password); err != nil {
			// Fallback: NTLM bind with password (works when simple bind is restricted)
			domain, user := splitLDAPUser(cfg.Username, cfg.Domain)
			if nerr := conn.NTLMBind(domain, user, cfg.Password); nerr != nil {
				return nil, fmt.Errorf("LDAP bind: %w (ntlm fallback: %v)", err, nerr)
			}
		}
	}

	// Build base DN from domain
	baseDN := domainToBaseDN(cfg.Domain)

	// Build search filter
	filter := cfg.CustomFilter
	if filter == "" {
		var err error
		filter, err = BuildLDAPFilter(cfg.QueryType, baseDN)
		if err != nil {
			return nil, err
		}
	}

	// Determine attributes
	attrs := cfg.Attributes
	if len(attrs) == 0 {
		attrs = defaultAttributes[cfg.QueryType]
	}
	if len(attrs) == 0 {
		attrs = []string{"*"}
	}

	searchReq := ldaplib.NewSearchRequest(
		baseDN,
		ldaplib.ScopeWholeSubtree,
		ldaplib.NeverDerefAliases,
		0, 0, false,
		filter,
		attrs,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	result := &pb.LDAPEnumResult{
		Domain:       cfg.Domain,
		Dc:           cfg.TargetDc,
		QueryType:    cfg.QueryType,
		TotalResults: int32(len(sr.Entries)),
	}

	for _, entry := range sr.Entries {
		ldapEntry := &pb.LDAPEntry{
			Dn:         entry.DN,
			Attributes: make(map[string]*pb.LDAPValues),
		}
		for _, attr := range entry.Attributes {
			ldapEntry.Attributes[attr.Name] = &pb.LDAPValues{
				Values: attr.Values,
			}
		}
		result.Entries = append(result.Entries, ldapEntry)
	}

	result.NextSuggestedActions = suggestions.ForLDAPEnum(result)
	return result, nil
}

// BuildLDAPFilter returns the LDAP filter for a query type and domain base DN.
func BuildLDAPFilter(queryType, baseDN string) (string, error) {
	if queryType == "domain_admins" {
		return fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,%s))", baseDN), nil
	}
	filter, ok := queryFilters[queryType]
	if !ok {
		return "", fmt.Errorf("unknown query type: %s (available: %s)", queryType, availableQueryTypes())
	}
	return filter, nil
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

func splitLDAPUser(username, domain string) (dom, user string) {
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
	// NTLM domain is often NetBIOS; strip DNS suffix first label as best effort.
	if dom != "" && strings.Contains(dom, ".") {
		dom = strings.SplitN(dom, ".", 2)[0]
	}
	return dom, user
}

// normalizeLDAPHash returns NT hash hex for go-ldap NTLMBindWithHash.
func normalizeLDAPHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		hash = parts[len(parts)-1]
	}
	if len(hash) == 64 {
		hash = hash[32:]
	}
	return strings.ToLower(hash)
}

func availableQueryTypes() string {
	types := make([]string, 0, len(queryFilters))
	for k := range queryFilters {
		types = append(types, k)
	}
	return strings.Join(types, ", ")
}

// EnumKerberoastable queries LDAP for kerberoastable accounts and returns their SPNs.
func EnumKerberoastable(conn *ldaplib.Conn, baseDN string) ([]struct{ SAM, SPN string }, error) {
	filter := queryFilters["kerberoastable"]
	sr, err := conn.Search(ldaplib.NewSearchRequest(
		baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	))
	if err != nil {
		return nil, err
	}

	var results []struct{ SAM, SPN string }
	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			results = append(results, struct{ SAM, SPN string }{SAM: sam, SPN: spn})
		}
	}
	return results, nil
}

// EnumASREPRoastable queries LDAP for accounts with DONT_REQ_PREAUTH set.
func EnumASREPRoastable(conn *ldaplib.Conn, baseDN string) ([]string, error) {
	filter := queryFilters["asrep_roastable"]
	sr, err := conn.Search(ldaplib.NewSearchRequest(
		baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"sAMAccountName"},
		nil,
	))
	if err != nil {
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		users = append(users, entry.GetAttributeValue("sAMAccountName"))
	}
	return users, nil
}
