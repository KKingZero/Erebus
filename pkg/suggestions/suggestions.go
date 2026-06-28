package suggestions

import (
	"fmt"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

const maxActions = 5

// Cap limits suggestion count for LLM context.
func Cap(actions []string) []string {
	if len(actions) <= maxActions {
		return actions
	}
	return actions[:maxActions]
}

// ForLDAPEnum derives follow-on actions from LDAP enumeration results.
func ForLDAPEnum(r *pb.LDAPEnumResult) []string {
	if r == nil {
		return nil
	}
	var out []string
	qt := strings.ToLower(r.QueryType)

	if r.TotalResults == 0 {
		switch qt {
		case "kerberoastable":
			out = append(out, "ldap_enum query_type=asrep_roastable")
		case "asrep_roastable":
			out = append(out, "ldap_enum query_type=users")
		default:
			out = append(out, "ldap_enum query_type=kerberoastable", "ldap_enum query_type=computers")
		}
		return Cap(out)
	}

	switch qt {
	case "kerberoastable":
		out = append(out, fmt.Sprintf("kerberoast domain=%s target_dc=%s (requires domain creds)", r.Domain, r.Dc))
		for i, e := range r.Entries {
			if i >= 3 {
				break
			}
			sam := ldapAttr(e, "sAMAccountName")
			spn := firstLDAPAttr(e, "servicePrincipalName")
			if sam != "" && spn != "" {
				out = append(out, fmt.Sprintf("kerberoast target SPN %s (%s)", spn, sam))
			}
		}
	case "asrep_roastable":
		out = append(out, fmt.Sprintf("asreproast domain=%s target_dc=%s", r.Domain, r.Dc))
		for i, e := range r.Entries {
			if i >= 3 {
				break
			}
			if sam := ldapAttr(e, "sAMAccountName"); sam != "" {
				out = append(out, fmt.Sprintf("asreproast candidate user=%s", sam))
			}
		}
	case "dcs", "domain_controllers":
		out = append(out,
			fmt.Sprintf("ldap_enum query_type=kerberoastable domain=%s target_dc=%s", r.Domain, r.Dc),
		)
		for i, e := range r.Entries {
			if i >= 2 {
				break
			}
			host := ldapAttr(e, "dNSHostName")
			if host == "" {
				host = ldapAttr(e, "sAMAccountName")
			}
			if host != "" {
				out = append(out, fmt.Sprintf("portscan target=%s ports=[88,389,445,5985]", host))
			}
		}
	case "domain_admins", "admins":
		out = append(out, "high-value targets found — consider creds_dump method=lsass if justified")
		for i, e := range r.Entries {
			if i >= 3 {
				break
			}
			if sam := ldapAttr(e, "sAMAccountName"); sam != "" {
				out = append(out, fmt.Sprintf("lateral_move target=<host> username=%s (after cred recovery)", sam))
			}
		}
	case "computers":
		for i, e := range r.Entries {
			if i >= 2 {
				break
			}
			if host := ldapAttr(e, "dNSHostName"); host != "" {
				out = append(out, fmt.Sprintf("portscan target=%s ports=[445,5985,3389]", host))
			}
		}
	case "trusts":
		out = append(out, "review trust relationships for cross-domain attack paths")
	default:
		out = append(out,
			fmt.Sprintf("ldap_enum query_type=kerberoastable domain=%s target_dc=%s", r.Domain, r.Dc),
			fmt.Sprintf("ldap_enum query_type=domain_admins domain=%s target_dc=%s", r.Domain, r.Dc),
		)
	}

	return Cap(out)
}

// ForKerberoast derives follow-on actions from kerberoast results.
func ForKerberoast(r *pb.KerberoastResult) []string {
	if r == nil || len(r.Hashes) == 0 {
		return Cap([]string{"ldap_enum query_type=kerberoastable to find more SPNs"})
	}
	var out []string
	out = append(out, "crack offline: hashcat -m 13100 (or 19600/19700 for AES)")
	for i, h := range r.Hashes {
		if i >= 2 {
			break
		}
		if h.SamAccountName != "" {
			out = append(out, fmt.Sprintf("after crack: lateral_move with user=%s", h.SamAccountName))
		}
	}
	return Cap(out)
}

// ForASREPRoast derives follow-on actions from AS-REP roast results.
func ForASREPRoast(r *pb.ASREPRoastResult) []string {
	if r == nil || len(r.Hashes) == 0 {
		return Cap([]string{"ldap_enum query_type=asrep_roastable"})
	}
	var out []string
	out = append(out, "crack offline: hashcat -m 18200")
	for i, h := range r.Hashes {
		if i >= 2 {
			break
		}
		if h.Username != "" {
			out = append(out, fmt.Sprintf("after crack: lateral_move with user=%s", h.Username))
		}
	}
	return Cap(out)
}

// ForCredDump derives follow-on actions from credential dump results.
func ForCredDump(r *pb.CredDumpResult) []string {
	if r == nil || len(r.Credentials) == 0 {
		return nil
	}
	var out []string
	hasNTLM := false
	hasBrowser := false
	for _, c := range r.Credentials {
		ct := strings.ToLower(c.Type)
		if strings.Contains(ct, "ntlm") || strings.Contains(ct, "hash") || ct == "password" {
			hasNTLM = true
			if c.Username != "" {
				out = append(out, fmt.Sprintf("lateral_move method=wmi target=<host> username=%s", c.Username))
			}
		}
		if strings.Contains(ct, "browser") || strings.Contains(c.Source, "Chrome") || strings.Contains(c.Source, "Firefox") {
			hasBrowser = true
		}
	}
	if hasBrowser {
		out = append(out, "cloud_harvest provider=all")
	}
	if !hasNTLM && !hasBrowser {
		out = append(out, "review loot for usable credentials")
	}
	return Cap(out)
}

// ForPortscan derives follow-on actions from port scan results.
func ForPortscan(r *pb.NetPortscanResult) []string {
	if r == nil || len(r.Ports) == 0 {
		return nil
	}
	var host string
	hasLDAP, hasSMB, hasWinRM := false, false, false
	for _, p := range r.Ports {
		if !p.Open {
			continue
		}
		if host == "" {
			host = p.Host
		}
		switch p.Port {
		case 88, 389:
			hasLDAP = true
		case 445:
			hasSMB = true
		case 5985, 5986:
			hasWinRM = true
		}
	}
	if host == "" {
		return nil
	}
	var out []string
	if hasLDAP {
		out = append(out, fmt.Sprintf("ldap_enum target_dc=%s (discover domain from host)", host))
	}
	if hasSMB || hasWinRM {
		out = append(out, fmt.Sprintf("lateral_move method=winrm target=%s (requires creds)", host))
	}
	if hasSMB {
		out = append(out, fmt.Sprintf("lateral_move method=psexec target=%s (requires creds + payload)", host))
	}
	return Cap(out)
}

// ForCloudHarvest derives follow-on actions from cloud harvest results.
func ForCloudHarvest(r *pb.CloudHarvestResult) []string {
	if r == nil {
		return nil
	}
	if len(r.Tokens) == 0 && len(r.Credentials) == 0 {
		return Cap([]string{"cloud_harvest provider=all method=all"})
	}
	var out []string
	out = append(out, "list_loot to review captured cloud tokens")
	for i, t := range r.Tokens {
		if i >= 2 {
			break
		}
		if t.Provider != "" {
			out = append(out, fmt.Sprintf("enumerate %s resources with harvested %s token", t.Provider, t.TokenType))
		}
	}
	return Cap(out)
}

func ldapAttr(e *pb.LDAPEntry, name string) string {
	if e == nil || e.Attributes == nil {
		return ""
	}
	if v, ok := e.Attributes[name]; ok && len(v.Values) > 0 {
		return v.Values[0]
	}
	// case-insensitive fallback
	lower := strings.ToLower(name)
	for k, v := range e.Attributes {
		if strings.ToLower(k) == lower && len(v.Values) > 0 {
			return v.Values[0]
		}
	}
	return ""
}

func firstLDAPAttr(e *pb.LDAPEntry, name string) string {
	if e == nil || e.Attributes == nil {
		return ""
	}
	if v, ok := e.Attributes[name]; ok && len(v.Values) > 0 {
		return v.Values[0]
	}
	lower := strings.ToLower(name)
	for k, v := range e.Attributes {
		if strings.ToLower(k) == lower && len(v.Values) > 0 {
			return v.Values[0]
		}
	}
	return ""
}