package ad

// Pre-defined LDAP query types for AD enumeration.
var queryFilters = map[string]string{
	"kerberoastable":          "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
	"asrep_roastable":         "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",

	"computers":               "(objectCategory=computer)",
	"dcs":                     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
	"gpos":                    "(objectClass=groupPolicyContainer)",
	"trusts":                  "(objectClass=trustedDomain)",
	"unconstrained_delegation": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
	"constrained_delegation":   "(msDS-AllowedToDelegateTo=*)",
	// Users with free-text notes often used as secret stashes (Support-style info=password).
	"interesting": "(&(objectCategory=person)(objectClass=user)(|(info=*)(description=*)(comment=*)))",
	"secrets":     "(&(objectCategory=person)(objectClass=user)(|(info=*)(description=*)(comment=*)))",
	"users":                   "(&(objectCategory=person)(objectClass=user))",
	"groups":                  "(objectCategory=group)",
	"admins":                  "(&(objectCategory=person)(adminCount=1))",
	// RBCD-related: accounts that already have an allowed-to-act blob set.
	"rbcd": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
}

// DefaultAttributes are the attributes to retrieve for each query type.
var defaultAttributes = map[string][]string{
	"kerberoastable":          {"sAMAccountName", "servicePrincipalName", "distinguishedName", "memberOf"},
	"asrep_roastable":         {"sAMAccountName", "distinguishedName", "userAccountControl"},
	"domain_admins":           {"sAMAccountName", "distinguishedName", "memberOf", "lastLogon"},
	"computers":               {"dNSHostName", "operatingSystem", "operatingSystemVersion", "distinguishedName"},
	"dcs":                     {"dNSHostName", "operatingSystem", "distinguishedName"},
	"gpos":                    {"displayName", "gPCFileSysPath", "distinguishedName"},
	"trusts":                  {"cn", "trustDirection", "trustType", "trustAttributes"},
	"unconstrained_delegation": {"dNSHostName", "sAMAccountName", "distinguishedName"},
	"constrained_delegation":   {"dNSHostName", "sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"},
	"interesting":             {"sAMAccountName", "distinguishedName", "info", "description", "comment", "memberOf"},
	"secrets":                 {"sAMAccountName", "distinguishedName", "info", "description", "comment", "memberOf"},
	"users":                   {"sAMAccountName", "distinguishedName", "memberOf", "lastLogon", "info", "description"},
	"groups":                  {"sAMAccountName", "distinguishedName", "member"},
	"admins":                  {"sAMAccountName", "distinguishedName", "memberOf", "adminCount"},
	"rbcd":                    {"sAMAccountName", "dNSHostName", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"},
}
