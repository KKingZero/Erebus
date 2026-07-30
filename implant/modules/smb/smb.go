package smb

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"github.com/hirochachacha/go-smb2"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

const maxDownloadBytes = 10 << 20 // 10 MB

func init() {
	plugin.Global.Register(&SMBModule{})
}

// SMBModule is a remote SMB client (list shares, list dir, download).
type SMBModule struct{}

func (m *SMBModule) Name() string        { return "smb" }
func (m *SMBModule) Description() string { return "Remote SMB share list/list_dir/download" }

func (m *SMBModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.SMBClientConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal smb config: %w", err)
	}
	result, err := runSMB(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(result)
}

func runSMB(ctx context.Context, cfg *pb.SMBClientConfig) (*pb.SMBClientResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	action := strings.ToLower(strings.TrimSpace(cfg.Action))
	if action == "" {
		action = "list_shares"
	}

	session, err := dialSMB(cfg)
	if err != nil {
		return nil, err
	}
	defer session.Logoff()

	result := &pb.SMBClientResult{
		Action: action,
		Host:   cfg.Host,
		Share:  cfg.Share,
		Path:   cfg.Path,
	}

	switch action {
	case "list_shares", "shares":
		names, err := session.ListSharenames()
		if err != nil {
			return nil, fmt.Errorf("list shares: %w", err)
		}
		result.Names = names
		result.NextSuggestedActions = suggestions.ForSMB(result)
		return result, nil

	case "list_dir", "ls", "dir":
		if cfg.Share == "" {
			return nil, fmt.Errorf("share required for list_dir")
		}
		share, err := session.Mount(uncShare(cfg.Host, cfg.Share))
		if err != nil {
			return nil, fmt.Errorf("mount %s: %w", cfg.Share, err)
		}
		defer share.Umount()

		dir := normalizeSharePath(cfg.Path)
		entries, err := share.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("readdir %s: %w", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				name += "/"
			}
			result.Names = append(result.Names, name)
		}
		result.NextSuggestedActions = suggestions.ForSMB(result)
		return result, nil

	case "download", "get":
		if cfg.Share == "" {
			return nil, fmt.Errorf("share required for download")
		}
		if cfg.Path == "" {
			return nil, fmt.Errorf("path required for download")
		}
		share, err := session.Mount(uncShare(cfg.Host, cfg.Share))
		if err != nil {
			return nil, fmt.Errorf("mount %s: %w", cfg.Share, err)
		}
		defer share.Umount()

		filePath := normalizeSharePath(cfg.Path)
		f, err := share.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", filePath, err)
		}
		defer f.Close()

		limited := io.LimitReader(f, maxDownloadBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filePath, err)
		}
		if len(data) > maxDownloadBytes {
			return nil, fmt.Errorf("file too large: max %d bytes", maxDownloadBytes)
		}
		result.FileData = data
		result.FileSize = int64(len(data))
		result.Path = filePath
		result.NextSuggestedActions = suggestions.ForSMB(result)
		return result, nil

	default:
		return nil, fmt.Errorf("unknown smb action %q (list_shares|list_dir|download)", action)
	}
}

func dialSMB(cfg *pb.SMBClientConfig) (*smb2.Session, error) {
	addr := cfg.Host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "445")
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smb connect %s: %w", addr, err)
	}

	initiator, err := smbInitiator(cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	s, err := (&smb2.Dialer{Initiator: initiator}).Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smb auth: %w", err)
	}
	return s, nil
}

func smbInitiator(cfg *pb.SMBClientConfig) (*smb2.NTLMInitiator, error) {
	if cfg.Anonymous || (cfg.Username == "" && cfg.Password == "" && cfg.NtlmHash == "") {
		return &smb2.NTLMInitiator{}, nil
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("username required (or set anonymous)")
	}
	init := &smb2.NTLMInitiator{
		User:     cfg.Username,
		Domain:   cfg.Domain,
		Password: cfg.Password,
	}
	if cfg.NtlmHash != "" {
		h, err := parseNTHash(cfg.NtlmHash)
		if err != nil {
			return nil, err
		}
		init.Hash = h
		init.Password = ""
	} else if cfg.Password == "" {
		return nil, fmt.Errorf("password or ntlm_hash required (or set anonymous)")
	}
	// Strip DOMAIN\ from user if domain already set
	if strings.Contains(init.User, `\`) {
		parts := strings.SplitN(init.User, `\`, 2)
		if init.Domain == "" {
			init.Domain = parts[0]
		}
		init.User = parts[1]
	}
	return init, nil
}

func parseNTHash(hashHex string) ([]byte, error) {
	hashHex = strings.TrimSpace(strings.ToLower(hashHex))
	if strings.Contains(hashHex, ":") {
		parts := strings.SplitN(hashHex, ":", 2)
		hashHex = parts[0] + parts[1]
	}
	if len(hashHex) == 32 {
		hashHex = "aad3b435b51404eeaad3b435b51404ee" + hashHex
	}
	if len(hashHex) != 64 {
		return nil, fmt.Errorf("ntlm_hash must be 32 or 64 hex characters")
	}
	return hex.DecodeString(hashHex)
}

func uncShare(host, share string) string {
	share = strings.Trim(share, `\`)
	return `\\` + host + `\` + share
}

func normalizeSharePath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	p = strings.TrimPrefix(p, `\`)
	if p == "" || p == "." {
		return "."
	}
	// go-smb2 uses forward-slash-ish paths internally; Keep backslash — library accepts both.
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}
