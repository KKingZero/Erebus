package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"github.com/KKingZero/erebus-exploit-framwork/server/builder"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// validOS and validArch are whitelists for build targets.
var (
	validOS        = map[string]bool{"windows": true, "linux": true, "darwin": true}
	validArch      = map[string]bool{"amd64": true, "arm64": true}
	validTransport = map[string]bool{"https": true, "dns": true}
	validLanguage  = map[string]bool{"go": true, "c": true, "": true}
)

// resolveProjectRoot finds the Erebus repo root (directory containing go.mod).
func resolveProjectRoot() string {
	if v := os.Getenv("EREBUS_ROOT"); v != "" {
		if _, err := os.Stat(filepath.Join(v, "go.mod")); err == nil {
			return v
		}
	}
	candidates := []string{"."}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	for _, start := range candidates {
		dir, err := filepath.Abs(start)
		if err != nil {
			continue
		}
		for i := 0; i < 8; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				// Prefer roots that look like Erebus (cmd/implant exists).
				if _, err := os.Stat(filepath.Join(dir, "cmd", "implant")); err == nil {
					return dir
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "."
}

// operatorFromContext extracts the operator identity from the mTLS client certificate.
func operatorFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if len(tlsInfo.State.PeerCertificates) > 0 {
		return tlsInfo.State.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// GRPCService implements the ErebusC2 gRPC service.
type GRPCService struct {
	pb.UnimplementedErebusC2Server
	ts *Teamserver
}

func NewGRPCService(ts *Teamserver) *GRPCService {
	return &GRPCService{ts: ts}
}

// --- Listeners ---

func (s *GRPCService) StartListener(ctx context.Context, req *pb.StartListenerRequest) (*pb.StartListenerResponse, error) {
	op := operatorFromContext(ctx)
	log.Printf("[audit] op=StartListener operator=%q name=%q", op, req.GetConfig().GetName())
	if req.Config == nil {
		return &pb.StartListenerResponse{Success: false, Error: "config required"}, nil
	}

	l, err := s.ts.CreateListener(req.Config)
	if err != nil {
		return &pb.StartListenerResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.StartListenerResponse{
		Success: true,
		Status:  l.Status(),
	}, nil
}

func (s *GRPCService) StopListener(ctx context.Context, req *pb.StopListenerRequest) (*pb.StopListenerResponse, error) {
	op := operatorFromContext(ctx)
	log.Printf("[audit] op=StopListener operator=%q id=%q", op, req.GetId())
	if err := s.ts.Listeners.Stop(req.Id); err != nil {
		return &pb.StopListenerResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.StopListenerResponse{Success: true}, nil
}

func (s *GRPCService) ListListeners(ctx context.Context, req *pb.ListListenersRequest) (*pb.ListListenersResponse, error) {
	return &pb.ListListenersResponse{Listeners: s.ts.Listeners.List()}, nil
}

// --- Sessions ---

func (s *GRPCService) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	sessions := s.ts.Sessions.List()
	var infos []*pb.SessionInfo
	for _, sess := range sessions {
		infos = append(infos, sess.ToProto())
	}
	return &pb.ListSessionsResponse{Sessions: infos}, nil
}

func (s *GRPCService) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.GetSessionResponse, error) {
	sess, ok := s.ts.Sessions.Get(req.SessionId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session not found: %s", req.SessionId)
	}
	return &pb.GetSessionResponse{Session: sess.ToProto()}, nil
}

func (s *GRPCService) KillSession(ctx context.Context, req *pb.KillSessionRequest) (*pb.KillSessionResponse, error) {
	op := operatorFromContext(ctx)
	log.Printf("[audit] op=KillSession operator=%q session=%q", op, req.GetSessionId())
	// Enqueue EXIT task so implant terminates on next beacon
	s.ts.Dispatcher.Dispatch(ctx, req.SessionId, pb.TaskType_TASK_EXIT, nil, 0, false)

	if err := s.ts.Sessions.Kill(req.SessionId); err != nil {
		return &pb.KillSessionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.KillSessionResponse{Success: true}, nil
}

// --- Tasks ---

func (s *GRPCService) checkTaskApproval(ctx context.Context, sessionID string, taskType pb.TaskType, data []byte) error {
	if s.ts.Approval == nil {
		return nil
	}
	needs := s.ts.Approval.RequiresApproval(taskType)
	moduleName := ""
	if !needs && taskType == pb.TaskType_TASK_MODULE {
		moduleName = approval.ModuleNameFromTaskData(data)
		needs = moduleName != "" && s.ts.Approval.RequiresModuleApproval(moduleName)
	}
	if !needs {
		return nil
	}
	requester := operatorFromContext(ctx)
	if requester == "" {
		return status.Errorf(codes.PermissionDenied, "operator identity required for high-risk tasks")
	}
	if s.ts.Approval.RequiresApproval(taskType) {
		desc := fmt.Sprintf("%s on session %s", taskType.String(), sessionID)
		approved, err := s.ts.Approval.RequestApproval(ctx, sessionID, taskType, desc, requester)
		if err != nil {
			return err
		}
		if !approved {
			return status.Errorf(codes.PermissionDenied, "task denied by operator")
		}
		return nil
	}
	desc := fmt.Sprintf("module %s on session %s", moduleName, sessionID)
	approved, err := s.ts.Approval.RequestModuleApproval(ctx, sessionID, moduleName, desc, requester)
	if err != nil {
		return err
	}
	if !approved {
		return status.Errorf(codes.PermissionDenied, "task denied by operator")
	}
	return nil
}

func (s *GRPCService) ExecuteTask(ctx context.Context, req *pb.ExecuteTaskRequest) (*pb.ExecuteTaskResponse, error) {
	op := operatorFromContext(ctx)
	log.Printf("[audit] op=ExecuteTask operator=%q session=%q type=%s", op, req.GetSessionId(), req.GetTaskType().String())
	if err := s.checkTaskApproval(ctx, req.SessionId, req.TaskType, req.Data); err != nil {
		return nil, err
	}

	// Reverse SOCKS: start/stop teamserver-side listener bound to the session.
	if s.ts.Socks != nil {
		switch req.TaskType {
		case pb.TaskType_TASK_SOCKS_START:
			port := uint32(1080)
			if len(req.Data) > 0 {
				var st pb.SocksStartTask
				if err := proto.Unmarshal(req.Data, &st); err == nil && st.Port > 0 {
					port = st.Port
				}
			}
			if _, err := s.ts.Socks.StartForSession(req.SessionId, port); err != nil {
				return nil, status.Errorf(codes.Internal, "start socks: %v", err)
			}
		case pb.TaskType_TASK_SOCKS_STOP:
			_ = s.ts.Socks.StopForSession(req.SessionId)
		}
	}

	taskID, result, err := s.ts.Dispatcher.Dispatch(ctx, req.SessionId, req.TaskType, req.Data, req.TimeoutMs, req.Wait)
	if err != nil {
		return nil, err
	}
	return &pb.ExecuteTaskResponse{
		TaskId: taskID,
		Result: result,
	}, nil
}

func (s *GRPCService) GetTaskResult(ctx context.Context, req *pb.GetTaskResultRequest) (*pb.GetTaskResultResponse, error) {
	result, pending, err := s.ts.Dispatcher.GetResult(req.TaskId)
	if err != nil {
		return nil, err
	}
	return &pb.GetTaskResultResponse{
		Result:  result,
		Pending: pending,
	}, nil
}

func (s *GRPCService) ListTasks(ctx context.Context, req *pb.ListTasksRequest) (*pb.ListTasksResponse, error) {
	rows, err := s.ts.Store.ListTasksBySession(req.SessionId)
	if err != nil {
		return nil, err
	}

	// Resolve the real implant ID from the session
	implantID := req.SessionId // fallback
	if sess, ok := s.ts.Sessions.Get(req.SessionId); ok {
		implantID = sess.ImplantID
	} else if row, err := s.ts.Store.GetSession(req.SessionId); err == nil {
		implantID = row.ImplantID
	}

	var tasks []*pb.Task
	for _, row := range rows {
		tasks = append(tasks, &pb.Task{
			TaskId:    row.TaskID,
			ImplantId: implantID,
			TaskType:  pb.TaskType(row.TaskType),
			Data:      row.Data,
			TimeoutMs: row.TimeoutMs,
		})
	}
	return &pb.ListTasksResponse{Tasks: tasks}, nil
}

// --- Events ---

func (s *GRPCService) Subscribe(req *pb.SubscribeRequest, stream pb.ErebusC2_SubscribeServer) error {
	ch, unsub := s.ts.Events.Subscribe()
	defer unsub()

	log.Printf("[grpc] new event subscriber")

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// --- Builder ---

func (s *GRPCService) GenerateImplant(ctx context.Context, req *pb.GenerateImplantRequest) (*pb.GenerateImplantResponse, error) {
	// H9: Validate inputs against whitelists
	targetOS := req.Os
	if targetOS == "" {
		targetOS = "windows"
	}
	if !validOS[targetOS] {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported OS: %s (available: windows, linux, darwin)", targetOS),
		}, nil
	}

	targetArch := req.Arch
	if targetArch == "" {
		targetArch = "amd64"
	}
	if !validArch[targetArch] {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported arch: %s (available: amd64, arm64)", targetArch),
		}, nil
	}

	transport := req.Transport
	if transport == "" {
		transport = "https"
	}
	if !validTransport[transport] {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported transport: %s (available: https, dns)", transport),
		}, nil
	}

	// Validate callback URLs
	for _, cb := range req.Callbacks {
		parsed, err := url.ParseRequestURI(cb)
		if err != nil {
			return &pb.GenerateImplantResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid callback URL %q: %v", cb, err),
			}, nil
		}
		if transport == "https" && parsed.Scheme != "https" {
			return &pb.GenerateImplantResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid callback URL %q: https transport requires https callback URL", cb),
			}, nil
		}
	}

	language := req.Language
	if language == "" {
		language = "go"
	}
	if !validLanguage[language] {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported language: %s (available: go, c)", language),
		}, nil
	}

	format := builder.FormatEXE
	switch req.Format {
	case "shellcode":
		format = builder.FormatShellcode
	case "dll":
		format = builder.FormatDLL
	case "", "exe":
		format = builder.FormatEXE
	default:
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported format: %s (available: exe, dll, shellcode)", req.Format),
		}, nil
	}

	// Resolve ProjectRoot: EREBUS_ROOT, then walk up from cwd / executable for go.mod.
	projectRoot := resolveProjectRoot()

	// H11: Extract operator identity from mTLS context
	operator := operatorFromContext(ctx)

	if language == "c" && format != builder.FormatEXE {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   "C implant only supports exe format",
		}, nil
	}
	if language == "c" && (targetOS != "windows" || targetArch != "amd64") {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   "C implant only supports windows/amd64",
		}, nil
	}

	log.Printf("[audit] op=GenerateImplant operator=%q os=%s arch=%s transport=%s lang=%s",
		operator, targetOS, targetArch, transport, language)

	buildReq := &builder.BuildRequest{
		Language:    language,
		OS:          targetOS,
		Arch:        targetArch,
		Transport:   transport,
		Callbacks:   req.Callbacks,
		SleepMs:     req.SleepMs,
		JitterPct:   req.JitterPct,
		Garble:      req.Garble,
		CDNDomain:   req.CdnDomain,
		DNSDomain:   req.DnsDomain,
		DNSServer:   req.DnsServer,
		Format:      format,
		Operator:    operator,
		// Unique per-implant secret is generated inside Build; do not inject fleet PSK.
		ProjectRoot: projectRoot,
	}
	if language == "c" {
		buildReq.CACertPath = filepath.Join(s.ts.Config.DataDir, "ca-cert.pem")
	}

	result, err := builder.Build(buildReq)
	if err != nil {
		return &pb.GenerateImplantResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Persist sealed per-implant secret for auth / session-key wrap.
	if s.ts.Store != nil && result.ImplantID != "" && result.ImplantSecret != "" {
		if err := s.ts.RegisterImplantSecret(result.ImplantID, result.BuildID, operator, result.ImplantSecret, false); err != nil {
			log.Printf("[grpc] warning: failed to register implant secret: %v", err)
			return &pb.GenerateImplantResponse{
				Success: false,
				Error:   fmt.Sprintf("build ok but failed to register implant secret: %v", err),
			}, nil
		}
	}

	// H5: Log warning if build recording fails
	if s.ts.Store != nil {
		if err := builder.RecordBuild(s.ts.Store, buildReq, result); err != nil {
			log.Printf("[grpc] warning: failed to record build: %v", err)
		}
	}

	return &pb.GenerateImplantResponse{
		Success:  true,
		BuildId:  result.BuildID,
		Binary:   result.Binary,
		Filename: result.Filename,
		Format:   string(result.Format),
	}, nil
}

// RegisterImplantSecret stores a sealed per-implant PSK for manual/ldflags builds.
func (s *GRPCService) RegisterImplantSecret(ctx context.Context, req *pb.RegisterImplantSecretRequest) (*pb.RegisterImplantSecretResponse, error) {
	op := operatorFromContext(ctx)
	log.Printf("[audit] op=RegisterImplantSecret operator=%q implant_id=%q", op, req.GetImplantId())
	if req.GetImplantId() == "" || req.GetSecretHex() == "" {
		return &pb.RegisterImplantSecretResponse{
			Success: false,
			Error:   "implant_id and secret_hex required",
		}, nil
	}
	if op == "" {
		return &pb.RegisterImplantSecretResponse{
			Success: false,
			Error:   "operator identity required",
		}, nil
	}
	buildID := req.GetBuildId()
	if buildID == "" {
		buildID = "manual"
	}
	if err := s.ts.RegisterImplantSecret(req.ImplantId, buildID, op, req.SecretHex, true); err != nil {
		return &pb.RegisterImplantSecretResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.RegisterImplantSecretResponse{Success: true}, nil
}

// --- Loot ---

func (s *GRPCService) ListLoot(ctx context.Context, req *pb.ListLootRequest) (*pb.ListLootResponse, error) {
	rows, err := s.ts.Store.ListLoot(req.SessionId)
	if err != nil {
		return nil, err
	}
	var items []*pb.LootItem
	for _, row := range rows {
		items = append(items, &pb.LootItem{
			Id:        row.ID,
			Type:      row.Type,
			Source:    row.Source,
			SessionId: row.SessionID,
			Data:      row.Data,
			CreatedAt: row.CreatedAt.Unix(),
		})
	}
	return &pb.ListLootResponse{Items: items}, nil
}

func (s *GRPCService) GetLoot(ctx context.Context, req *pb.GetLootRequest) (*pb.GetLootResponse, error) {
	row, err := s.ts.Store.GetLoot(req.Id)
	if err != nil {
		return nil, err
	}
	return &pb.GetLootResponse{
		Item: &pb.LootItem{
			Id:        row.ID,
			Type:      row.Type,
			Source:    row.Source,
			SessionId: row.SessionID,
			Data:      row.Data,
			CreatedAt: row.CreatedAt.Unix(),
		},
	}, nil
}

// --- Approval Gates ---

func (s *GRPCService) ListPendingApprovals(ctx context.Context, req *pb.ListPendingApprovalsRequest) (*pb.ListPendingApprovalsResponse, error) {
	return &pb.ListPendingApprovalsResponse{
		Approvals: s.ts.Approval.ListPending(),
	}, nil
}

func (s *GRPCService) Approve(ctx context.Context, req *pb.ApproveRequest) (*pb.ApproveResponse, error) {
	approver := operatorFromContext(ctx)
	log.Printf("[audit] op=Approve operator=%q approval_id=%q", approver, req.GetApprovalId())
	if err := s.ts.Approval.Approve(req.ApprovalId, approver); err != nil {
		return &pb.ApproveResponse{Success: false}, err
	}
	return &pb.ApproveResponse{Success: true}, nil
}

func (s *GRPCService) Deny(ctx context.Context, req *pb.DenyRequest) (*pb.DenyResponse, error) {
	denier := operatorFromContext(ctx)
	log.Printf("[audit] op=Deny operator=%q approval_id=%q reason=%q", denier, req.GetApprovalId(), req.GetReason())
	if err := s.ts.Approval.Deny(req.ApprovalId, denier, req.Reason); err != nil {
		return &pb.DenyResponse{Success: false}, err
	}
	return &pb.DenyResponse{Success: true}, nil
}
