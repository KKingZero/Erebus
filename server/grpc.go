package server

import (
	"context"
	"fmt"
	"log"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

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
		return nil, fmt.Errorf("session not found: %s", req.SessionId)
	}
	return &pb.GetSessionResponse{Session: sess.ToProto()}, nil
}

func (s *GRPCService) KillSession(ctx context.Context, req *pb.KillSessionRequest) (*pb.KillSessionResponse, error) {
	// Enqueue EXIT task so implant terminates on next beacon
	s.ts.Dispatcher.Dispatch(ctx, req.SessionId, pb.TaskType_TASK_EXIT, nil, 0, false)

	if err := s.ts.Sessions.Kill(req.SessionId); err != nil {
		return &pb.KillSessionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.KillSessionResponse{Success: true}, nil
}

// --- Tasks ---

func (s *GRPCService) ExecuteTask(ctx context.Context, req *pb.ExecuteTaskRequest) (*pb.ExecuteTaskResponse, error) {
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

// --- Builder (stub for Phase 1) ---

func (s *GRPCService) GenerateImplant(ctx context.Context, req *pb.GenerateImplantRequest) (*pb.GenerateImplantResponse, error) {
	return &pb.GenerateImplantResponse{
		Success: false,
		Error:   "implant generation not yet implemented — use Makefile for Phase 1",
	}, nil
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
