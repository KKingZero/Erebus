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
)

type EventCallback func(event *pb.Event)

type Dispatcher struct {
	sessions    *sessions.Manager
	store       *db.Store
	pending     *PendingTasks
	onEvent     EventCallback
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

// HandleResult processes a task result from an implant.
func (d *Dispatcher) HandleResult(result *pb.TaskResult) {
	log.Printf("[dispatcher] task %s result: success=%v", result.TaskId, result.Success)

	if d.store != nil {
		d.store.CompleteTask(result.TaskId, result.Success, result.Data, result.Error, result.ExecutionTimeMs)
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
