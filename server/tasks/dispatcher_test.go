package tasks

import (
	"context"
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
)

func newTestDispatcher(t *testing.T) (*Dispatcher, *sessions.Manager, *db.Store) {
	t.Helper()

	store, err := db.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	mgr := sessions.NewManager(store)
	return NewDispatcher(mgr, store, nil), mgr, store
}

func registerTestSession(t *testing.T, mgr *sessions.Manager, implantID string) string {
	t.Helper()

	sess := sessions.NewSession(&pb.Register{
		ImplantId: implantID,
		Hostname:  "host-" + implantID,
		Username:  "tester",
		Os:        "linux",
		Arch:      "amd64",
	}, "https", "127.0.0.1:1")

	sessionID, _, err := mgr.RegisterOrReconnect(sess)
	if err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func TestHandleResultForSessionCompletesMatchingTask(t *testing.T) {
	dispatcher, mgr, store := newTestDispatcher(t)
	sessionID := registerTestSession(t, mgr, "implant-match")

	taskID, _, err := dispatcher.Dispatch(context.Background(), sessionID, pb.TaskType_TASK_PROCESS_LIST, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	dispatcher.HandleResultForSession(sessionID, &pb.TaskResult{
		TaskId:  taskID,
		Success: true,
		Data:    []byte("ok"),
	})

	row, err := store.GetTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if row.CompletedAt == nil {
		t.Fatal("expected matching-session result to complete task")
	}
}

func TestHandleResultForSessionRejectsCrossSessionTask(t *testing.T) {
	dispatcher, mgr, store := newTestDispatcher(t)
	sessionA := registerTestSession(t, mgr, "implant-a")
	sessionB := registerTestSession(t, mgr, "implant-b")

	taskID, _, err := dispatcher.Dispatch(context.Background(), sessionA, pb.TaskType_TASK_PROCESS_LIST, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	dispatcher.HandleResultForSession(sessionB, &pb.TaskResult{
		TaskId:  taskID,
		Success: true,
		Data:    []byte("wrong-session"),
	})

	row, err := store.GetTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if row.CompletedAt != nil {
		t.Fatal("cross-session result should not complete task")
	}
}

func TestHandleResultForSessionRejectsUnknownTask(t *testing.T) {
	dispatcher, mgr, _ := newTestDispatcher(t)
	sessionID := registerTestSession(t, mgr, "implant-unknown")

	dispatcher.HandleResultForSession(sessionID, &pb.TaskResult{
		TaskId:  "missing-task",
		Success: true,
		Data:    []byte("ignored"),
	})
}
