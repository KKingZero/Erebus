package sessions

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
)

func TestRegisterOrReconnectUpdatesMetadata(t *testing.T) {
	store, err := db.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	m := NewManager(store)

	sess1 := NewSession(&pb.Register{
		ImplantId: "implant-meta",
		Hostname:  "host-a",
		Username:  "alice",
		Pid:       100,
	}, "https", "10.0.0.1:443")
	sess1.SessionKey = []byte("key-a")

	id1, reconn, err := m.RegisterOrReconnect(sess1)
	if err != nil || reconn {
		t.Fatalf("first register: id=%s reconn=%v err=%v", id1, reconn, err)
	}

	sess2 := NewSession(&pb.Register{
		ImplantId: "implant-meta",
		Hostname:  "host-b",
		Username:  "bob",
		Pid:       200,
	}, "https", "10.0.0.2:443")
	sess2.SessionKey = []byte("key-b")

	id2, reconn, err := m.RegisterOrReconnect(sess2)
	if err != nil || !reconn {
		t.Fatalf("reconnect: id=%s reconn=%v err=%v", id2, reconn, err)
	}
	if id2 != id1 {
		t.Fatalf("expected same session id, got %s vs %s", id2, id1)
	}

	got, ok := m.Get(id1)
	if !ok {
		t.Fatal("session not found")
	}
	if got.Hostname != "host-b" || got.Username != "bob" || got.PID != 200 || got.RemoteAddr != "10.0.0.2:443" {
		t.Fatalf("metadata not updated: %+v", got)
	}

	row, err := store.GetSession(id1)
	if err != nil {
		t.Fatal(err)
	}
	if row.Hostname != "host-b" || row.Username != "bob" || row.PID != 200 || row.RemoteAddr != "10.0.0.2:443" {
		t.Fatalf("db metadata not updated: %+v", row)
	}
}

func TestKillDoesNotReviveOnUpdateCheckin(t *testing.T) {
	m := NewManager(nil)
	sess := NewSession(&pb.Register{ImplantId: "implant-kill", Hostname: "h"}, "https", "1.1.1.1:1")
	id, _, err := m.RegisterOrReconnect(sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Kill(id); err != nil {
		t.Fatal(err)
	}
	got, ok := m.Get(id)
	if !ok {
		t.Fatal("session missing")
	}
	got.UpdateCheckin()
	if got.IsAlive() {
		t.Fatal("operator-killed session must not revive on UpdateCheckin")
	}
	if !got.ShouldTerminate() {
		t.Fatal("expected ShouldTerminate after Kill")
	}
}

func TestMarkDeadAllowsReviveOnUpdateCheckin(t *testing.T) {
	sess := NewSession(&pb.Register{ImplantId: "implant-reaper", Hostname: "h"}, "https", "1.1.1.1:1")
	sess.MarkDead()
	if sess.IsAlive() {
		t.Fatal("expected dead after MarkDead")
	}
	if sess.ShouldTerminate() {
		t.Fatal("reaper MarkDead must not request terminate")
	}
	sess.UpdateCheckin()
	if !sess.IsAlive() {
		t.Fatal("reaper-dead session should revive on UpdateCheckin")
	}
}

func TestRegisterPrunesDeadSessionsForImplant(t *testing.T) {
	m := NewManager(nil)

	sess1 := NewSession(&pb.Register{ImplantId: "implant-prune", Hostname: "old"}, "https", "1.1.1.1:1")
	id1, _, err := m.RegisterOrReconnect(sess1)
	if err != nil {
		t.Fatal(err)
	}

	dead, ok := m.Get(id1)
	if !ok {
		t.Fatal("session missing")
	}
	dead.Kill()

	sess2 := NewSession(&pb.Register{ImplantId: "implant-prune", Hostname: "new"}, "https", "2.2.2.2:2")
	id2, reconn, err := m.RegisterOrReconnect(sess2)
	if err != nil || reconn {
		t.Fatalf("new register: id=%s reconn=%v err=%v", id2, reconn, err)
	}
	if id2 == id1 {
		t.Fatal("expected new session id after dead implant re-register")
	}

	if _, ok := m.Get(id1); ok {
		t.Fatal("dead session should be pruned from memory")
	}
	if len(m.List()) != 1 {
		t.Fatalf("expected 1 session in memory, got %d", len(m.List()))
	}
}