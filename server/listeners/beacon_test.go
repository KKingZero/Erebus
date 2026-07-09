package listeners

import (
	"testing"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
)

func TestHandleRegisterAndBeacon(t *testing.T) {
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}

	h := &BeaconHandler{
		Secret:      secret,
		Sessions:    sessions.NewManager(nil),
		ReplayCache: zcrypto.NewReplayCache(60 * time.Second),
	}

	ts := time.Now().Unix()
	reg := &pb.Register{
		ImplantId: "implant-1",
		Hostname:  "testhost",
		Username:  "tester",
		Os:        "windows",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-1", ts),
	}

	resp, err := HandleRegister(h, reg, "https", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !resp.Success || resp.SessionId == "" || len(resp.EncryptedSessionKey) == 0 {
		t.Fatalf("bad register response: %+v", resp)
	}

	sessionKey, err := zcrypto.AESDecrypt(secret, resp.EncryptedSessionKey)
	if err != nil {
		t.Fatal(err)
	}

	sess, ok := h.Sessions.Get(resp.SessionId)
	if !ok {
		t.Fatal("session missing")
	}
	sess.SessionKey = sessionKey

	sess.EnqueueTask(&pb.Task{
		TaskId:    "task-1",
		ImplantId: "implant-1",
		TaskType:  pb.TaskType_TASK_SHELL,
	})

	beaconTs := ts + 1
	beaconHmac := zcrypto.ComputeHMAC(secret, "implant-1", beaconTs)
	beaconResp, err := HandleBeacon(h, &pb.Beacon{
		ImplantId: "implant-1",
		SessionId: resp.SessionId,
		Timestamp: beaconTs,
		Hmac:      beaconHmac,
	})
	if err != nil {
		t.Fatalf("beacon: %v", err)
	}
	// NextCheckinMs 0 is valid: implant keeps build-time sleep (no server override).
	if beaconResp.NextCheckinMs < 0 {
		t.Fatalf("bad next checkin: %+v", beaconResp)
	}
	if len(beaconResp.EncryptedTasks) == 0 && len(beaconResp.Tasks) == 0 {
		t.Fatal("expected queued task in beacon response")
	}
}

func TestHandleBeaconRequeuesTasksOnEncryptFailure(t *testing.T) {
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}

	h := &BeaconHandler{
		Secret:      secret,
		Sessions:    sessions.NewManager(nil),
		ReplayCache: zcrypto.NewReplayCache(60 * time.Second),
	}

	ts := time.Now().Unix()
	reg := &pb.Register{
		ImplantId: "implant-2",
		Hostname:  "testhost",
		Username:  "tester",
		Os:        "windows",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-2", ts),
	}
	resp, err := HandleRegister(h, reg, "https", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	sess, ok := h.Sessions.Get(resp.SessionId)
	if !ok {
		t.Fatal("session missing")
	}
	sess.SessionKey = []byte("invalid-key") // force encrypt failure

	task := &pb.Task{TaskId: "task-retry", ImplantId: "implant-2", TaskType: pb.TaskType_TASK_SHELL}
	sess.EnqueueTask(task)

	beaconTs := ts + 1
	_, err = HandleBeacon(h, &pb.Beacon{
		ImplantId: "implant-2",
		SessionId: resp.SessionId,
		Timestamp: beaconTs,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-2", beaconTs),
	})
	if err != nil {
		t.Fatal(err)
	}

	requeued := sess.DrainTasks()
	if len(requeued) != 1 || requeued[0].TaskId != "task-retry" {
		t.Fatalf("expected requeued task, got %+v", requeued)
	}
}

func TestHandleRegisterReconnectRotatesKey(t *testing.T) {
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}

	sharedCache := zcrypto.NewReplayCache(60 * time.Second)
	h := &BeaconHandler{
		Secret:      secret,
		Sessions:    sessions.NewManager(nil),
		ReplayCache: sharedCache,
	}

	var eventCount int
	h.OnEvent = func(e *pb.Event) {
		if e.Type == pb.EventType_EVENT_SESSION_NEW {
			eventCount++
		}
	}

	ts := time.Now().Unix()
	reg := &pb.Register{
		ImplantId: "implant-reconnect",
		Hostname:  "testhost",
		Username:  "tester",
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-reconnect", ts),
	}

	resp1, err := HandleRegister(h, reg, "https", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	key1, err := zcrypto.AESDecrypt(secret, resp1.EncryptedSessionKey)
	if err != nil {
		t.Fatal(err)
	}

	ts2 := ts + 1
	reg2 := &pb.Register{
		ImplantId: "implant-reconnect",
		Hostname:  "reconnect-host",
		Username:  "reconnect-user",
		Pid:       4242,
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: ts2,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-reconnect", ts2),
	}
	resp2, err := HandleRegister(h, reg2, "https", "127.0.0.1:2")
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if resp2.SessionId != resp1.SessionId {
		t.Fatalf("expected same session id, got %s vs %s", resp2.SessionId, resp1.SessionId)
	}
	if eventCount != 1 {
		t.Fatalf("expected one SESSION_NEW event, got %d", eventCount)
	}

	key2, err := zcrypto.AESDecrypt(secret, resp2.EncryptedSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) == string(key2) {
		t.Fatal("expected rotated session key on reconnect")
	}

	sess, ok := h.Sessions.Get(resp1.SessionId)
	if !ok {
		t.Fatal("session missing")
	}
	if string(sess.SessionKey) != string(key2) {
		t.Fatal("server session key not updated")
	}
	if sess.Hostname != "reconnect-host" || sess.Username != "reconnect-user" || sess.PID != 4242 || sess.RemoteAddr != "127.0.0.1:2" {
		t.Fatalf("metadata not refreshed on reconnect: %+v", sess)
	}

	sess.EnqueueTask(&pb.Task{TaskId: "task-enc", ImplantId: "implant-reconnect", TaskType: pb.TaskType_TASK_SHELL})
	beaconTs := ts2 + 1
	beaconResp, err := HandleBeacon(h, &pb.Beacon{
		ImplantId: "implant-reconnect",
		SessionId: resp1.SessionId,
		Timestamp: beaconTs,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-reconnect", beaconTs),
	})
	if err != nil {
		t.Fatalf("beacon after reconnect: %v", err)
	}
	if len(beaconResp.EncryptedTasks) == 0 {
		t.Fatal("expected encrypted tasks with rotated key")
	}
}

func TestSharedReplayCacheRejectsAcrossHandlers(t *testing.T) {
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}

	sharedCache := zcrypto.NewReplayCache(60 * time.Second)
	h1 := &BeaconHandler{Secret: secret, Sessions: sessions.NewManager(nil), ReplayCache: sharedCache}
	h2 := &BeaconHandler{Secret: secret, Sessions: h1.Sessions, ReplayCache: sharedCache}

	ts := time.Now().Unix()
	reg := &pb.Register{
		ImplantId: "implant-shared",
		Hostname:  "host",
		Username:  "user",
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-shared", ts),
	}
	if _, err := HandleRegister(h1, reg, "https", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}

	beacon := &pb.Beacon{
		ImplantId: "implant-shared",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, "implant-shared", ts),
	}
	if _, err := HandleBeacon(h2, beacon); err == nil {
		t.Fatal("expected replay rejection on second handler")
	}
}