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
	if beaconResp.NextCheckinMs <= 0 {
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