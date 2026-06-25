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
		Secret:   secret,
		Sessions: sessions.NewManager(nil),
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

	beaconHmac := zcrypto.ComputeHMAC(secret, "implant-1", ts)
	beaconResp, err := HandleBeacon(h, &pb.Beacon{
		ImplantId: "implant-1",
		SessionId: resp.SessionId,
		Timestamp: ts,
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