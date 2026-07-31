package autoharvest

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
)

// RequesterCN is the dual-control identity for auto-harvest approval requests.
// Any real operator/approver seat (CN ≠ this value) can approve.
const RequesterCN = "autoharvest"

// TaskDispatcher is the subset of tasks.Dispatcher used by auto-harvest.
type TaskDispatcher interface {
	Dispatch(ctx context.Context, sessionID string, taskType pb.TaskType, data []byte, timeoutMs int64, wait bool) (string, *pb.TaskResult, error)
}

// AutoHarvester subscribes to SESSION_NEW events and dispatches recon tasks
// on new implant sessions. Low-risk tasks dispatch immediately; high-risk
// tasks (per approval policy) wait for an operator approver seat.
type AutoHarvester struct {
	config     *AutoHarvestConfig
	dispatcher TaskDispatcher
	store      *db.Store
	gate       *approval.Gate
	unsub      func()
	done       chan struct{}
	debug      bool

	// Mutex to prevent race condition in idempotency check
	sessionMu sync.Mutex
}

// New creates a new AutoHarvester. gate may be nil (all tasks dispatch without approval).
func New(cfg *AutoHarvestConfig, dispatcher TaskDispatcher, store *db.Store, gate *approval.Gate) *AutoHarvester {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &AutoHarvester{
		config:     cfg,
		dispatcher: dispatcher,
		store:      store,
		gate:       gate,
		done:       make(chan struct{}),
	}
}

// Start subscribes to the event bus and begins processing SESSION_NEW events.
func (h *AutoHarvester) Start(eventCh <-chan *pb.Event, unsub func(), debug bool) {
	h.debug = debug
	if !h.config.Enabled {
		log.Printf("[autoharvest] disabled by configuration")
		return
	}

	h.unsub = unsub
	go h.run(eventCh)
	log.Printf("[autoharvest] started — low-risk tasks auto-dispatch; high-risk require approver (requester=%s)", RequesterCN)
}

// Stop unsubscribes from the event bus and shuts down.
func (h *AutoHarvester) Stop() {
	close(h.done)
	if h.unsub != nil {
		h.unsub()
	}
}

func (h *AutoHarvester) run(eventCh <-chan *pb.Event) {
	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			if event.Type == pb.EventType_EVENT_SESSION_NEW {
				h.onNewSession(event)
			}
		case <-h.done:
			return
		}
	}
}

func (h *AutoHarvester) onNewSession(event *pb.Event) {
	sessionID := event.SessionId
	if sessionID == "" {
		return
	}

	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	if h.store != nil {
		harvested, err := h.store.HasAutoHarvested(sessionID)
		if err == nil && harvested {
			return
		}
	}

	targetOS := ""
	if h.store != nil {
		sess, err := h.store.GetSession(sessionID)
		if err != nil {
			log.Printf("[autoharvest] session %s not found in DB, using default tasks", sessionID)
		} else {
			targetOS = sess.OS
		}
	}

	harvestTasks := DefaultTasks(targetOS)

	if h.debug {
		log.Printf("[autoharvest] processing %d tasks for session %s", len(harvestTasks), sessionID)
	}

	for _, ht := range harvestTasks {
		need := approval.CheckTaskApproval(h.gate, ht.TaskType, ht.Data)
		if need.Needed {
			// High-risk: do not block the SESSION_NEW loop; wait for approval async.
			go h.dispatchWithApproval(sessionID, ht, need)
			continue
		}
		h.dispatchNow(sessionID, ht)
	}
}

func (h *AutoHarvester) dispatchWithApproval(sessionID string, ht HarvestTask, need approval.ApprovalNeed) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	desc := fmt.Sprintf("autoharvest %s on session %s", ht.Name, sessionID)
	var (
		approved bool
		err      error
	)
	if need.ModuleName != "" {
		log.Printf("[autoharvest] waiting for approval: module %s (%s) session=%s risk=%s",
			need.ModuleName, ht.Name, sessionID, need.RiskLevel)
		approved, err = h.gate.RequestModuleApproval(ctx, sessionID, need.ModuleName, desc, RequesterCN)
	} else {
		log.Printf("[autoharvest] waiting for approval: %s session=%s risk=%s",
			ht.TaskType.String(), sessionID, need.RiskLevel)
		approved, err = h.gate.RequestApproval(ctx, sessionID, ht.TaskType, desc, RequesterCN)
	}
	if err != nil {
		log.Printf("[autoharvest] approval failed for %s session=%s: %v", ht.Name, sessionID, err)
		return
	}
	if !approved {
		log.Printf("[autoharvest] approval denied for %s session=%s", ht.Name, sessionID)
		return
	}
	h.dispatchNow(sessionID, ht)
}

func (h *AutoHarvester) dispatchNow(sessionID string, ht HarvestTask) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	if h.dispatcher == nil {
		log.Printf("[autoharvest] no dispatcher configured; skip %s", ht.Name)
		return
	}

	taskID, _, err := h.dispatcher.Dispatch(ctx, sessionID, ht.TaskType, ht.Data, 120000, false)
	if err != nil {
		log.Printf("[autoharvest] failed to dispatch %s for %s: %v", ht.Name, sessionID, err)
		return
	}

	if h.store != nil {
		id, err := zcrypto.RandomID(8)
		if err != nil {
			log.Printf("[autoharvest] failed to generate task tracking ID: %v", err)
			return
		}
		if err := h.store.CreateAutoHarvestTask(&db.AutoHarvestTaskRow{
			ID:        id,
			SessionID: sessionID,
			TaskID:    taskID,
			TaskType:  ht.Name,
			Status:    "pending",
			CreatedAt: time.Now(),
		}); err != nil {
			log.Printf("[autoharvest] failed to track task %s: %v", taskID, err)
		}
	}

	if h.debug {
		log.Printf("[autoharvest] dispatched %s (task=%s) for session %s", ht.Name, taskID, sessionID)
	}
}
