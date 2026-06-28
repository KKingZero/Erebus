package agent

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// RunOptions configures an agent engagement.
type RunOptions struct {
	Objective  string
	SessionID  string
	MaxSteps   int
	JSONMode   bool
	OnApproval func(id, risk, desc string)
	OnStep     func(StepOutput)
}

// Run executes the semi-autonomous agent loop against the teamserver.
func Run(ctx context.Context, cfg *Config, opts RunOptions) error {
	if opts.Objective == "" {
		return fmt.Errorf("objective required")
	}

	client, err := Connect(cfg)
	if err != nil {
		return fmt.Errorf("connect teamserver: %w", err)
	}
	defer client.Close()

	if err := client.StartSubscribe(ctx); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	sid := opts.SessionID
	if sid == "" {
		resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{})
		if err == nil && len(resp.Sessions) == 1 {
			sid = resp.Sessions[0].SessionId
		}
	}

	maxSteps := opts.MaxSteps
	if maxSteps <= 0 {
		maxSteps = cfg.Autonomy.MaxSteps
	}

	exec := &Executor{Client: client, OnApproval: opts.OnApproval}
	loop := &Loop{
		LLM:      NewLLM(cfg.LLM),
		Executor: exec,
		State:    NewState(opts.Objective, sid, maxSteps),
		JSONMode: opts.JSONMode,
	}
	if opts.OnStep != nil {
		loop.Emit = opts.OnStep
	} else if opts.JSONMode {
		loop.Emit = EmitJSON
	}

	return loop.Run(ctx)
}