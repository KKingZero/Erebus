package agent

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// StepLog records one agent iteration.
type StepLog struct {
	Step      int       `json:"step"`
	Tool      string    `json:"tool"`
	Args      string    `json:"args,omitempty"`
	Result    string    `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	Risk      string    `json:"risk,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// State tracks engagement context across the agent loop.
type State struct {
	Objective   string
	SessionID   string
	Steps       []StepLog
	Findings    []string
	MaxSteps    int
}

// NewState creates engagement state.
func NewState(objective, sessionID string, maxSteps int) *State {
	return &State{
		Objective: objective,
		SessionID: sessionID,
		MaxSteps:  maxSteps,
	}
}

// RecordStep appends a step log entry.
func (s *State) RecordStep(step int, tool, args, result, errStr, risk string) {
	s.Steps = append(s.Steps, StepLog{
		Step:      step,
		Tool:      tool,
		Args:      args,
		Result:    result,
		Error:     errStr,
		Risk:      risk,
		Timestamp: time.Now(),
	})
	if result != "" && errStr == "" {
		s.Findings = append(s.Findings, fmt.Sprintf("[%s] %s", tool, truncate(result, 300)))
	}
}

// ContextSummary builds text for the LLM system/user context.
func (s *State) ContextSummary(events []*pb.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Objective: %s\n", s.Objective)
	if s.SessionID != "" {
		fmt.Fprintf(&b, "Primary session: %s\n", s.SessionID)
	}
	if len(s.Findings) > 0 {
		b.WriteString("Recent findings:\n")
		start := 0
		if len(s.Findings) > 10 {
			start = len(s.Findings) - 10
		}
		for _, f := range s.Findings[start:] {
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	if len(events) > 0 {
		b.WriteString("Recent events:\n")
		start := 0
		if len(events) > 5 {
			start = len(events) - 5
		}
		for _, e := range events[start:] {
			fmt.Fprintf(&b, "- %s: %s\n", e.Type.String(), e.Message)
		}
	}
	return b.String()
}