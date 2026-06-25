package agent

import (
	"context"
	"encoding/json"
	"fmt"

	openai "github.com/sashabaranov/go-openai"
)

// StepOutput is emitted per iteration in JSON mode.
type StepOutput struct {
	Step    int    `json:"step"`
	Tool    string `json:"tool,omitempty"`
	Args    string `json:"args,omitempty"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
	Risk    string `json:"risk,omitempty"`
	Message string `json:"message,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

// Loop runs the semi-autonomous agent.
type Loop struct {
	LLM      *LLM
	Executor *Executor
	State    *State
	JSONMode bool
	Emit     func(StepOutput)
}

// Run executes the agent loop until complete or max steps.
func (l *Loop) Run(ctx context.Context) error {
	messages := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: SystemPrompt()},
		{Role: openai.ChatMessageRoleUser, Content: fmt.Sprintf("Objective: %s\n\nBegin working toward this objective.", l.State.Objective)},
	}

	for step := 1; step <= l.State.MaxSteps; step++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Inject fresh context each step.
		ctxMsg := l.State.ContextSummary(l.Executor.Client.Events())
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: "Current context:\n" + ctxMsg,
		})

		msg, err := l.LLM.Chat(ctx, messages)
		if err != nil {
			return err
		}
		messages = append(messages, msg)

		if len(msg.ToolCalls) == 0 {
			out := StepOutput{Step: step, Message: msg.Content}
			l.emit(out)
			if msg.Content != "" {
				l.State.RecordStep(step, "assistant", "", msg.Content, "", "")
			}
			continue
		}

		for _, tc := range msg.ToolCalls {
			toolName := tc.Function.Name
			args := tc.Function.Arguments

			tool, _ := LookupTool(toolName)
			risk := tool.Risk
			if toolName == "mission_complete" {
				risk = RiskNone
			}

			result, err := l.Executor.RunTool(ctx, toolName, args, l.State.SessionID)
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			l.State.RecordStep(step, toolName, args, result, errStr, risk)

			out := StepOutput{
				Step:   step,
				Tool:   toolName,
				Args:   args,
				Result: result,
				Error:  errStr,
				Risk:   risk,
			}
			l.emit(out)

			if toolName == "mission_complete" {
				out.Done = true
				out.Message = result
				l.emit(out)
				return nil
			}

			toolContent := result
			if err != nil {
				toolContent = "ERROR: " + err.Error()
			}
			messages = append(messages, openai.ChatCompletionMessage{
				Role:       openai.ChatMessageRoleTool,
				Content:    toolContent,
				ToolCallID: tc.ID,
				Name:       toolName,
			})
		}
	}

	return fmt.Errorf("max steps (%d) reached", l.State.MaxSteps)
}

func (l *Loop) emit(out StepOutput) {
	if l.Emit == nil {
		return
	}
	l.Emit(out)
}

// EmitJSON prints one JSON line.
func EmitJSON(out StepOutput) {
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}