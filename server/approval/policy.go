package approval

import (
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// Policy defines which task types require approval and their risk levels.
type Policy struct {
	HighRiskTasks map[pb.TaskType]string // task type -> risk level
}

// DefaultPolicy returns the default approval policy.
func DefaultPolicy() *Policy {
	return &Policy{
		HighRiskTasks: map[pb.TaskType]string{
			pb.TaskType_TASK_CREDS_DUMP:    "critical",
			pb.TaskType_TASK_INJECT:        "high",
			pb.TaskType_TASK_PE_LOAD:       "high",
			pb.TaskType_TASK_LATERAL_MOVE:  "critical",
			pb.TaskType_TASK_PERSIST:       "critical",
			pb.TaskType_TASK_PRIVESC:       "high",
			pb.TaskType_TASK_PE_LOAD_EXEC:  "high",
		},
	}
}

// RequiresApproval returns true if the task type needs operator approval.
func (p *Policy) RequiresApproval(taskType pb.TaskType) bool {
	_, ok := p.HighRiskTasks[taskType]
	return ok
}

// RiskLevel returns the risk level for a task type, or "low" if not high-risk.
func (p *Policy) RiskLevel(taskType pb.TaskType) string {
	if level, ok := p.HighRiskTasks[taskType]; ok {
		return level
	}
	return "low"
}
