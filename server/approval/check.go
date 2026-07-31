package approval

import pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"

// ApprovalNeed describes whether a task requires operator approval and why.
type ApprovalNeed struct {
	Needed     bool
	ModuleName string // set when TASK_MODULE targets a high-risk module
	RiskLevel  string
}

// CheckTaskApproval evaluates the default policy against a task type and payload.
// Shared by ExecuteTask (gRPC) and auto-harvest so both honor the same gate rules.
func CheckTaskApproval(gate *Gate, taskType pb.TaskType, data []byte) ApprovalNeed {
	if gate == nil {
		return ApprovalNeed{}
	}
	if gate.RequiresApproval(taskType) {
		return ApprovalNeed{
			Needed:    true,
			RiskLevel: gate.policy.RiskLevel(taskType),
		}
	}
	if taskType == pb.TaskType_TASK_MODULE {
		moduleName := ModuleNameFromTaskData(data)
		if moduleName != "" && gate.RequiresModuleApproval(moduleName) {
			return ApprovalNeed{
				Needed:     true,
				ModuleName: moduleName,
				RiskLevel:  gate.policy.ModuleRiskLevel(moduleName),
			}
		}
	}
	return ApprovalNeed{}
}
