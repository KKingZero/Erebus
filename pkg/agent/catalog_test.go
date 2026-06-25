package agent

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
)

func TestCatalogRiskMatchesPolicy(t *testing.T) {
	p := approval.DefaultPolicy()
	for _, tool := range Catalog() {
		if tool.TaskType == pb.TaskType_TASK_UNKNOWN || tool.TaskType == 0 {
			continue
		}
		want := p.RiskLevel(tool.TaskType)
		if tool.Risk != want {
			t.Fatalf("%s risk %q want %q", tool.Name, tool.Risk, want)
		}
	}
}

func TestBuildLDAPEnum(t *testing.T) {
	data, err := buildLDAPEnum(map[string]any{
		"query_type": "kerberoastable",
		"domain":     "corp.local",
		"target_dc":  "dc01.corp.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty data")
	}
}

func TestRequiresApproval(t *testing.T) {
	if !RequiresApproval(pb.TaskType_TASK_CREDS_DUMP) {
		t.Fatal("creds_dump should require approval")
	}
	if RequiresApproval(pb.TaskType_TASK_SHELL) {
		t.Fatal("shell should not require approval")
	}
}