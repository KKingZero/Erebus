package agent

import (
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/server/approval"
	"google.golang.org/protobuf/proto"
)

func TestCatalogRiskMatchesPolicy(t *testing.T) {
	p := approval.DefaultPolicy()
	for _, tool := range Catalog() {
		if tool.TaskType == pb.TaskType_TASK_UNKNOWN || tool.TaskType == 0 {
			continue
		}
		want := p.RiskLevel(tool.TaskType)
		if tool.ModuleName != "" {
			want = p.ModuleRiskLevel(tool.ModuleName)
		}
		if tool.Risk != want {
			t.Fatalf("%s risk %q want %q", tool.Name, tool.Risk, want)
		}
	}
}

func TestCatalogHasSchemas(t *testing.T) {
	schemas := ToolSchemas()
	for _, tool := range Catalog() {
		if _, ok := schemas[tool.Name]; !ok {
			t.Fatalf("missing schema for catalog tool %s", tool.Name)
		}
	}
	if _, ok := schemas["mission_complete"]; !ok {
		t.Fatal("missing mission_complete schema")
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

func TestBuildCloudHarvest(t *testing.T) {
	tool, ok := LookupTool("cloud_harvest")
	if !ok {
		t.Fatal("cloud_harvest not in catalog")
	}
	data, err := tool.BuildData(map[string]any{"provider": "azure"})
	if err != nil {
		t.Fatal(err)
	}
	mod := &pb.ModuleTask{}
	if err := proto.Unmarshal(data, mod); err != nil {
		t.Fatal(err)
	}
	if mod.ModuleName != "cloud" {
		t.Fatalf("module %q", mod.ModuleName)
	}
}

func TestRequiresApproval(t *testing.T) {
	creds, _ := LookupTool("creds_dump")
	if !RequiresApproval(creds) {
		t.Fatal("creds_dump should require approval")
	}
	shell, _ := LookupTool("run_shell")
	if RequiresApproval(shell) {
		t.Fatal("shell should not require approval")
	}
	cloud, _ := LookupTool("cloud_harvest")
	if RequiresApproval(cloud) {
		t.Fatal("cloud_harvest should not require approval")
	}
}