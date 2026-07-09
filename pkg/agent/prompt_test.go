package agent

import (
	"strings"
	"testing"
)

func TestPlanSystemPromptStructure(t *testing.T) {
	p := PlanSystemPrompt()
	for _, want := range []string{
		"PLAN mode",
		"cannot execute tools",
		"## Objective",
		"## Steps",
		"## Approvals required",
		"## Success criteria",
		"ldap_enum",
		"kerberoast",
		"mission_complete",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("PlanSystemPrompt missing %q", want)
		}
	}
	// Must list tools from catalog
	if !strings.Contains(p, "run_shell") {
		t.Error("expected run_shell in plan tool list")
	}
}

func TestSystemPromptGoldenPath(t *testing.T) {
	p := SystemPrompt()
	for _, want := range []string{
		"GOLDEN PATH",
		"next_suggested_actions",
		"mission_complete",
		"Do NOT call creds_dump",
		"ldap_enum",
		"kerberoast",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("SystemPrompt missing %q", want)
		}
	}
}

func TestLooksLikeGoldenADObjective(t *testing.T) {
	if !LooksLikeGoldenADObjective(GoldenADObjective) {
		t.Fatal("frozen golden objective should match")
	}
	if !LooksLikeGoldenADObjective("enumerate kerberoastable users in corp.local") {
		t.Fatal("expected match for kerberoastable enum")
	}
	if LooksLikeGoldenADObjective("scan ports on 10.0.0.1 only") {
		t.Fatal("port-only objective should not look like golden AD")
	}
}
