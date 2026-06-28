package agent

import (
	"strings"
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func TestInterpretShellResult(t *testing.T) {
	data, _ := proto.Marshal(&pb.ShellResult{
		Stdout:   "erebus-ok",
		ExitCode: 0,
	})
	summary := InterpretResult(pb.TaskType_TASK_SHELL, &pb.TaskResult{
		Success: true,
		Data:    data,
	})
	if !strings.Contains(summary, "erebus-ok") {
		t.Fatalf("unexpected summary: %s", summary)
	}
}

func TestInterpretLDAPResult(t *testing.T) {
	data, _ := proto.Marshal(&pb.LDAPEnumResult{
		Domain:       "corp.local",
		Dc:           "dc01",
		QueryType:    "kerberoastable",
		TotalResults: 5,
		NextSuggestedActions: []string{"kerberoast domain=corp.local"},
	})
	summary := InterpretResult(pb.TaskType_TASK_LDAP_ENUM, &pb.TaskResult{
		Success: true,
		Data:    data,
	})
	if !strings.Contains(summary, "5 entries") {
		t.Fatalf("unexpected summary: %s", summary)
	}
	if !strings.Contains(summary, "next_suggested_actions") {
		t.Fatalf("expected suggested actions: %s", summary)
	}
}