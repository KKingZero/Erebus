package lateral

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&LateralMoveModule{})
}

type LateralMoveModule struct{}

func (m *LateralMoveModule) Name() string        { return "lateral_move" }
func (m *LateralMoveModule) Description() string { return "Lateral movement (WinRM, PsExec, WMI, DCOM)" }

func (m *LateralMoveModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.LateralMoveConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal lateral move config: %w", err)
	}

	var result *pb.LateralMoveResult
	var err error

	switch cfg.Method {
	case "winrm":
		result, err = moveWinRM(ctx, cfg)
	case "psexec":
		result, err = movePsExec(ctx, cfg)
	case "wmi":
		result, err = moveWMI(ctx, cfg)
	case "dcom":
		result, err = moveDCOM(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown lateral movement method: %s (available: winrm, psexec, wmi, dcom)", cfg.Method)
	}

	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}
