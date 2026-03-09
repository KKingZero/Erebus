package privesc

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&PrivescModule{})
}

type PrivescModule struct{}

func (m *PrivescModule) Name() string        { return "privesc" }
func (m *PrivescModule) Description() string { return "Privilege escalation (token theft, UAC bypass)" }

func (m *PrivescModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.PrivescConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal privesc config: %w", err)
	}

	var result *pb.PrivescResult
	var err error

	switch cfg.Method {
	case "token":
		result, err = privescToken(ctx, cfg)
	case "uac_fodhelper":
		result, err = privescUACFodhelper(ctx, cfg)
	case "uac_eventvwr":
		result, err = privescUACEventvwr(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown privesc method: %s (available: token, uac_fodhelper, uac_eventvwr)", cfg.Method)
	}

	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}
