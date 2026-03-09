package persist

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&PersistModule{})
}

type PersistModule struct{}

func (m *PersistModule) Name() string        { return "persist" }
func (m *PersistModule) Description() string { return "Persistence mechanisms (scheduled task, registry, service)" }

func (m *PersistModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.PersistConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal persist config: %w", err)
	}

	var result *pb.PersistResult
	var err error

	switch cfg.Method {
	case "schtask":
		result, err = persistSchTask(ctx, cfg)
	case "registry":
		result, err = persistRegistry(ctx, cfg)
	case "service":
		result, err = persistService(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown persistence method: %s (available: schtask, registry, service)", cfg.Method)
	}

	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}
