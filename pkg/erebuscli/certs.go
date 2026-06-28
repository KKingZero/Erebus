package erebuscli

import (
	"fmt"
	"os"
	"path/filepath"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
)

// DefaultCertPaths returns standard operator mTLS paths under ~/.erebus/certs/.
func DefaultCertPaths() (cert, key, ca string) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".erebus", "certs")
	return filepath.Join(dir, "operator.pem"),
		filepath.Join(dir, "operator-key.pem"),
		filepath.Join(dir, "ca.pem")
}

// EnsureOperatorCerts creates operator client certs if missing.
func EnsureOperatorCerts(dataDir string) (cert, key, ca string, err error) {
	cert, key, ca = DefaultCertPaths()
	if fileExists(cert) && fileExists(key) && fileExists(ca) {
		return cert, key, ca, nil
	}

	if err := os.MkdirAll(filepath.Dir(cert), 0o700); err != nil {
		return "", "", "", err
	}

	caCertPath := filepath.Join(dataDir, "ca-cert.pem")
	caKeyPath := filepath.Join(dataDir, "ca-key.pem")
	caAuth, err := zcrypto.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		return "", "", "", fmt.Errorf("load CA (start teamserver first): %w", err)
	}

	_, clientCertPEM, clientKeyPEM, err := caAuth.GenerateClientCert("operator")
	if err != nil {
		return "", "", "", fmt.Errorf("generate operator cert: %w", err)
	}

	if err := zcrypto.SavePEM(cert, clientCertPEM); err != nil {
		return "", "", "", err
	}
	if err := zcrypto.SavePEM(key, clientKeyPEM); err != nil {
		return "", "", "", err
	}
	if err := zcrypto.SavePEM(ca, caAuth.CertPEM); err != nil {
		return "", "", "", err
	}

	return cert, key, ca, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}