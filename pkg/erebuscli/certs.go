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

// DefaultApproverCertPaths returns approver seat mTLS paths under ~/.erebus/certs/.
func DefaultApproverCertPaths() (cert, key string) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".erebus", "certs")
	return filepath.Join(dir, "approver.pem"),
		filepath.Join(dir, "approver-key.pem")
}

// SeatCerts holds operator and approver client certificate paths.
type SeatCerts struct {
	OperatorCert, OperatorKey, CA string
	ApproverCert, ApproverKey     string
}

func loadClientCA(dataDir string) (*zcrypto.CertificateAuthority, string, error) {
	opCert, _, ca := DefaultCertPaths()
	if err := os.MkdirAll(filepath.Dir(opCert), 0o700); err != nil {
		return nil, "", err
	}
	caCertPath := filepath.Join(dataDir, "ca-cert.pem")
	caKeyPath := filepath.Join(dataDir, "ca-key.pem")
	caAuth, err := zcrypto.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load CA (start teamserver first): %w", err)
	}
	if !fileExists(ca) {
		if err := zcrypto.SavePEM(ca, caAuth.CertPEM); err != nil {
			return nil, "", err
		}
	}
	return caAuth, ca, nil
}

// EnsureSeatCerts creates both operator and approver client certs.
// Use this only for explicit lab provisioning; normal startup uses
// EnsureOperatorCerts so one process does not hold both dual-control seats.
func EnsureSeatCerts(dataDir string) (SeatCerts, error) {
	opCert, opKey, ca := DefaultCertPaths()
	apCert, apKey := DefaultApproverCertPaths()

	caAuth, ca, err := loadClientCA(dataDir)
	if err != nil {
		return SeatCerts{}, err
	}

	if !fileExists(opCert) || !fileExists(opKey) {
		_, clientCertPEM, clientKeyPEM, err := caAuth.GenerateClientCert("operator")
		if err != nil {
			return SeatCerts{}, fmt.Errorf("generate operator cert: %w", err)
		}
		if err := zcrypto.SavePEM(opCert, clientCertPEM); err != nil {
			return SeatCerts{}, err
		}
		if err := zcrypto.SavePEM(opKey, clientKeyPEM); err != nil {
			return SeatCerts{}, err
		}
	}

	if !fileExists(apCert) || !fileExists(apKey) {
		_, clientCertPEM, clientKeyPEM, err := caAuth.GenerateClientCert("approver")
		if err != nil {
			return SeatCerts{}, fmt.Errorf("generate approver cert: %w", err)
		}
		if err := zcrypto.SavePEM(apCert, clientCertPEM); err != nil {
			return SeatCerts{}, err
		}
		if err := zcrypto.SavePEM(apKey, clientKeyPEM); err != nil {
			return SeatCerts{}, err
		}
	}

	return SeatCerts{
		OperatorCert: opCert,
		OperatorKey:  opKey,
		CA:           ca,
		ApproverCert: apCert,
		ApproverKey:  apKey,
	}, nil
}

// EnsureOperatorCerts creates operator client certs if missing.
func EnsureOperatorCerts(dataDir string) (cert, key, ca string, err error) {
	cert, key, _ = DefaultCertPaths()
	caAuth, ca, err := loadClientCA(dataDir)
	if err != nil {
		return "", "", "", err
	}
	if !fileExists(cert) || !fileExists(key) {
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
	}
	return cert, key, ca, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
