package server

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
	"gopkg.in/yaml.v3"
)

const encryptedPrefix = "EREBUS_ENC_V1:"

type Config struct {
	GRPCAddr          string   `yaml:"grpc_addr"`
	DBPath            string   `yaml:"db_path"`
	DataDir           string   `yaml:"data_dir"`
	OperatorCertFiles []string `yaml:"operator_cert_files,omitempty"`
	ApproverCertFiles []string `yaml:"approver_cert_files,omitempty"`
	OperatorCNs       []string `yaml:"operator_cns,omitempty"`
	ApproverCNs       []string `yaml:"approver_cns,omitempty"`
	// ImplantSecret is a legacy fleet-wide PSK (hex). New builds use unique
	// per-implant secrets stored in the DB. Kept only for old implants / e2e.
	ImplantSecret string `yaml:"implant_secret"`
	// MasterKey is a hex-encoded 32-byte key used to seal session keys and
	// per-implant secrets at rest.
	MasterKey   string           `yaml:"master_key,omitempty"`
	Listeners   []ListenerConfig `yaml:"listeners"`
	AutoHarvest AutoHarvestYAML  `yaml:"auto_harvest"`
	Debug       bool             `yaml:"debug,omitempty"`
}

type AutoHarvestYAML struct {
	Enabled *bool    `yaml:"enabled,omitempty"` // pointer to distinguish unset from false
	Tasks   []string `yaml:"tasks,omitempty"`
}

type ListenerConfig struct {
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"`
	Host     string `yaml:"host"`
	Port     uint32 `yaml:"port"`
	Domain   string `yaml:"domain,omitempty"` // required for DNS listeners
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".erebus")
	return &Config{
		GRPCAddr:          "127.0.0.1:50051",
		DBPath:            filepath.Join(dataDir, "erebus.db"),
		DataDir:           dataDir,
		OperatorCertFiles: []string{filepath.Join(dataDir, "certs", "operator.pem")},
		ApproverCertFiles: []string{filepath.Join(dataDir, "certs", "approver.pem")},
		Listeners: []ListenerConfig{
			{
				Name:     "default-https",
				Protocol: "https",
				Host:     "0.0.0.0",
				Port:     443,
			},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// LoadEncryptedConfig loads config from an encrypted file. Auto-detects plaintext YAML for migration.
func LoadEncryptedConfig(path, passphrase string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	content := string(data)

	// Auto-detect plaintext YAML (no encryption prefix) for migration
	if !strings.HasPrefix(content, encryptedPrefix) {
		cfg := DefaultConfig()
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse plaintext config: %w", err)
		}
		return cfg, nil
	}

	// Encrypted format: EREBUS_ENC_V1:<base64(32-byte salt + AES-GCM ciphertext)>
	encoded := strings.TrimPrefix(content, encryptedPrefix)
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted config: %w", err)
	}

	if len(blob) < 32 {
		return nil, fmt.Errorf("encrypted config too short")
	}

	salt := blob[:32]
	ciphertext := blob[32:]

	key, err := zcrypto.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	plaintext, err := zcrypto.AESDecrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt config (wrong passphrase?): %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(plaintext, cfg); err != nil {
		return nil, fmt.Errorf("parse decrypted config: %w", err)
	}
	return cfg, nil
}

// SaveEncrypted saves the config encrypted with the given passphrase.
func (c *Config) SaveEncrypted(path, passphrase string) error {
	plaintext, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	salt, err := zcrypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key, err := zcrypto.DeriveKey(passphrase, salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	ciphertext, err := zcrypto.AESEncrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	// Format: EREBUS_ENC_V1:<base64(salt + ciphertext)>
	blob := append(salt, ciphertext...)
	content := encryptedPrefix + base64.StdEncoding.EncodeToString(blob)

	return os.WriteFile(path, []byte(content), 0600)
}

func (c *Config) EnsureDirs() error {
	return os.MkdirAll(c.DataDir, 0700)
}

func (c *Config) IsOperatorCN(cn string) bool {
	return containsCN(c.OperatorCNs, cn)
}

func (c *Config) IsApproverCN(cn string) bool {
	return containsCN(c.ApproverCNs, cn)
}

func containsCN(allowed []string, cn string) bool {
	if cn == "" {
		return false
	}
	for _, allowedCN := range allowed {
		if strings.TrimSpace(allowedCN) == cn {
			return true
		}
	}
	return false
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".erebus", "server.yaml")
}
