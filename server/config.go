package server

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GRPCAddr     string           `yaml:"grpc_addr"`
	DBPath       string           `yaml:"db_path"`
	DataDir      string           `yaml:"data_dir"`
	ImplantSecret string          `yaml:"implant_secret"` // Hex-encoded shared secret
	Listeners    []ListenerConfig `yaml:"listeners"`
}

type ListenerConfig struct {
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"`
	Host     string `yaml:"host"`
	Port     uint32 `yaml:"port"`
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".erebus")
	return &Config{
		GRPCAddr: "127.0.0.1:50051",
		DBPath:   filepath.Join(dataDir, "erebus.db"),
		DataDir:  dataDir,
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

func (c *Config) EnsureDirs() error {
	return os.MkdirAll(c.DataDir, 0700)
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
