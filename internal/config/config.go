package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	API      APIConfig      `yaml:"api"`
	Database DatabaseConfig `yaml:"database"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
	Clients  []ClientConfig `yaml:"clients"`
}

type ServerConfig struct {
	APIAddr                     string `yaml:"api_addr"`
	RadiusAddr                  string `yaml:"radius_addr"`
	RadiusMaxConcurrentRequests int    `yaml:"radius_max_concurrent_requests"`
}

type APIConfig struct {
	AllowedSources []string `yaml:"allowed_sources"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Level       string `yaml:"level"`
	File        string `yaml:"file"`
	RotateDaily bool   `yaml:"rotate_daily"`
	MaxSizeMB   int    `yaml:"max_size_mb"`
	MaxBackups  int    `yaml:"max_backups"`
	MaxAgeDays  int    `yaml:"max_age_days"`
	Compress    bool   `yaml:"compress"`
}

type SecurityConfig struct {
	BcryptCost int `yaml:"bcrypt_cost"`
}

type ClientConfig struct {
	Name    string `yaml:"name"`
	Network string `yaml:"network"`
	Secret  string `yaml:"secret"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			APIAddr:                     ":8080",
			RadiusAddr:                  ":1812",
			RadiusMaxConcurrentRequests: 64,
		},
		Database: DatabaseConfig{
			Path: "data/radius-go.db",
		},
		Logging: LoggingConfig{
			Level:       "info",
			File:        "logs/radius-go.log",
			RotateDaily: true,
			MaxSizeMB:   100,
			MaxBackups:  14,
			MaxAgeDays:  30,
			Compress:    true,
		},
		Security: SecurityConfig{
			BcryptCost: 12,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.APIAddr) == "" {
		return fmt.Errorf("server.api_addr is required")
	}
	if strings.TrimSpace(c.Server.RadiusAddr) == "" {
		return fmt.Errorf("server.radius_addr is required")
	}
	if c.Server.RadiusMaxConcurrentRequests <= 0 {
		return fmt.Errorf("server.radius_max_concurrent_requests must be greater than zero")
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		return fmt.Errorf("database.path is required")
	}
	if strings.TrimSpace(c.Logging.File) == "" {
		return fmt.Errorf("logging.file is required")
	}
	if c.Logging.MaxSizeMB <= 0 {
		return fmt.Errorf("logging.max_size_mb must be greater than zero")
	}
	if c.Security.BcryptCost < bcrypt.MinCost || c.Security.BcryptCost > bcrypt.MaxCost {
		return fmt.Errorf("security.bcrypt_cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	for i, source := range c.API.AllowedSources {
		if err := validateIPOrCIDR(source); err != nil {
			return fmt.Errorf("api.allowed_sources[%d] must be an IP address or CIDR: %w", i, err)
		}
	}
	for i, proxy := range c.API.TrustedProxies {
		if err := validateIPOrCIDR(proxy); err != nil {
			return fmt.Errorf("api.trusted_proxies[%d] must be an IP address or CIDR: %w", i, err)
		}
	}
	if len(c.Clients) == 0 {
		return fmt.Errorf("at least one RADIUS client must be configured")
	}
	seenNames := make(map[string]struct{}, len(c.Clients))
	for i, client := range c.Clients {
		if strings.TrimSpace(client.Name) == "" {
			return fmt.Errorf("clients[%d].name is required", i)
		}
		if _, ok := seenNames[client.Name]; ok {
			return fmt.Errorf("clients[%d].name is duplicated", i)
		}
		seenNames[client.Name] = struct{}{}

		if strings.TrimSpace(client.Network) == "" {
			return fmt.Errorf("clients[%d].network is required", i)
		}
		if _, _, err := net.ParseCIDR(client.Network); err != nil {
			return fmt.Errorf("clients[%d].network must be a valid CIDR: %w", i, err)
		}
		if len(client.Secret) < 8 {
			return fmt.Errorf("clients[%d].secret must be at least 8 characters", i)
		}
	}
	return nil
}

func validateIPOrCIDR(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value is empty")
	}
	if ip := net.ParseIP(value); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return err
	}
	return nil
}
