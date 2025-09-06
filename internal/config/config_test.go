package config

import "testing"

func TestValidateAllowedAPISources(t *testing.T) {
	cfg := validTestConfig()
	cfg.API.AllowedSources = []string{"127.0.0.1", "10.0.0.0/8", "2001:db8::/32"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid API allowed sources, got %v", err)
	}
}

func TestValidateRejectsInvalidAPISource(t *testing.T) {
	cfg := validTestConfig()
	cfg.API.AllowedSources = []string{"not-an-ip"}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid API source to fail validation")
	}
}

func validTestConfig() Config {
	cfg := Default()
	cfg.Clients = []ClientConfig{
		{
			Name:    "test-client",
			Network: "127.0.0.1/32",
			Secret:  "shared-secret",
		},
	}
	return cfg
}
