package config

import "testing"

func TestValidateAllowedAPISources(t *testing.T) {
	cfg := validTestConfig()
	cfg.API.AllowedSources = []string{"127.0.0.1", "10.0.0.0/8", "2001:db8::/32"}
	cfg.API.TrustedProxies = []string{"127.0.0.1", "172.16.0.0/12"}

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

func TestValidateRejectsInvalidTrustedProxy(t *testing.T) {
	cfg := validTestConfig()
	cfg.API.TrustedProxies = []string{"not-an-ip"}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid trusted proxy to fail validation")
	}
}

func TestValidateRejectsInvalidRadiusConcurrencyLimit(t *testing.T) {
	cfg := validTestConfig()
	cfg.Server.RadiusMaxConcurrentRequests = 0

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected a non-positive RADIUS concurrency limit to fail validation")
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
