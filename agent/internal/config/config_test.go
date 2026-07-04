package config

import "testing"

func TestDefaultConfigValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestConfigValidationRejectsBadPort(t *testing.T) {
	cfg := Default()
	cfg.Agent.Port = 70000
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestConfigValidationRejectsBadDNSResolver(t *testing.T) {
	cfg := Default()
	cfg.Targets.DNS.Resolvers[0].Name = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid dns resolver error")
	}
}

func TestConfigValidationRejectsBadHTTPTarget(t *testing.T) {
	cfg := Default()
	cfg.Targets.HTTP[0].URL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid http target error")
	}
}

func TestConfigValidationRejectsProtectedMetricsWithoutToken(t *testing.T) {
	cfg := Default()
	cfg.Security.ProtectMetrics = true
	cfg.Security.ReadToken = ""
	cfg.Security.AdminToken = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected protected metrics without token error")
	}
}

func TestConfigValidationRejectsPrivateReadsWithoutToken(t *testing.T) {
	cfg := Default()
	cfg.Security.AllowPublicReads = false
	cfg.Security.ReadToken = ""
	cfg.Security.AdminToken = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected private reads without token error")
	}
}

func TestConfigValidationAcceptsPrivateReadsWithAdminToken(t *testing.T) {
	cfg := Default()
	cfg.Security.AllowPublicReads = false
	cfg.Security.AdminToken = "admin-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected private reads with admin token to pass: %v", err)
	}
}

func TestConfigValidationRejectsBadSpeedtestTarget(t *testing.T) {
	cfg := Default()
	cfg.Targets.Speedtest.DownloadURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid speedtest target error")
	}
}

func TestConfigValidationRejectsBadDiscoveryCIDR(t *testing.T) {
	cfg := Default()
	cfg.Targets.Discovery.CIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid discovery CIDR error")
	}
}

func TestIntervalDuration(t *testing.T) {
	cfg := Default()
	if cfg.Tests.Ping.Duration() <= 0 {
		t.Fatal("expected positive ping interval")
	}
}
