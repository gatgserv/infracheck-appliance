package runner

import (
	"context"
	"testing"
	"time"
)

func TestDNSRunnerRejectsInvalidDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result := DNSRunner{}.Run(ctx, DNSTarget{
		SiteID:          "site-1",
		ResolverName:    "system",
		ResolverAddress: "auto",
		Domain:          "invalid domain",
		RecordType:      "A",
	})

	if result.Success {
		t.Fatal("expected invalid domain lookup to fail")
	}
	if result.Error == "" {
		t.Fatal("expected error")
	}
}

func TestEffectiveResolverAddressUsesNetworkDNSForAuto(t *testing.T) {
	t.Setenv("INFRACHECK_NETWORK_DNS", "192.168.1.1")

	if got := effectiveResolverAddress("auto"); got != "192.168.1.1" {
		t.Fatalf("expected network DNS, got %q", got)
	}
	if got := effectiveResolverAddress("8.8.8.8"); got != "8.8.8.8" {
		t.Fatalf("explicit resolver must be preserved, got %q", got)
	}
}
