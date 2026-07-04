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
