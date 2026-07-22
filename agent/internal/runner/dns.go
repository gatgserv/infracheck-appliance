package runner

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type DNSTarget struct {
	SiteID          string
	ResolverName    string
	ResolverAddress string
	Domain          string
	RecordType      string
}

type DNSRunner struct{}

func (r DNSRunner) Run(ctx context.Context, target DNSTarget) storage.DNSResult {
	result := storage.DNSResult{
		Timestamp:       time.Now().UTC(),
		SiteID:          target.SiteID,
		ResolverName:    target.ResolverName,
		ResolverAddress: target.ResolverAddress,
		Domain:          strings.TrimSuffix(target.Domain, "."),
		RecordType:      strings.ToUpper(target.RecordType),
	}

	resolverAddress := effectiveResolverAddress(target.ResolverAddress)
	result.ResolverAddress = resolverAddress
	resolver := systemResolver()
	if resolverAddress != "" && resolverAddress != "auto" {
		resolver = resolverForAddress(resolverAddress)
	}

	start := time.Now()
	answers, err := lookup(ctx, resolver, result.Domain, result.RecordType)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.AnswerCount = answers
	return result
}

func effectiveResolverAddress(configured string) string {
	configured = strings.TrimSpace(configured)
	if configured == "" || configured == "auto" {
		if networkDNS := strings.TrimSpace(os.Getenv("INFRACHECK_NETWORK_DNS")); networkDNS != "" {
			return networkDNS
		}
	}
	return configured
}

func lookup(ctx context.Context, resolver *net.Resolver, domain, recordType string) (int, error) {
	switch strings.ToUpper(recordType) {
	case "AAAA":
		records, err := resolver.LookupIP(ctx, "ip6", domain)
		return len(records), err
	default:
		records, err := resolver.LookupIP(ctx, "ip4", domain)
		return len(records), err
	}
}

func systemResolver() *net.Resolver {
	return net.DefaultResolver
}

func resolverForAddress(address string) *net.Resolver {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "53"
	}
	target := net.JoinHostPort(host, port)
	dialer := net.Dialer{}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", target)
		},
	}
}
