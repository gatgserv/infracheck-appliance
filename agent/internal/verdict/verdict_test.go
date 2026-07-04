package verdict

import (
	"testing"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func TestEvaluateHealthy(t *testing.T) {
	now := time.Now()
	health := Evaluate(Input{
		Now:     now,
		Gateway: []storage.PingResult{{Timestamp: now, TargetType: "gateway", Up: true, LatencyMS: 1, LossPercent: 0}},
		Internet: []storage.PingResult{
			{Timestamp: now, TargetName: "one", TargetType: "internet", Up: true, LatencyMS: 5, LossPercent: 0},
			{Timestamp: now, TargetName: "two", TargetType: "internet", Up: true, LatencyMS: 8, LossPercent: 0},
		},
		DNS: []storage.DNSResult{
			{Timestamp: now, ResolverName: "system", ResolverAddress: "auto", Domain: "example.com", RecordType: "A", Success: true},
			{Timestamp: now, ResolverName: "cloudflare", ResolverAddress: "1.1.1.1", Domain: "example.com", RecordType: "A", Success: true},
		},
	})
	if health.Status != "healthy" {
		t.Fatalf("status = %s", health.Status)
	}
	if health.Verdicts[0].Code != "healthy" {
		t.Fatalf("verdict = %s", health.Verdicts[0].Code)
	}
}

func TestEvaluateLocalDNSProblem(t *testing.T) {
	now := time.Now()
	health := Evaluate(Input{
		Now: now,
		DNS: []storage.DNSResult{
			{Timestamp: now, ResolverName: "system", ResolverAddress: "auto", Domain: "example.com", RecordType: "A", Success: false},
			{Timestamp: now, ResolverName: "cloudflare", ResolverAddress: "1.1.1.1", Domain: "example.com", RecordType: "A", Success: true},
			{Timestamp: now, ResolverName: "google", ResolverAddress: "8.8.8.8", Domain: "example.com", RecordType: "A", Success: true},
		},
	})
	assertVerdict(t, health, "local_dns_problem")
}

func TestEvaluateUpstreamPacketLoss(t *testing.T) {
	now := time.Now()
	health := Evaluate(Input{
		Now:     now,
		Gateway: []storage.PingResult{{Timestamp: now, TargetType: "gateway", Up: true, LatencyMS: 1, LossPercent: 0}},
		Internet: []storage.PingResult{
			{Timestamp: now, TargetName: "wan", TargetType: "internet", Up: true, LatencyMS: 20, LossPercent: 5},
		},
	})
	assertVerdict(t, health, "upstream_packet_loss")
}

func TestEvaluateServiceDown(t *testing.T) {
	now := time.Now()
	health := Evaluate(Input{
		Now:  now,
		HTTP: []storage.HTTPResult{{Timestamp: now, Name: "app", URL: "https://example.com", Up: false, StatusCode: 500}},
	})
	assertVerdict(t, health, "service_down")
	if health.ServiceAvailability >= 100 {
		t.Fatalf("service score = %d", health.ServiceAvailability)
	}
}

func TestEvaluateTLSExpiring(t *testing.T) {
	now := time.Now()
	health := Evaluate(Input{
		Now:  now,
		HTTP: []storage.HTTPResult{{Timestamp: now, Name: "app", URL: "https://example.com", Up: true, StatusCode: 200, TLSValid: true, TLSDaysUntilExpiry: 7}},
	})
	assertVerdict(t, health, "tls_expiring")
}

func assertVerdict(t *testing.T, health Health, code string) {
	t.Helper()
	for _, verdict := range health.Verdicts {
		if verdict.Code == code {
			return
		}
	}
	t.Fatalf("missing verdict %s in %#v", code, health.Verdicts)
}
