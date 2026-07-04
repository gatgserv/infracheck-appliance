package report

import (
	"strings"
	"testing"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/infracheck/infracheck/container/agent/internal/verdict"
)

func TestGenerateReportHTML(t *testing.T) {
	output, err := Generate(Input{
		Site:        config.SiteConfig{ID: "site-1", Name: "Site One", Location: "Office"},
		Type:        "daily",
		PeriodStart: time.Now().Add(-24 * time.Hour),
		PeriodEnd:   time.Now(),
		Health: verdict.Health{
			OverallHealthScore:   100,
			WANScore:             100,
			DNSScore:             100,
			GatewayLANScore:      100,
			ServiceAvailability:  100,
			DeviceInventoryScore: 100,
		},
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	html := string(output.HTML)
	if !strings.Contains(html, "Infracheck daily report") {
		t.Fatalf("missing title in html: %s", html)
	}
	if !strings.Contains(html, "Executive Summary") {
		t.Fatalf("missing executive summary")
	}
	if !strings.Contains(html, "Appliance Network Load") {
		t.Fatalf("missing network load section")
	}
}

func TestGenerateReportPDF(t *testing.T) {
	output, err := GeneratePDF(Input{
		Site:        config.SiteConfig{ID: "site-1", Name: "Site One", Location: "Office"},
		Type:        "current-status",
		PeriodStart: time.Now().Add(-24 * time.Hour),
		PeriodEnd:   time.Now(),
		Health: verdict.Health{
			Status:               "healthy",
			OverallHealthScore:   100,
			WANScore:             100,
			DNSScore:             100,
			GatewayLANScore:      100,
			ServiceAvailability:  100,
			DeviceInventoryScore: 100,
		},
	})
	if err != nil {
		t.Fatalf("generate pdf failed: %v", err)
	}
	if !strings.HasPrefix(string(output.PDF), "%PDF-") {
		t.Fatalf("missing pdf header")
	}
	if len(output.PDF) < 500 {
		t.Fatalf("pdf output unexpectedly small: %d", len(output.PDF))
	}
}

func TestPrioritizedFindingsGroupsRepeatedAdvancedSpeedHistory(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	input := Input{}
	for i := 0; i < 8; i++ {
		input.Advanced = append(input.Advanced, storage.AdvancedResult{
			Timestamp:  now.Add(time.Duration(i) * time.Minute),
			CheckType:  "speed_history",
			TargetName: "WAN speed trend",
			Target:     "speedtest",
			Success:    true,
			Severity:   "warning",
			Summary:    "Speed latest vs baseline speedtest dropped below expected range",
		})
	}

	rows := prioritizedFindings(input)
	if len(rows) != 1 {
		t.Fatalf("expected repeated speed history findings to be grouped, got %d rows: %#v", len(rows), rows)
	}
	if rows[0].Count != 8 {
		t.Fatalf("expected grouped count 8, got %d", rows[0].Count)
	}
	if rows[0].Title != "Multiple WAN speed trend findings" {
		t.Fatalf("unexpected grouped title: %q", rows[0].Title)
	}
}

func TestLineParsingKeepsHTTPURLTitleAndTimestamp(t *testing.T) {
	line := "- [HTTP] https://www.google.com at 2026-07-03 08:06:14: up=false status=0 duration=5002 ms TLS=true/0 days context deadline exceeded"

	if got := titleFromLine(line); got != "[HTTP] https://www.google.com" {
		t.Fatalf("unexpected title: %q", got)
	}
	if got := whenFromLine(line); got != "2026-07-03 08:06:14" {
		t.Fatalf("unexpected timestamp: %q", got)
	}
}

func TestWrapPDFCellUsesBoundedReadableLines(t *testing.T) {
	lines := wrapPDFCell("HTTP response slow because the service took 2400 ms above the configured baseline and should be investigated", 34, 2)
	if len(lines) != 2 {
		t.Fatalf("expected two wrapped lines, got %d: %#v", len(lines), lines)
	}
	for _, line := range lines {
		if len(line) > 34 {
			t.Fatalf("line exceeds width: %q", line)
		}
	}
	if !strings.HasSuffix(lines[1], "...") {
		t.Fatalf("expected truncated second line, got %#v", lines)
	}
}

func TestRadarFocusUsesAlertThresholdStatusWhenDomainsAreGreen(t *testing.T) {
	input := Input{Health: verdict.Health{
		Status:               "warning",
		OverallHealthScore:   80,
		WANScore:             100,
		DNSScore:             100,
		GatewayLANScore:      100,
		ServiceAvailability:  100,
		DeviceInventoryScore: 90,
	}}
	fallback := radarDomains(input)[4]
	focus := radarFocus(input, fallback)
	if focus.Name != "Alerts/thresholds" {
		t.Fatalf("expected alerts/threshold focus, got %#v", focus)
	}
}

func TestPrimaryDomainUsesAlertThresholdCapWhenOverallIsLowerThanWeakestDomain(t *testing.T) {
	input := Input{Health: verdict.Health{
		Status:               "critical",
		OverallHealthScore:   60,
		WANScore:             100,
		DNSScore:             100,
		GatewayLANScore:      100,
		ServiceAvailability:  70,
		DeviceInventoryScore: 90,
	}}
	domain := primaryDomain(input)
	if domain.Name != "Alerts/thresholds" {
		t.Fatalf("expected alerts/threshold primary domain, got %#v", domain)
	}
	if domain.Status != "critical" {
		t.Fatalf("expected critical status for score 60, got %q", domain.Status)
	}
}

func TestDNSTriageDoesNotInheritHTTPRecommendationText(t *testing.T) {
	input := Input{
		Health: verdict.Health{Verdicts: []verdict.Verdict{
			{
				Severity:       "warning",
				Category:       "service",
				Code:           "http_threshold",
				Title:          "HTTP response slow",
				Summary:        "Google response took 1200 ms.",
				Recommendation: "Compare with WAN latency, DNS timing, proxy path, and upstream service performance.",
			},
		}},
		Alerts: []storage.AlertRecord{
			{
				Severity:       "warning",
				Category:       "service",
				Title:          "HTTP response slow",
				Summary:        "Google response took 1200 ms.",
				Recommendation: "Compare with WAN latency, DNS timing, proxy path, and upstream service performance.",
			},
		},
	}

	evidence := dnsEvidence(input)
	for _, line := range evidence {
		if strings.Contains(line, "HTTP response slow") {
			t.Fatalf("dns evidence inherited unrelated http verdict: %#v", evidence)
		}
	}
}

func TestEvidenceLimitDeduplicatesSignals(t *testing.T) {
	evidence := evidenceLimit([]string{
		"critical: Ping target down",
		" critical:  Ping target down ",
		"warning: HTTP response slow",
	}, 4)

	if len(evidence) != 2 {
		t.Fatalf("expected deduplicated evidence, got %#v", evidence)
	}
}

func TestTriageStatusDoesNotTreatSlowestAsWarning(t *testing.T) {
	status := triageStatus(100, []string{"DNS 500/500 ok, slowest 90 ms"})
	if status != "ok" {
		t.Fatalf("expected ok status for informational slowest metric, got %q", status)
	}
}
