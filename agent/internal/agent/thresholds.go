package agent

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/infracheck/infracheck/container/agent/internal/verdict"
)

func (a *Agent) applyThresholdHealth(health *verdict.Health) {
	thresholds := a.effectiveThresholds()
	now := time.Now().UTC()
	var additions []verdict.Verdict

	if ping, err := a.db.LatestPing("", 500); err == nil {
		additions = append(additions, thresholdPingVerdicts(now, thresholds, latestPingPerTarget(ping), ping)...)
	}
	if dns, err := a.db.RecentDNS(500); err == nil {
		additions = append(additions, thresholdDNSVerdicts(now, thresholds, latestDNSPerTarget(dns))...)
	}
	if httpRows, err := a.db.RecentHTTP(500); err == nil {
		additions = append(additions, thresholdHTTPVerdicts(now, thresholds, latestHTTPPerTarget(httpRows), httpRows)...)
	}
	if len(additions) == 0 {
		return
	}
	health.Verdicts = removeHealthyVerdict(health.Verdicts)
	health.Verdicts = append(health.Verdicts, additions...)
	for _, item := range additions {
		if item.Severity == "critical" {
			health.Status = "critical"
			break
		}
		if item.Severity == "warning" && health.Status == "healthy" {
			health.Status = "warning"
		}
	}
	if health.Status == "critical" {
		health.OverallHealthScore = minInt(health.OverallHealthScore, 60)
	} else if health.Status == "warning" {
		health.OverallHealthScore = minInt(health.OverallHealthScore, 80)
	}
	health.Recommendations = recommendationsFromVerdicts(health.Verdicts)
}

func thresholdPingVerdicts(now time.Time, thresholds config.ThresholdsConfig, latest []storage.PingResult, all []storage.PingResult) []verdict.Verdict {
	var out []verdict.Verdict
	for _, result := range latest {
		set := thresholdFor(thresholds, result.TargetName, result.TargetHost)
		if !result.Up {
			name := firstNonEmpty(result.TargetName, result.TargetType, "ping target")
			host := firstNonEmpty(result.TargetHost, "unknown host")
			out = append(out, thresholdVerdict(now, "critical", "wan", "ping_target_down", "Ping target down",
				fmt.Sprintf("%s (%s) is unreachable", name, host),
				[]string{fmt.Sprintf("target: %s", name), fmt.Sprintf("host: %s", host), fmt.Sprintf("type: %s", result.TargetType), fmt.Sprintf("error: %s", result.Error)},
				"Check routing, firewall ICMP policy, upstream reachability, and whether this target is still valid."))
			continue
		}
		if set.PacketLossCriticalPercent > 0 && result.LossPercent >= set.PacketLossCriticalPercent {
			out = append(out, pingThresholdVerdict(now, "critical", result, "packet loss critical", fmt.Sprintf("packet loss %.2f%% is above the critical limit %.2f%%", result.LossPercent, set.PacketLossCriticalPercent)))
		} else if set.PacketLossWarningPercent > 0 && result.LossPercent >= set.PacketLossWarningPercent {
			out = append(out, pingThresholdVerdict(now, "warning", result, "packet loss warning", fmt.Sprintf("packet loss %.2f%% is above the warning limit %.2f%%", result.LossPercent, set.PacketLossWarningPercent)))
		}
		if set.LatencyCriticalMS > 0 && result.LatencyMS >= set.LatencyCriticalMS {
			out = append(out, pingThresholdVerdict(now, "critical", result, "latency critical", fmt.Sprintf("latency %.1f ms is above the critical limit %.1f ms", result.LatencyMS, set.LatencyCriticalMS)))
		} else if set.LatencyWarningMS > 0 && result.LatencyMS >= set.LatencyWarningMS {
			out = append(out, pingThresholdVerdict(now, "warning", result, "latency warning", fmt.Sprintf("latency %.1f ms is above the warning limit %.1f ms", result.LatencyMS, set.LatencyWarningMS)))
		}
		if set.LatencyRelativeWarningPercent > 0 && set.LatencyRelativeWindowDays > 0 {
			if baseline, ok := pingBaseline(result, all, set.LatencyRelativeWindowDays); ok {
				limit := baseline * (1 + set.LatencyRelativeWarningPercent/100)
				if result.LatencyMS > limit {
					out = append(out, pingThresholdVerdict(now, "warning", result, "latency above baseline", fmt.Sprintf("latency %.1f ms is above %.1f ms baseline limit (average %.1f ms over %d days, %.0f%% relative warning)", result.LatencyMS, limit, baseline, set.LatencyRelativeWindowDays, set.LatencyRelativeWarningPercent)))
				}
			}
		}
	}
	return out
}

func thresholdDNSVerdicts(now time.Time, thresholds config.ThresholdsConfig, latest []storage.DNSResult) []verdict.Verdict {
	var out []verdict.Verdict
	for _, result := range latest {
		set := thresholdFor(thresholds, dnsKey(result), result.ResolverName, result.ResolverAddress, result.Domain)
		if !result.Success {
			out = append(out, thresholdVerdict(now, "warning", "dns", "dns_lookup_failed", "DNS lookup failed",
				fmt.Sprintf("%s failed for %s %s", result.ResolverName, result.Domain, result.RecordType),
				[]string{fmt.Sprintf("resolver: %s", result.ResolverName), fmt.Sprintf("domain: %s", result.Domain), fmt.Sprintf("record: %s", result.RecordType), fmt.Sprintf("error: %s", result.Error)},
				"Check resolver reachability, DNS server health, firewall UDP/TCP 53 policy, and domain correctness."))
			continue
		}
		if set.DNSDurationCriticalMS > 0 && result.DurationMS >= set.DNSDurationCriticalMS {
			out = append(out, dnsThresholdVerdict(now, "critical", result, fmt.Sprintf("lookup took %.0f ms, above the critical limit %.0f ms", result.DurationMS, set.DNSDurationCriticalMS)))
		} else if set.DNSDurationWarningMS > 0 && result.DurationMS >= set.DNSDurationWarningMS {
			out = append(out, dnsThresholdVerdict(now, "warning", result, fmt.Sprintf("lookup took %.0f ms, above the warning limit %.0f ms", result.DurationMS, set.DNSDurationWarningMS)))
		}
	}
	return out
}

func thresholdHTTPVerdicts(now time.Time, thresholds config.ThresholdsConfig, latest []storage.HTTPResult, all []storage.HTTPResult) []verdict.Verdict {
	var out []verdict.Verdict
	for _, result := range latest {
		set := thresholdFor(thresholds, result.Name, result.URL)
		severity := ""
		var reasons []string
		if set.HTTPDurationCriticalMS > 0 && result.DurationMS >= set.HTTPDurationCriticalMS {
			severity = "critical"
			reasons = append(reasons, fmt.Sprintf("response took %.0f ms, above the critical limit %.0f ms", result.DurationMS, set.HTTPDurationCriticalMS))
		} else if set.HTTPDurationWarningMS > 0 && result.DurationMS >= set.HTTPDurationWarningMS {
			severity = "warning"
			reasons = append(reasons, fmt.Sprintf("response took %.0f ms, above the warning limit %.0f ms", result.DurationMS, set.HTTPDurationWarningMS))
		}
		if set.HTTPRelativeWarningPercent > 0 && set.HTTPRelativeWindowDays > 0 {
			if baseline, ok := httpBaseline(result, all, set.HTTPRelativeWindowDays); ok {
				limit := baseline * (1 + set.HTTPRelativeWarningPercent/100)
				if result.DurationMS > limit {
					if severity == "" {
						severity = "warning"
					}
					reason := fmt.Sprintf("response took %.0f ms, above %.0f ms baseline limit (average %.0f ms over %d days, %.0f%% relative warning)", result.DurationMS, limit, baseline, set.HTTPRelativeWindowDays, set.HTTPRelativeWarningPercent)
					if len(reasons) > 0 {
						reason = fmt.Sprintf("also above %.0f ms baseline limit (average %.0f ms over %d days, %.0f%% relative warning)", limit, baseline, set.HTTPRelativeWindowDays, set.HTTPRelativeWarningPercent)
					}
					reasons = append(reasons, reason)
				}
			}
		}
		if len(reasons) > 0 {
			out = append(out, httpThresholdVerdict(now, severity, result, strings.Join(reasons, "; ")))
		}
		if result.TLSValid && result.TLSDaysUntilExpiry > 0 {
			if set.TLSExpiryCriticalDays > 0 && result.TLSDaysUntilExpiry <= set.TLSExpiryCriticalDays {
				out = append(out, tlsThresholdVerdict(now, "critical", result, set.TLSExpiryCriticalDays))
			} else if set.TLSExpiryWarningDays > 0 && result.TLSDaysUntilExpiry <= set.TLSExpiryWarningDays {
				out = append(out, tlsThresholdVerdict(now, "warning", result, set.TLSExpiryWarningDays))
			}
		}
	}
	return out
}

func thresholdFor(thresholds config.ThresholdsConfig, keys ...string) config.ThresholdSet {
	set := thresholds.Global
	for _, key := range keys {
		if key == "" {
			continue
		}
		if override, ok := thresholds.PerTarget[key]; ok {
			return mergeThreshold(set, override)
		}
	}
	return set
}

func mergeThreshold(base, override config.ThresholdSet) config.ThresholdSet {
	if override.PacketLossWarningPercent != 0 {
		base.PacketLossWarningPercent = override.PacketLossWarningPercent
	}
	if override.PacketLossCriticalPercent != 0 {
		base.PacketLossCriticalPercent = override.PacketLossCriticalPercent
	}
	if override.LatencyWarningMS != 0 {
		base.LatencyWarningMS = override.LatencyWarningMS
	}
	if override.LatencyCriticalMS != 0 {
		base.LatencyCriticalMS = override.LatencyCriticalMS
	}
	if override.LatencyRelativeWarningPercent != 0 {
		base.LatencyRelativeWarningPercent = override.LatencyRelativeWarningPercent
	}
	if override.LatencyRelativeWindowDays != 0 {
		base.LatencyRelativeWindowDays = override.LatencyRelativeWindowDays
	}
	if override.DNSDurationWarningMS != 0 {
		base.DNSDurationWarningMS = override.DNSDurationWarningMS
	}
	if override.DNSDurationCriticalMS != 0 {
		base.DNSDurationCriticalMS = override.DNSDurationCriticalMS
	}
	if override.HTTPDurationWarningMS != 0 {
		base.HTTPDurationWarningMS = override.HTTPDurationWarningMS
	}
	if override.HTTPDurationCriticalMS != 0 {
		base.HTTPDurationCriticalMS = override.HTTPDurationCriticalMS
	}
	if override.HTTPRelativeWarningPercent != 0 {
		base.HTTPRelativeWarningPercent = override.HTTPRelativeWarningPercent
	}
	if override.HTTPRelativeWindowDays != 0 {
		base.HTTPRelativeWindowDays = override.HTTPRelativeWindowDays
	}
	if override.TLSExpiryWarningDays != 0 {
		base.TLSExpiryWarningDays = override.TLSExpiryWarningDays
	}
	if override.TLSExpiryCriticalDays != 0 {
		base.TLSExpiryCriticalDays = override.TLSExpiryCriticalDays
	}
	return base
}

func pingBaseline(current storage.PingResult, all []storage.PingResult, days int) (float64, bool) {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	var values []float64
	for _, item := range all {
		if item.TargetName != current.TargetName || item.TargetHost != current.TargetHost || !item.Up || item.LatencyMS <= 0 || item.Timestamp.Before(cutoff) || item.ID == current.ID {
			continue
		}
		values = append(values, item.LatencyMS)
	}
	return trimmedAverage(values)
}

func httpBaseline(current storage.HTTPResult, all []storage.HTTPResult, days int) (float64, bool) {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	var values []float64
	for _, item := range all {
		if item.Name != current.Name || item.URL != current.URL || !item.Up || item.DurationMS <= 0 || item.Timestamp.Before(cutoff) || item.ID == current.ID {
			continue
		}
		values = append(values, item.DurationMS)
	}
	return trimmedAverage(values)
}

func trimmedAverage(values []float64) (float64, bool) {
	if len(values) < 5 {
		return 0, false
	}
	var sum float64
	var count int
	avg := averageFloat(values)
	for _, value := range values {
		if value <= avg*3 {
			sum += value
			count++
		}
	}
	if count == 0 {
		return 0, false
	}
	return sum / float64(count), true
}

func averageFloat(values []float64) float64 {
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / math.Max(float64(len(values)), 1)
}

func latestPingPerTarget(results []storage.PingResult) []storage.PingResult {
	seen := map[string]storage.PingResult{}
	for _, result := range results {
		if strings.TrimSpace(result.TargetHost) == "" {
			continue
		}
		key := result.TargetName + "|" + result.TargetHost
		if existing, ok := seen[key]; !ok || result.Timestamp.After(existing.Timestamp) {
			seen[key] = result
		}
	}
	out := make([]storage.PingResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out
}

func latestDNSPerTarget(results []storage.DNSResult) []storage.DNSResult {
	seen := map[string]storage.DNSResult{}
	for _, result := range results {
		key := dnsKey(result)
		if existing, ok := seen[key]; !ok || result.Timestamp.After(existing.Timestamp) {
			seen[key] = result
		}
	}
	out := make([]storage.DNSResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out
}

func latestHTTPPerTarget(results []storage.HTTPResult) []storage.HTTPResult {
	seen := map[string]storage.HTTPResult{}
	for _, result := range results {
		key := result.Name + "|" + result.URL
		if existing, ok := seen[key]; !ok || result.Timestamp.After(existing.Timestamp) {
			seen[key] = result
		}
	}
	out := make([]storage.HTTPResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out
}

func dnsKey(result storage.DNSResult) string {
	return result.ResolverName + "|" + result.Domain + "|" + result.RecordType
}

func pingThresholdVerdict(now time.Time, severity string, result storage.PingResult, title, evidence string) verdict.Verdict {
	name := firstNonEmpty(result.TargetName, result.TargetType, "ping target")
	host := firstNonEmpty(result.TargetHost, "unknown host")
	return thresholdVerdict(now, severity, "wan", "ping_threshold", "Ping "+title,
		fmt.Sprintf("%s (%s): %s.", name, host, evidence),
		[]string{fmt.Sprintf("target: %s", name), fmt.Sprintf("host: %s", host), evidence},
		"Compare gateway and internet targets to separate LAN, firewall, and ISP causes.")
}

func dnsThresholdVerdict(now time.Time, severity string, result storage.DNSResult, evidence string) verdict.Verdict {
	return thresholdVerdict(now, severity, "dns", "dns_threshold", "DNS response slow",
		fmt.Sprintf("%s resolving %s %s: %s.", result.ResolverName, result.Domain, result.RecordType, evidence),
		[]string{fmt.Sprintf("resolver: %s", result.ResolverName), fmt.Sprintf("domain: %s", result.Domain), fmt.Sprintf("record: %s", result.RecordType), evidence},
		"Check resolver health, WAN latency, firewall DNS handling, and local DNS server load.")
}

func httpThresholdVerdict(now time.Time, severity string, result storage.HTTPResult, evidence string) verdict.Verdict {
	return thresholdVerdict(now, severity, "service", "http_threshold", "HTTP response slow",
		fmt.Sprintf("%s (%s): %s.", result.Name, result.URL, evidence),
		[]string{fmt.Sprintf("service: %s", result.Name), fmt.Sprintf("url: %s", result.URL), evidence},
		"Compare with WAN latency, DNS timing, proxy path, and upstream service performance.")
}

func tlsThresholdVerdict(now time.Time, severity string, result storage.HTTPResult, threshold int) verdict.Verdict {
	return thresholdVerdict(now, severity, "service", "tls_expiry_threshold", "TLS certificate expiry threshold",
		fmt.Sprintf("%s certificate expires in %d days, below the configured limit of %d days.", result.Name, result.TLSDaysUntilExpiry, threshold),
		[]string{fmt.Sprintf("service: %s", result.Name), fmt.Sprintf("url: %s", result.URL), fmt.Sprintf("days until expiry: %d", result.TLSDaysUntilExpiry), fmt.Sprintf("threshold days: %d", threshold)},
		"Renew or replace the certificate and verify the served chain after deployment.")
}

func thresholdVerdict(now time.Time, severity, category, code, title, summary string, evidence []string, recommendation string) verdict.Verdict {
	return verdict.Verdict{Timestamp: now, Severity: severity, Category: category, Code: code, Title: title, Summary: summary, Evidence: evidence, Recommendation: recommendation}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
