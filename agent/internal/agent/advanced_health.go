package agent

import (
	"fmt"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/infracheck/infracheck/container/agent/internal/verdict"
)

func (a *Agent) applyAdvancedHealth(health *verdict.Health) {
	results, err := a.db.LatestAdvanced("", 500)
	if err != nil {
		return
	}
	latest := latestAdvancedPerTarget(results)
	active := a.activeAdvancedChecks()
	var additions []verdict.Verdict
	for _, result := range latest {
		if !activeAdvancedResult(active, result) {
			continue
		}
		if result.Severity != "warning" && result.Severity != "critical" {
			continue
		}
		additions = append(additions, verdict.Verdict{
			Timestamp:      time.Now().UTC(),
			Severity:       result.Severity,
			Category:       "advanced",
			Code:           result.CheckType,
			Title:          advancedTitle(result),
			Summary:        result.Summary,
			Evidence:       []string{fmt.Sprintf("type: %s", result.CheckType), fmt.Sprintf("target: %s", result.Target), fmt.Sprintf("error: %s", result.Error)},
			Recommendation: advancedRecommendation(result),
		})
	}
	if len(additions) == 0 {
		return
	}
	health.Verdicts = removeHealthyVerdict(health.Verdicts)
	health.Verdicts = append(health.Verdicts, additions...)
	for _, item := range additions {
		if item.Severity == "critical" {
			health.Status = "critical"
			health.OverallHealthScore = minInt(health.OverallHealthScore, 60)
			break
		}
		if item.Severity == "warning" && health.Status == "healthy" {
			health.Status = "warning"
			health.OverallHealthScore = minInt(health.OverallHealthScore, 80)
		}
	}
	health.Recommendations = recommendationsFromVerdicts(health.Verdicts)
}

func (a *Agent) activeAdvancedChecks() map[string]bool {
	targets := a.effectiveTargets()
	advanced := targets.Advanced
	active := map[string]bool{
		"speed_history|WAN speed trend|speedtest": true,
	}
	if advanced.PublicIPEnabled {
		active["public_ip|Public IP|https://api.ipify.org"] = true
	}
	if advanced.GatewayIdentity {
		active["gateway_identity"] = true
	}
	if advanced.NetworkEnv {
		active["network_env|Network environment|local"] = true
	}
	if advanced.ProbeHealth {
		active["probe_health|Appliance health|local"] = true
	}
	if advanced.TLSDetails {
		for _, target := range targets.HTTP {
			active["tls_details|"+target.Name+"|"+target.URL] = true
		}
	}
	for _, target := range advanced.TCP {
		active["tcp|"+target.Name+"|"+target.Host+":"+fmt.Sprint(target.Port)] = true
	}
	for _, target := range advanced.Trace {
		active["trace|"+target.Name+"|"+target.Host] = true
	}
	for _, target := range advanced.NTP {
		active["ntp|"+target.Name+"|"+target.Host] = true
	}
	for _, expectation := range advanced.DNSExpectations {
		name := expectation.Name
		if name == "" {
			name = expectation.Domain
		}
		active["dns_correctness|"+name+"|"+expectation.Domain] = true
	}
	return active
}

func activeAdvancedResult(active map[string]bool, result storage.AdvancedResult) bool {
	if active[result.CheckType+"|"+result.TargetName+"|"+result.Target] {
		return true
	}
	return active[result.CheckType]
}

func advancedTitle(result storage.AdvancedResult) string {
	switch result.CheckType {
	case "tcp":
		return "TCP port check failed"
	case "public_ip":
		return "Public IP check failed"
	case "gateway_identity":
		return "Gateway identity check failed"
	case "trace":
		return "Trace check failed"
	case "ntp":
		return "NTP check failed"
	case "speed_history":
		return "WAN speed below baseline"
	case "dns_correctness":
		return "DNS correctness check failed"
	default:
		return result.CheckType + " check needs attention"
	}
}

func advancedRecommendation(result storage.AdvancedResult) string {
	switch result.CheckType {
	case "tcp":
		return "Confirm this port is expected to be reachable from the probe; otherwise disable this TCP target or correct the host/port."
	case "public_ip":
		return "Public IP checks need outbound HTTPS/DNS; disable this check if the probe has restricted internet access."
	case "gateway_identity":
		return "Run discovery or ping the gateway so the neighbor table contains its MAC; disable if the gateway is on a routed segment."
	case "trace":
		return "Traceroute often needs ICMP/UDP support through firewalls; disable it if path tracing is blocked by policy."
	case "ntp":
		return "Check DNS and outbound UDP/123, or use an internal NTP server target."
	case "speed_history":
		return "Review recent speedtest results; adjust the baseline threshold if this speed is acceptable for the site."
	case "dns_correctness":
		return "Compare the expected DNS answers with the resolver result and update the expectation if the record changed intentionally."
	default:
		return "Review this check in the dashboard and adjust its target or threshold if it is not applicable."
	}
}

func latestAdvancedPerTarget(results []storage.AdvancedResult) []storage.AdvancedResult {
	seen := map[string]storage.AdvancedResult{}
	for _, result := range results {
		key := result.CheckType + "|" + result.TargetName + "|" + result.Target
		if existing, ok := seen[key]; !ok || result.Timestamp.After(existing.Timestamp) {
			seen[key] = result
		}
	}
	out := make([]storage.AdvancedResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out
}
