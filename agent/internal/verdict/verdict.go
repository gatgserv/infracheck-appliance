package verdict

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type Verdict struct {
	Severity       string    `json:"severity"`
	Category       string    `json:"category"`
	Code           string    `json:"code"`
	Title          string    `json:"title"`
	Summary        string    `json:"summary"`
	Evidence       []string  `json:"evidence"`
	Recommendation string    `json:"recommendation"`
	Timestamp      time.Time `json:"timestamp"`
	Metrics        Metrics   `json:"metrics"`
}

type Metrics struct {
	GatewayUp          *bool    `json:"gateway_up,omitempty"`
	GatewayLatencyMS   *float64 `json:"gateway_latency_ms,omitempty"`
	GatewayLossPercent *float64 `json:"gateway_loss_percent,omitempty"`
	InternetUpRatio    *float64 `json:"internet_up_ratio,omitempty"`
	InternetMaxLoss    *float64 `json:"internet_max_loss_percent,omitempty"`
	SystemDNSSuccess   *float64 `json:"system_dns_success_ratio,omitempty"`
	PublicDNSSuccess   *float64 `json:"public_dns_success_ratio,omitempty"`
	HTTPUpRatio        *float64 `json:"http_up_ratio,omitempty"`
	HTTPMaxDurationMS  *float64 `json:"http_max_duration_ms,omitempty"`
	MinTLSDays         *int     `json:"min_tls_days_until_expiry,omitempty"`
}

type Health struct {
	Timestamp            time.Time `json:"timestamp"`
	OverallHealthScore   int       `json:"overall_health_score"`
	WANScore             int       `json:"wan_score"`
	DNSScore             int       `json:"dns_score"`
	GatewayLANScore      int       `json:"gateway_lan_score"`
	ServiceAvailability  int       `json:"service_availability_score"`
	DeviceInventoryScore int       `json:"device_inventory_score"`
	Status               string    `json:"status"`
	Verdicts             []Verdict `json:"verdicts"`
	Recommendations      []string  `json:"recommendations"`
}

type Input struct {
	Gateway  []storage.PingResult
	Internet []storage.PingResult
	DNS      []storage.DNSResult
	HTTP     []storage.HTTPResult
	Now      time.Time
}

func Evaluate(input Input) Health {
	if input.Now.IsZero() {
		input.Now = time.Now().UTC()
	}
	state := summarize(input)
	verdicts := rules(input.Now, state)
	scores := score(state, verdicts)
	status := "healthy"
	for _, v := range verdicts {
		if v.Severity == "critical" {
			status = "critical"
			break
		}
		if v.Severity == "warning" {
			status = "warning"
		}
	}
	recommendations := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		if v.Recommendation != "" {
			recommendations = append(recommendations, v.Recommendation)
		}
	}
	return Health{
		Timestamp:            input.Now,
		OverallHealthScore:   average(scores.wan, scores.dns, scores.gateway, scores.service, scores.inventory),
		WANScore:             scores.wan,
		DNSScore:             scores.dns,
		GatewayLANScore:      scores.gateway,
		ServiceAvailability:  scores.service,
		DeviceInventoryScore: scores.inventory,
		Status:               status,
		Verdicts:             verdicts,
		Recommendations:      recommendations,
	}
}

type summary struct {
	gateway          *storage.PingResult
	internet         []storage.PingResult
	internetUpRatio  float64
	internetMaxLoss  float64
	systemDNSSuccess float64
	publicDNSSuccess float64
	hasDNS           bool
	http             []storage.HTTPResult
	httpUpRatio      float64
	httpMaxDuration  float64
	minTLSDays       *int
}

type scores struct {
	wan       int
	dns       int
	gateway   int
	service   int
	inventory int
}

func summarize(input Input) summary {
	s := summary{internetUpRatio: 1, systemDNSSuccess: 1, publicDNSSuccess: 1}
	if len(input.Gateway) > 0 {
		s.gateway = &input.Gateway[0]
	}
	s.internet = latestPerTarget(input.Internet)
	if len(s.internet) > 0 {
		var up int
		for _, r := range s.internet {
			if r.Up {
				up++
			}
			s.internetMaxLoss = math.Max(s.internetMaxLoss, r.LossPercent)
		}
		s.internetUpRatio = float64(up) / float64(len(s.internet))
	}
	systemSuccess, systemTotal, publicSuccess, publicTotal := 0, 0, 0, 0
	for _, r := range latestDNSPerKey(input.DNS) {
		s.hasDNS = true
		if r.ResolverName == "system" || r.ResolverAddress == "auto" {
			systemTotal++
			if r.Success {
				systemSuccess++
			}
			continue
		}
		publicTotal++
		if r.Success {
			publicSuccess++
		}
	}
	if systemTotal > 0 {
		s.systemDNSSuccess = float64(systemSuccess) / float64(systemTotal)
	}
	if publicTotal > 0 {
		s.publicDNSSuccess = float64(publicSuccess) / float64(publicTotal)
	}
	s.http = latestHTTPPerTarget(input.HTTP)
	if len(s.http) > 0 {
		var up int
		for _, r := range s.http {
			if r.Up {
				up++
			}
			s.httpMaxDuration = math.Max(s.httpMaxDuration, r.DurationMS)
			if r.TLSDaysUntilExpiry > 0 {
				days := r.TLSDaysUntilExpiry
				if s.minTLSDays == nil || days < *s.minTLSDays {
					s.minTLSDays = &days
				}
			}
		}
		s.httpUpRatio = float64(up) / float64(len(s.http))
	}
	return s
}

func rules(now time.Time, s summary) []Verdict {
	var verdicts []Verdict
	if s.gateway != nil && (!s.gateway.Up || s.gateway.LossPercent > 1 || s.gateway.LatencyMS > 20) {
		v := base(now, "critical", "gateway", "local_gateway_unstable", "Local gateway unstable")
		v.Summary = "The local gateway is unreachable, dropping packets, or responding with high latency."
		v.Evidence = []string{
			fmt.Sprintf("gateway up: %t", s.gateway.Up),
			fmt.Sprintf("gateway latency: %.2f ms", s.gateway.LatencyMS),
			fmt.Sprintf("gateway packet loss: %.2f%%", s.gateway.LossPercent),
		}
		v.Recommendation = "Check the router, switch path, cabling, VLAN, and local gateway load before escalating to the ISP."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	if s.gateway != nil && s.gateway.Up && s.gateway.LossPercent == 0 && s.internetMaxLoss > 3 {
		v := base(now, "warning", "wan", "upstream_packet_loss", "Upstream packet loss detected")
		v.Summary = "The local gateway looks healthy while internet targets show packet loss."
		v.Evidence = []string{
			"gateway packet loss: 0.00%",
			fmt.Sprintf("internet max packet loss: %.2f%%", s.internetMaxLoss),
		}
		v.Recommendation = "Collect WAN latency/loss evidence and check ISP handoff, modem, firewall WAN interface, and provider status."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	if len(s.internet) > 0 && s.internetUpRatio == 0 {
		v := base(now, "critical", "wan", "internet_unreachable", "Internet unreachable")
		v.Summary = "All configured internet ping targets are currently unreachable."
		v.Evidence = []string{fmt.Sprintf("internet targets reachable: %.0f%%", s.internetUpRatio*100)}
		v.Recommendation = "Check WAN connectivity, firewall egress policy, DNS-independent routing, and ISP status."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	if s.hasDNS && s.systemDNSSuccess < 0.9 && s.publicDNSSuccess >= 0.95 {
		v := base(now, "warning", "dns", "local_dns_problem", "Local DNS problem")
		v.Summary = "The system resolver is failing while public resolvers are working."
		v.Evidence = []string{
			fmt.Sprintf("system DNS success: %.0f%%", s.systemDNSSuccess*100),
			fmt.Sprintf("public DNS success: %.0f%%", s.publicDNSSuccess*100),
		}
		v.Recommendation = "Check DNS configured on the router/DHCP scope or temporarily compare clients against 1.1.1.1 and 8.8.8.8."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	if s.hasDNS && s.systemDNSSuccess < 0.9 && s.publicDNSSuccess < 0.9 {
		v := base(now, "critical", "dns", "dns_general_outage", "DNS resolution failing")
		v.Summary = "Both system and public resolver checks are failing."
		v.Evidence = []string{
			fmt.Sprintf("system DNS success: %.0f%%", s.systemDNSSuccess*100),
			fmt.Sprintf("public DNS success: %.0f%%", s.publicDNSSuccess*100),
		}
		v.Recommendation = "Check WAN reachability, firewall UDP/TCP 53 policy, and resolver availability."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	for _, service := range s.http {
		if !service.Up {
			v := base(now, "warning", "service", "service_down", "Service unavailable")
			v.Summary = "A configured HTTP service check is failing."
			v.Evidence = []string{
				fmt.Sprintf("service: %s", service.Name),
				fmt.Sprintf("url: %s", service.URL),
				fmt.Sprintf("status code: %d", service.StatusCode),
				fmt.Sprintf("error: %s", service.Error),
			}
			v.Recommendation = "Check the remote service, firewall policy, proxy path, DNS result, and certificate chain for this URL."
			v.Metrics = metricsFor(s)
			verdicts = append(verdicts, v)
		}
		if service.Up && service.DurationMS > 3000 {
			v := base(now, "warning", "service", "service_slow", "Service response slow")
			v.Summary = "A configured HTTP service is responding slowly."
			v.Evidence = []string{
				fmt.Sprintf("service: %s", service.Name),
				fmt.Sprintf("duration: %.2f ms", service.DurationMS),
			}
			v.Recommendation = "Compare with WAN latency and check application, proxy, and upstream service performance."
			v.Metrics = metricsFor(s)
			verdicts = append(verdicts, v)
		}
		if !service.TLSValid {
			v := base(now, "critical", "service", "tls_invalid", "TLS certificate invalid")
			v.Summary = "A configured HTTPS endpoint presented an invalid certificate or TLS validation failed."
			v.Evidence = []string{fmt.Sprintf("service: %s", service.Name), fmt.Sprintf("url: %s", service.URL), service.Error}
			v.Recommendation = "Inspect the certificate chain, hostname, expiry, and any TLS interception devices."
			v.Metrics = metricsFor(s)
			verdicts = append(verdicts, v)
		}
		if service.TLSValid && service.TLSDaysUntilExpiry > 0 && service.TLSDaysUntilExpiry <= 14 {
			v := base(now, "warning", "service", "tls_expiring", "TLS certificate expiring soon")
			v.Summary = "A configured HTTPS endpoint certificate is close to expiry."
			v.Evidence = []string{
				fmt.Sprintf("service: %s", service.Name),
				fmt.Sprintf("days until expiry: %d", service.TLSDaysUntilExpiry),
			}
			v.Recommendation = "Renew or replace the certificate before expiry and confirm the served chain after deployment."
			v.Metrics = metricsFor(s)
			verdicts = append(verdicts, v)
		}
	}
	if len(verdicts) == 0 {
		v := base(now, "info", "overall", "healthy", "Network checks healthy")
		v.Summary = "No active gateway, WAN, or DNS problems were detected from the latest samples."
		v.Evidence = []string{"latest gateway, internet, and DNS checks are within current thresholds"}
		v.Recommendation = "Continue monitoring and review trends if users report intermittent symptoms."
		v.Metrics = metricsFor(s)
		verdicts = append(verdicts, v)
	}
	return verdicts
}

func score(s summary, verdicts []Verdict) scores {
	out := scores{wan: 100, dns: 100, gateway: 100, service: 100, inventory: 100}
	if len(s.internet) > 0 {
		out.wan = clamp(int(100 - s.internetMaxLoss*10))
		if s.internetUpRatio < 1 {
			out.wan = clamp(int(s.internetUpRatio * 80))
		}
	}
	if s.gateway != nil {
		out.gateway = 100
		if !s.gateway.Up {
			out.gateway = 0
		} else if s.gateway.LossPercent > 0 {
			out.gateway = clamp(100 - int(s.gateway.LossPercent*30))
		} else if s.gateway.LatencyMS > 20 {
			out.gateway = 70
		}
	}
	if s.hasDNS {
		out.dns = clamp(int(((s.systemDNSSuccess * 0.6) + (s.publicDNSSuccess * 0.4)) * 100))
	}
	if len(s.http) > 0 {
		out.service = clamp(int(s.httpUpRatio * 100))
		if s.httpMaxDuration > 3000 && out.service > 70 {
			out.service = 70
		}
		if s.minTLSDays != nil && *s.minTLSDays <= 14 && out.service > 80 {
			out.service = 80
		}
	}
	for _, v := range verdicts {
		if v.Severity == "critical" && v.Category == "wan" {
			out.wan = min(out.wan, 20)
		}
	}
	return out
}

func base(now time.Time, severity, category, code, title string) Verdict {
	return Verdict{Timestamp: now, Severity: severity, Category: category, Code: code, Title: title}
}

func metricsFor(s summary) Metrics {
	m := Metrics{}
	if s.gateway != nil {
		m.GatewayUp = &s.gateway.Up
		m.GatewayLatencyMS = &s.gateway.LatencyMS
		m.GatewayLossPercent = &s.gateway.LossPercent
	}
	m.InternetUpRatio = &s.internetUpRatio
	m.InternetMaxLoss = &s.internetMaxLoss
	if s.hasDNS {
		m.SystemDNSSuccess = &s.systemDNSSuccess
		m.PublicDNSSuccess = &s.publicDNSSuccess
	}
	if len(s.http) > 0 {
		m.HTTPUpRatio = &s.httpUpRatio
		m.HTTPMaxDurationMS = &s.httpMaxDuration
		m.MinTLSDays = s.minTLSDays
	}
	return m
}

func latestPerTarget(results []storage.PingResult) []storage.PingResult {
	seen := map[string]storage.PingResult{}
	for _, result := range results {
		key := result.TargetName + "|" + result.TargetHost
		if existing, ok := seen[key]; !ok || result.Timestamp.After(existing.Timestamp) {
			seen[key] = result
		}
	}
	out := make([]storage.PingResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetName < out[j].TargetName })
	return out
}

func latestDNSPerKey(results []storage.DNSResult) []storage.DNSResult {
	seen := map[string]storage.DNSResult{}
	for _, result := range results {
		key := result.ResolverName + "|" + result.Domain + "|" + result.RecordType
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
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func average(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	var total int
	for _, value := range values {
		total += value
	}
	return total / len(values)
}

func clamp(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
