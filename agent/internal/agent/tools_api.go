package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/runner"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type toolPingRequest struct {
	Host  string `json:"host"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type toolTCPRequest struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
}

type toolDNSRequest struct {
	Domain          string   `json:"domain"`
	ResolverName    string   `json:"resolver_name"`
	ResolverAddress string   `json:"resolver_address"`
	RecordTypes     []string `json:"record_types"`
}

type toolTraceRequest struct {
	Host string `json:"host"`
	Name string `json:"name"`
}

type toolPortScanRequest struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
	Name  string `json:"name"`
}

type toolDeviceEnrichRequest struct {
	IP string `json:"ip"`
}

func (a *Agent) toolPing(w http.ResponseWriter, r *http.Request) {
	var req toolPingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	if net.ParseIP(host) == nil && host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	}
	count := req.Count
	if count <= 0 || count > 10 {
		count = 3
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	result := runner.PingRunner{Count: count}.Run(ctx, runner.PingTarget{
		SiteID: a.cfg.Site.ID,
		Name:   nonEmpty(req.Name, host),
		Host:   host,
		Type:   "ad_hoc",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"result":  result,
		"summary": pingToolSummary(result),
	})
}

func (a *Agent) toolTCP(w http.ResponseWriter, r *http.Request) {
	var req toolTCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Host) == "" || req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid host and port are required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result := a.advanced.TCP(ctx, a.cfg.Site.ID, config.TCPTarget{
		Name: nonEmpty(req.Name, req.Host+":"+strconv.Itoa(req.Port)),
		Host: strings.TrimSpace(req.Host),
		Port: req.Port,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"result":  result,
		"summary": tcpToolSummary(result),
	})
}

func (a *Agent) toolDNS(w http.ResponseWriter, r *http.Request) {
	var req toolDNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	domain := strings.TrimSpace(strings.TrimSuffix(req.Domain, "."))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	recordTypes := sanitizeRecordTypes(req.RecordTypes)
	if len(recordTypes) == 0 {
		recordTypes = []string{"A", "AAAA"}
	}
	resolverAddress := strings.TrimSpace(req.ResolverAddress)
	resolverName := nonEmpty(req.ResolverName, nonEmpty(resolverAddress, "system"))
	results := make([]storage.DNSResult, 0, len(recordTypes))
	for _, recordType := range recordTypes {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		result := a.dns.Run(ctx, runner.DNSTarget{
			SiteID:          a.cfg.Site.ID,
			ResolverName:    resolverName,
			ResolverAddress: resolverAddress,
			Domain:          domain,
			RecordType:      recordType,
		})
		cancel()
		if err := a.db.SaveDNS(result); err != nil {
			a.logger.Error("failed to save manual dns result", "error", err, "domain", domain)
		}
		a.metrics.RecordDNS(result)
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"summary": dnsToolSummary(results),
	})
}

func (a *Agent) toolTrace(w http.ResponseWriter, r *http.Request) {
	var req toolTraceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	result := a.advanced.Trace(ctx, a.cfg.Site.ID, config.HostTarget{Name: nonEmpty(req.Name, host), Host: host})
	if err := a.db.SaveAdvanced(result); err != nil {
		a.logger.Error("failed to save manual trace result", "error", err, "target", host)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":  result,
		"hops":    parseTraceHops(result.Details),
		"summary": traceToolSummary(result),
	})
}

func (a *Agent) toolPortScan(w http.ResponseWriter, r *http.Request) {
	var req toolPortScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	}
	ports := sanitizePorts(req.Ports)
	if len(ports) == 0 {
		ports = []int{22, 80, 443, 445, 3389, 8080, 8443}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	result := a.advanced.PortScan(ctx, a.cfg.Site.ID, storage.Device{IP: host}, ports)
	if req.Name != "" {
		result.TargetName = strings.TrimSpace(req.Name)
	}
	if err := a.db.SaveAdvanced(result); err != nil {
		a.logger.Error("failed to save manual port scan result", "error", err, "host", host)
	}
	open := parsePortList(result.Details)
	devices, _ := a.db.Devices(a.cfg.Site.ID)
	for _, device := range devices {
		if device.IP == host {
			a.persistDevicePortScan(device, result)
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":       host,
		"ports":      ports,
		"open_ports": open,
		"result":     result,
		"summary":    portScanSummary(host, open, len(ports)),
	})
}

func (a *Agent) toolDeviceEnrich(w http.ResponseWriter, r *http.Request) {
	var req toolDeviceEnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ip := strings.TrimSpace(req.IP)
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid IP is required"})
		return
	}
	devices, _ := a.db.Devices(a.cfg.Site.ID)
	mac := ""
	for _, device := range devices {
		if device.IP == ip {
			mac = device.MAC
			break
		}
	}
	result := runner.IdentityEnricher{}.Enrich(r.Context(), runner.IdentityTarget{IP: ip, MAC: mac})
	hostname := result.Hostname
	now := time.Now().UTC()
	enriched, err := a.db.UpdateDeviceIdentityByIP(a.cfg.Site.ID, ip, hostname, result.Vendor, identityToolSourceLabel(result.Sources))
	if errors.Is(err, sql.ErrNoRows) {
		_, err = a.db.UpsertDevices([]storage.Device{{
			SiteID:    a.cfg.Site.ID,
			IP:        ip,
			MAC:       mac,
			Vendor:    result.Vendor,
			Hostname:  hostname,
			FirstSeen: now,
			LastSeen:  now,
			Source:    "identity-tool",
		}})
		if err == nil {
			devices, _ := a.db.Devices(a.cfg.Site.ID)
			for _, device := range devices {
				if device.IP == ip {
					enriched = device
					break
				}
			}
		}
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(result.Services) > 0 {
		enriched = a.persistDeviceServices(enriched, result.Services)
	}
	summary := "Identity enrichment completed for " + ip
	if hostname != "" {
		summary += ": hostname " + hostname
	} else {
		summary += ": no hostname found"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device":   enriched,
		"hostname": hostname,
		"vendor":   result.Vendor,
		"services": result.Services,
		"sources":  result.Sources,
		"summary":  summary,
	})
}

func identityToolSourceLabel(sources []runner.IdentitySource) string {
	label := identitySourceLabel(sources)
	if label == "" {
		return "identity-tool"
	}
	return strings.Replace(label, "identity-auto:", "identity-tool:", 1)
}

func (a *Agent) toolTopologyRefresh(w http.ResponseWriter, r *http.Request) {
	found := a.runDiscovery(r.Context())
	devices, _ := a.db.Devices(a.cfg.Site.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":       fmt.Sprintf("Topology refreshed: %d device(s) seen in this run, %d total known device(s).", len(found), len(devices)),
		"run_devices":   found,
		"known_devices": devices,
		"gateway":       firstNonEmpty(a.effectiveTargets().Gateway.Address, runner.ResolveGateway()),
	})
}

func sanitizePorts(input []int) []int {
	out := make([]int, 0, len(input))
	seen := map[int]struct{}{}
	for _, port := range input {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func sanitizeRecordTypes(input []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range input {
		recordType := strings.ToUpper(strings.TrimSpace(item))
		if recordType != "A" && recordType != "AAAA" {
			continue
		}
		if _, ok := seen[recordType]; ok {
			continue
		}
		seen[recordType] = struct{}{}
		out = append(out, recordType)
	}
	return out
}

func pingToolSummary(result storage.PingResult) string {
	if result.Up {
		return fmt.Sprintf("%s is reachable: %.1f ms average latency, %.1f%% loss, %.1f ms jitter.", result.TargetHost, result.LatencyMS, result.LossPercent, result.JitterMS)
	}
	if result.Error != "" {
		return fmt.Sprintf("%s is not reachable: %.1f%% loss. Error: %s", result.TargetHost, result.LossPercent, result.Error)
	}
	return fmt.Sprintf("%s is not reachable: %.1f%% loss.", result.TargetHost, result.LossPercent)
}

func dnsToolSummary(results []storage.DNSResult) string {
	if len(results) == 0 {
		return "DNS diagnostic returned no result."
	}
	ok := 0
	maxDuration := 0.0
	failed := []string{}
	for _, result := range results {
		if result.Success {
			ok++
		} else {
			failed = append(failed, result.RecordType+": "+nonEmpty(result.Error, "failed"))
		}
		if result.DurationMS > maxDuration {
			maxDuration = result.DurationMS
		}
	}
	first := results[0]
	summary := fmt.Sprintf("DNS %s via %s: %d/%d lookup(s) succeeded, slowest %.0f ms.", first.Domain, nonEmpty(first.ResolverAddress, first.ResolverName), ok, len(results), maxDuration)
	if len(failed) > 0 {
		summary += " Failed: " + strings.Join(failed, "; ")
	}
	return summary
}

func traceToolSummary(result storage.AdvancedResult) string {
	hops := parseTraceHops(result.Details)
	if result.Success {
		return fmt.Sprintf("Trace to %s completed in %.0f ms with %d parsed hop(s).", result.Target, result.DurationMS, len(hops))
	}
	if result.Error != "" {
		return fmt.Sprintf("Trace to %s failed after %.0f ms: %s", result.Target, result.DurationMS, result.Error)
	}
	return fmt.Sprintf("Trace to %s failed after %.0f ms.", result.Target, result.DurationMS)
}

func tcpToolSummary(result storage.AdvancedResult) string {
	if result.Success {
		return fmt.Sprintf("%s is reachable on %s in %.0f ms.", result.TargetName, result.Target, result.DurationMS)
	}
	if result.Error != "" {
		return fmt.Sprintf("%s is not reachable on %s. Error: %s", result.TargetName, result.Target, result.Error)
	}
	return fmt.Sprintf("%s is not reachable on %s.", result.TargetName, result.Target)
}

func portScanSummary(host string, open []int, total int) string {
	if len(open) == 0 {
		return fmt.Sprintf("%s has no open ports among %d checked common ports.", host, total)
	}
	parts := make([]string, 0, len(open))
	for _, port := range open {
		parts = append(parts, strconv.Itoa(port))
	}
	return fmt.Sprintf("%s has %d open port(s): %s.", host, len(open), strings.Join(parts, ", "))
}

func reverseLookupName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
	if name == ip {
		return ""
	}
	return name
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
