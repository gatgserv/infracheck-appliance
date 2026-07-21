package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/runner"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func (a *Agent) runAdvancedLoop(ctx context.Context) {
	for {
		a.runAdvanced(ctx, false)
		if !waitForNextRun(ctx, a.effectiveTests().Advanced.Duration()) {
			return
		}
	}
}

func (a *Agent) runAdvanced(parent context.Context, force bool) []storage.AdvancedResult {
	targets := a.effectiveTargets().Advanced
	tests := a.effectiveTests()
	ctx, cancel := context.WithTimeout(parent, tests.Advanced.Timeout())
	defer cancel()
	results := []storage.AdvancedResult{}
	save := func(result storage.AdvancedResult) {
		a.applyChangeDetection(&result)
		if result.Severity == "" {
			result.Severity = "info"
		}
		if err := a.db.SaveAdvanced(result); err != nil {
			a.logger.Error("failed to save advanced result", "error", err, "type", result.CheckType)
		}
		results = append(results, result)
	}
	for _, target := range targets.TCP {
		save(a.advanced.TCP(ctx, a.cfg.Site.ID, target))
	}
	if targets.PublicIPEnabled {
		save(a.advanced.PublicIP(ctx, a.cfg.Site.ID))
	}
	if targets.GatewayIdentity {
		save(a.advanced.GatewayIdentity(ctx, a.cfg.Site.ID))
	}
	if targets.NetworkEnv {
		save(a.advanced.NetworkEnv(a.cfg.Site.ID))
	}
	if targets.ProbeHealth {
		save(a.advanced.ProbeHealth(a.cfg.Site.ID))
	}
	if speed := a.speedHistoryCheck(); speed.TargetName != "" {
		save(speed)
	}
	if targets.TLSDetails && (force || a.tlsDetailsDue(tests.TLSDetails.Duration())) {
		tlsCtx, tlsCancel := context.WithTimeout(parent, tests.TLSDetails.Timeout())
		defer tlsCancel()
		for _, target := range a.effectiveTargets().HTTP {
			save(a.advanced.TLSDetails(tlsCtx, a.cfg.Site.ID, target))
		}
	}
	for _, target := range targets.Trace {
		save(a.advanced.Trace(ctx, a.cfg.Site.ID, target))
	}
	for _, target := range targets.NTP {
		save(a.advanced.NTP(ctx, a.cfg.Site.ID, target))
	}
	for _, expectation := range targets.DNSExpectations {
		save(a.runDNSExpectation(ctx, expectation))
	}
	if targets.PortScan.Enabled {
		devices, err := a.db.Devices(a.cfg.Site.ID)
		if err == nil {
			limit := targets.PortScan.Limit
			if limit <= 0 || limit > 128 {
				limit = 32
			}
			ports := targets.PortScan.Ports
			if len(ports) == 0 {
				ports = []int{22, 80, 443, 445, 3389}
			}
			for i, device := range devices {
				if i >= limit {
					break
				}
				if net.ParseIP(device.IP) != nil {
					scan := a.advanced.PortScan(ctx, a.cfg.Site.ID, device, ports)
					save(scan)
					device = a.persistDevicePortScan(device, scan)
					save(classifyDeviceResult(a.cfg.Site.ID, device))
				}
			}
		}
	}
	return results
}

func (a *Agent) tlsDetailsDue(interval time.Duration) bool {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	latest, err := a.db.LatestAdvanced("tls_details", 1)
	if err != nil || len(latest) == 0 {
		return true
	}
	return time.Since(latest[0].Timestamp) >= interval
}

func classifyDeviceResult(siteID string, device storage.Device) storage.AdvancedResult {
	details, _ := json.Marshal(map[string]any{"category": device.Category, "confidence": device.ClassificationConfidence, "evidence": device.ClassificationEvidence, "risk_flags": device.RiskFlags, "open_ports": json.RawMessage(device.OpenPorts), "classifier_version": device.ClassificationVersion})
	return storage.AdvancedResult{
		Timestamp:  time.Now().UTC(),
		SiteID:     siteID,
		CheckType:  "device_classification",
		TargetName: device.IP,
		Target:     device.IP,
		Success:    true,
		Severity:   "info",
		Summary:    "Device classified as " + device.Category + " (" + strings.ToLower(device.ClassificationConfidence) + " confidence)",
		Details:    string(details),
	}
}

func (a *Agent) applyChangeDetection(result *storage.AdvancedResult) {
	if result.CheckType != "public_ip" && result.CheckType != "gateway_identity" && result.CheckType != "network_env" {
		return
	}
	if !result.Success || result.Details == "" {
		return
	}
	previous, err := a.db.LatestAdvanced(result.CheckType, 5)
	if err != nil {
		return
	}
	for _, item := range previous {
		if item.TargetName == result.TargetName && item.Details != "" {
			if item.Details != result.Details {
				result.Severity = "warning"
				result.Success = false
				result.Error = "value changed from previous sample"
				result.Summary += " changed"
			}
			return
		}
	}
}

func (a *Agent) speedHistoryCheck() storage.AdvancedResult {
	results, err := a.db.LatestSpeedtest(20)
	result := storage.AdvancedResult{Timestamp: time.Now().UTC(), SiteID: a.cfg.Site.ID, CheckType: "speed_history", TargetName: "WAN speed trend", Target: "speedtest", Severity: "info"}
	if err != nil || len(results) == 0 {
		return storage.AdvancedResult{}
	}
	latest := results[0]
	var downTotal, upTotal float64
	var count float64
	for _, item := range results[1:] {
		if item.Success && item.DownloadMbps > 0 {
			downTotal += item.DownloadMbps
			upTotal += item.UploadMbps
			count++
		}
	}
	if count < 5 {
		result.Success = true
		result.Summary = "Not enough speed history for baseline"
		return result
	}
	avgDown := downTotal / count
	avgUp := upTotal / count
	thresholds := a.effectiveThresholds().Global
	relative := thresholds.SpeedRelativeWarningPercent
	if relative <= 0 {
		relative = 60
	}
	minDown := thresholds.SpeedDownloadWarningMbps
	downLimitSource := "configured download limit"
	if minDown <= 0 {
		minDown = avgDown * relative / 100
		downLimitSource = fmt.Sprintf("%.0f%% of download baseline", relative)
	}
	minUp := thresholds.SpeedUploadWarningMbps
	upLimitSource := "configured upload limit"
	if minUp <= 0 && avgUp > 0 {
		minUp = avgUp * relative / 100
		upLimitSource = fmt.Sprintf("%.0f%% of upload baseline", relative)
	}
	result.Success = latest.Success && latest.DownloadMbps >= minDown && (minUp == 0 || latest.UploadMbps >= minUp)
	result.Summary = fmt.Sprintf("WAN speed is OK: download %.1f Mbps vs %.1f Mbps average, upload %.1f Mbps vs %.1f Mbps average.", latest.DownloadMbps, avgDown, latest.UploadMbps, avgUp)
	result.Details = fmt.Sprintf(`{"download_mbps":%.2f,"avg_download_mbps":%.2f,"min_download_mbps":%.2f,"download_limit_source":%q,"upload_mbps":%.2f,"avg_upload_mbps":%.2f,"min_upload_mbps":%.2f,"upload_limit_source":%q}`, latest.DownloadMbps, avgDown, minDown, downLimitSource, latest.UploadMbps, avgUp, minUp, upLimitSource)
	if !result.Success {
		result.Severity = "warning"
		result.Error = "WAN speed below configured or baseline-derived limit"
		parts := []string{}
		if !latest.Success {
			parts = append(parts, "the latest speedtest did not complete successfully")
		}
		if latest.DownloadMbps < minDown {
			parts = append(parts, fmt.Sprintf("download %.1f Mbps is below %.1f Mbps (%s, average %.1f Mbps)", latest.DownloadMbps, minDown, downLimitSource, avgDown))
		}
		if minUp > 0 && latest.UploadMbps < minUp {
			parts = append(parts, fmt.Sprintf("upload %.1f Mbps is below %.1f Mbps (%s, average %.1f Mbps)", latest.UploadMbps, minUp, upLimitSource, avgUp))
		}
		result.Summary = "WAN speed warning: " + strings.Join(parts, "; ") + "."
	}
	return result
}

func (a *Agent) runDNSExpectation(ctx context.Context, expectation config.DNSExpectation) storage.AdvancedResult {
	start := time.Now()
	recordType := expectation.RecordType
	if recordType == "" {
		recordType = "A"
	}
	target := runner.DNSTarget{SiteID: a.cfg.Site.ID, ResolverName: expectation.ResolverName, ResolverAddress: expectation.ResolverAddress, Domain: expectation.Domain, RecordType: recordType}
	if target.ResolverName == "" {
		target.ResolverName = "system"
	}
	if target.ResolverAddress == "" {
		target.ResolverAddress = "auto"
	}
	result := storage.AdvancedResult{Timestamp: time.Now().UTC(), SiteID: a.cfg.Site.ID, CheckType: "dns_correctness", TargetName: expectation.Name, Target: expectation.Domain, Severity: "info"}
	if result.TargetName == "" {
		result.TargetName = expectation.Domain
	}
	res := a.dns.Run(ctx, target)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if !res.Success {
		result.Error = res.Error
		result.Severity = "warning"
		result.Summary = "DNS expectation lookup failed"
		return result
	}
	answers, err := net.DefaultResolver.LookupHost(ctx, expectation.Domain)
	if err != nil {
		result.Error = err.Error()
		result.Severity = "warning"
		result.Summary = "DNS correctness lookup failed"
		return result
	}
	sort.Strings(answers)
	expected := append([]string(nil), expectation.Expected...)
	sort.Strings(expected)
	result.Details = strings.Join(answers, ",")
	result.Success = len(expected) == 0 || strings.Join(answers, ",") == strings.Join(expected, ",")
	result.Summary = "DNS answers: " + result.Details
	if !result.Success {
		result.Severity = "warning"
		result.Error = "DNS answers do not match expected values"
	}
	return result
}

func (a *Agent) latestAdvanced(w http.ResponseWriter, r *http.Request) {
	checkType := r.URL.Query().Get("type")
	results, err := a.db.LatestAdvanced(checkType, 300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) runAdvancedNow(w http.ResponseWriter, r *http.Request) {
	results := a.runAdvanced(r.Context(), true)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
