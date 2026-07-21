package agent

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/iperf"
	"github.com/infracheck/infracheck/container/agent/internal/metrics"
	reportgen "github.com/infracheck/infracheck/container/agent/internal/report"
	"github.com/infracheck/infracheck/container/agent/internal/runner"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/infracheck/infracheck/container/agent/internal/verdict"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Agent struct {
	cfg           config.Config
	db            *storage.DB
	logger        *slog.Logger
	metrics       *metrics.Registry
	ping          runner.PingRunner
	dns           runner.DNSRunner
	http          runner.HTTPRunner
	discovery     runner.DiscoveryRunner
	speedtest     runner.SpeedtestRunner
	advanced      runner.AdvancedRunner
	iperf         *iperf.Manager
	udpEcho       *udpEchoManager
	started       time.Time
	mu            sync.RWMutex
	lastPing      []storage.PingResult
	lastDNS       []storage.DNSResult
	lastHTTP      []storage.HTTPResult
	lastDiscovery []storage.Device
	lastSpeedtest []storage.SpeedtestResult
}

func New(cfg config.Config, db *storage.DB, logger *slog.Logger) (*Agent, error) {
	return &Agent{
		cfg:       cfg,
		db:        db,
		logger:    logger,
		metrics:   metrics.New(),
		ping:      runner.PingRunner{Count: 3},
		dns:       runner.DNSRunner{},
		http:      runner.HTTPRunner{},
		discovery: runner.DiscoveryRunner{CIDRs: cfg.Targets.Discovery.CIDRs},
		speedtest: runner.SpeedtestRunner{},
		advanced:  runner.AdvancedRunner{},
		iperf:     iperf.NewManager(iperf.DefaultPort),
		udpEcho:   newUDPEchoManager(5202),
		started:   time.Now().UTC(),
	}, nil
}

func (a *Agent) Start(ctx context.Context) {
	go a.runPingLoop(ctx)
	go a.runDNSLoop(ctx)
	go a.runHTTPLoop(ctx)
	go a.runDiscoveryLoop(ctx)
	go a.runSpeedtestLoop(ctx)
	go a.runAdvancedLoop(ctx)
	go a.runIperfStatusLoop(ctx)
}

func (a *Agent) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.redirectUI)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /config", a.redirectConfig)
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.HandleFunc("GET /ui", a.ui)
	mux.HandleFunc("GET /ui/", a.ui)
	mux.Handle("GET /metrics", a.maybeProtectMetrics(promhttp.HandlerFor(a.metrics.Registry(), promhttp.HandlerOpts{})))
	mux.HandleFunc("GET /api/v1/info", a.maybeProtectReadFunc(a.info))
	mux.HandleFunc("GET /api/v1/tests/ping/latest", a.maybeProtectReadFunc(a.latestPing))
	mux.HandleFunc("POST /api/v1/tests/ping/run", a.requireAdmin(a.runPingNow))
	mux.HandleFunc("GET /api/v1/tests/dns/latest", a.maybeProtectReadFunc(a.latestDNS))
	mux.HandleFunc("POST /api/v1/tests/dns/run", a.requireAdmin(a.runDNSNow))
	mux.HandleFunc("GET /api/v1/tests/http/latest", a.maybeProtectReadFunc(a.latestHTTP))
	mux.HandleFunc("POST /api/v1/tests/http/run", a.requireAdmin(a.runHTTPNow))
	mux.HandleFunc("GET /api/v1/tests/speed/latest", a.maybeProtectReadFunc(a.latestSpeedtest))
	mux.HandleFunc("POST /api/v1/tests/speed/run", a.requireAdmin(a.runSpeedtestNow))
	mux.HandleFunc("GET /api/v1/tests/advanced/latest", a.maybeProtectReadFunc(a.latestAdvanced))
	mux.HandleFunc("POST /api/v1/tests/advanced/run", a.requireAdmin(a.runAdvancedNow))
	mux.HandleFunc("GET /api/v1/diagnostics/dns", a.maybeProtectReadFunc(a.dnsDiagnostics))
	mux.HandleFunc("GET /api/v1/diagnostics/trace", a.maybeProtectReadFunc(a.traceDiagnostics))
	mux.HandleFunc("GET /api/v1/diagnostics/ports", a.maybeProtectReadFunc(a.portHistory))
	mux.HandleFunc("GET /api/v1/topology", a.maybeProtectReadFunc(a.topology))
	mux.HandleFunc("GET /api/v1/iperf/status", a.maybeProtectReadFunc(a.iperfStatus))
	mux.HandleFunc("POST /api/v1/iperf/server/start", a.requireAdmin(a.iperfStart))
	mux.HandleFunc("POST /api/v1/iperf/server/stop", a.requireAdmin(a.iperfStop))
	mux.HandleFunc("GET /api/v1/field/throughput/download", a.requireAdmin(a.fieldThroughputDownload))
	mux.HandleFunc("POST /api/v1/field/throughput/upload", a.requireAdmin(a.fieldThroughputUpload))
	mux.HandleFunc("POST /api/v1/field/udp/start", a.requireAdmin(a.fieldUDPStart))
	mux.HandleFunc("POST /api/v1/field/udp/stop", a.requireAdmin(a.fieldUDPStop))
	mux.HandleFunc("POST /api/v1/field/autotest", a.requireAdmin(a.fieldAutoTest))
	mux.HandleFunc("POST /api/v1/diagnostics/path", a.requireAdmin(a.fieldProgressivePath))
	mux.HandleFunc("POST /api/v1/diagnostics/dhcp-integrity", a.requireAdmin(a.fieldDHCPIntegrity))
	mux.HandleFunc("POST /api/v1/diagnostics/dns-integrity", a.requireAdmin(a.fieldDNSIntegrity))
	mux.HandleFunc("POST /api/v1/topology/snmp", a.requireAdmin(a.fieldSNMPTopology))
	mux.HandleFunc("GET /api/v1/devices", a.maybeProtectReadFunc(a.devices))
	mux.HandleFunc("GET /api/v1/devices/new", a.maybeProtectReadFunc(a.newDevices))
	mux.HandleFunc("GET /api/v1/devices/missing", a.maybeProtectReadFunc(a.missingDevices))
	mux.HandleFunc("GET /api/v1/devices/events", a.maybeProtectReadFunc(a.deviceEvents))
	mux.HandleFunc("GET /api/v1/wifi/observations", a.maybeProtectReadFunc(a.wifiObservations))
	mux.HandleFunc("POST /api/v1/wifi/observations", a.requireAdmin(a.uploadWiFiObservations))
	mux.HandleFunc("GET /api/v1/devices/expectations", a.maybeProtectReadFunc(a.deviceExpectations))
	mux.HandleFunc("PUT /api/v1/devices/{id}/expectation", a.requireAdmin(a.updateDeviceExpectation))
	mux.HandleFunc("PUT /api/v1/devices/{id}", a.requireAdmin(a.updateDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/known", a.requireAdmin(a.markDeviceKnown))
	mux.HandleFunc("POST /api/v1/devices/known", a.requireAdmin(a.markAllDevicesKnown))
	mux.HandleFunc("POST /api/v1/tools/ping", a.requireAdmin(a.toolPing))
	mux.HandleFunc("POST /api/v1/tools/tcp", a.requireAdmin(a.toolTCP))
	mux.HandleFunc("POST /api/v1/tools/dns", a.requireAdmin(a.toolDNS))
	mux.HandleFunc("POST /api/v1/tools/trace", a.requireAdmin(a.toolTrace))
	mux.HandleFunc("POST /api/v1/tools/port-scan", a.requireAdmin(a.toolPortScan))
	mux.HandleFunc("POST /api/v1/tools/device-enrich", a.requireAdmin(a.toolDeviceEnrich))
	mux.HandleFunc("POST /api/v1/tools/topology-refresh", a.requireAdmin(a.toolTopologyRefresh))
	mux.HandleFunc("POST /api/v1/discovery/run", a.requireAdmin(a.runDiscoveryNow))
	mux.HandleFunc("GET /api/v1/health", a.maybeProtectReadFunc(a.health))
	mux.HandleFunc("GET /api/v1/verdicts", a.maybeProtectReadFunc(a.verdicts))
	mux.HandleFunc("GET /api/v1/verdicts/latest", a.maybeProtectReadFunc(a.verdicts))
	mux.HandleFunc("GET /api/v1/recommendations", a.maybeProtectReadFunc(a.recommendations))
	mux.HandleFunc("GET /api/v1/alerts/active", a.maybeProtectReadFunc(a.activeAlerts))
	mux.HandleFunc("GET /api/v1/alerts/unified", a.maybeProtectReadFunc(a.unifiedAlerts))
	mux.HandleFunc("POST /api/v1/alerts/{fingerprint}/ack", a.requireAdmin(a.acknowledgeAlert))
	mux.HandleFunc("POST /api/v1/alerts/{fingerprint}/suppress", a.requireAdmin(a.suppressAlert))
	mux.HandleFunc("POST /api/v1/alerts/{fingerprint}/close", a.requireAdmin(a.closeAlert))
	mux.HandleFunc("GET /api/v1/config", a.maybeProtectReadFunc(a.runtimeConfig))
	mux.HandleFunc("PUT /api/v1/config", a.requireAdmin(a.updateRuntimeConfig))
	mux.HandleFunc("GET /api/v1/config/discovery", a.maybeProtectReadFunc(a.discoveryConfig))
	mux.HandleFunc("PUT /api/v1/config/discovery", a.requireAdmin(a.updateDiscoveryConfig))
	mux.HandleFunc("PUT /api/v1/admin/token", a.requireAdmin(a.updateAdminToken))
	mux.HandleFunc("GET /api/v1/mobile/bootstrap", a.maybeProtectReadFunc(a.mobileBootstrap))
	mux.HandleFunc("GET /api/v1/mobile/summary", a.maybeProtectReadFunc(a.mobileSummary))
	mux.HandleFunc("POST /api/v1/reports/generate", a.requireAdmin(a.generateReport))
	mux.HandleFunc("POST /api/v1/reports/cleanup", a.requireAdmin(a.cleanupReports))
	mux.HandleFunc("GET /api/v1/reports", a.maybeProtectReadFunc(a.reports))
	mux.HandleFunc("GET /api/v1/reports/{id}", a.maybeProtectReadFunc(a.report))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Agent) redirectUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (a *Agent) redirectConfig(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/ui/config", http.StatusFound)
}

func (a *Agent) runDiscoveryLoop(ctx context.Context) {
	for {
		a.runDiscovery(ctx)
		if !waitForNextRun(ctx, a.effectiveTests().Discovery.Duration()) {
			return
		}
	}
}

func (a *Agent) runSpeedtestLoop(ctx context.Context) {
	for {
		if a.effectiveTargets().Speedtest.Enabled {
			a.runSpeedtest(ctx)
		}
		if !waitForNextRun(ctx, a.effectiveTests().Speedtest.Duration()) {
			return
		}
	}
}

func (a *Agent) runIperfStatusLoop(ctx context.Context) {
	record := func() {
		status := a.iperf.Status()
		a.metrics.RecordIperfServer(a.cfg.Site.ID, status.Port, status.Running)
	}

	record()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			record()
		}
	}
}

func (a *Agent) runHTTPLoop(ctx context.Context) {
	for {
		a.runAllHTTPTargets(ctx)
		if !waitForNextRun(ctx, a.effectiveTests().HTTP.Duration()) {
			return
		}
	}
}

func (a *Agent) runPingLoop(ctx context.Context) {
	for {
		a.runAllPingTargets(ctx)
		if !waitForNextRun(ctx, a.effectiveTests().Ping.Duration()) {
			return
		}
	}
}

func (a *Agent) runAllHTTPTargets(parent context.Context) []storage.HTTPResult {
	targets := a.httpTargets()
	results := make([]storage.HTTPResult, 0, len(targets))
	tests := a.effectiveTests()
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(parent, tests.HTTP.Timeout())
		result := a.http.Run(ctx, target)
		cancel()
		if err := a.db.SaveHTTP(result); err != nil {
			a.logger.Error("failed to save http result", "error", err, "target", target.Name)
		}
		if result.Error != "" {
			_ = a.db.SaveEvent("http", "http check failed", result.Error)
		}
		a.metrics.RecordHTTP(result)
		results = append(results, result)
	}
	a.mu.Lock()
	a.lastHTTP = results
	a.mu.Unlock()
	a.recordHealthMetric()
	return results
}

func (a *Agent) runDNSLoop(ctx context.Context) {
	for {
		a.runAllDNSTargets(ctx)
		if !waitForNextRun(ctx, a.effectiveTests().DNS.Duration()) {
			return
		}
	}
}

func (a *Agent) runAllPingTargets(parent context.Context) []storage.PingResult {
	targets := a.pingTargets()
	results := make([]storage.PingResult, 0, len(targets))
	tests := a.effectiveTests()
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(parent, tests.Ping.Timeout())
		result := a.ping.Run(ctx, target)
		cancel()
		if err := a.db.SavePing(result); err != nil {
			a.logger.Error("failed to save ping result", "error", err, "target", target.Name)
		}
		if result.Error != "" {
			_ = a.db.SaveEvent("ping", "ping check failed", result.Error)
		}
		a.metrics.RecordPing(result)
		results = append(results, result)
	}
	a.mu.Lock()
	a.lastPing = results
	a.mu.Unlock()
	a.recordHealthMetric()
	return results
}

func (a *Agent) runAllDNSTargets(parent context.Context) []storage.DNSResult {
	targets := a.dnsTargets()
	results := make([]storage.DNSResult, 0, len(targets))
	tests := a.effectiveTests()
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(parent, tests.DNS.Timeout())
		result := a.dns.Run(ctx, target)
		cancel()
		if err := a.db.SaveDNS(result); err != nil {
			a.logger.Error("failed to save dns result", "error", err, "resolver", target.ResolverName, "domain", target.Domain)
		}
		if result.Error != "" {
			_ = a.db.SaveEvent("dns", "dns check failed", result.Error)
		}
		a.metrics.RecordDNS(result)
		results = append(results, result)
	}
	a.mu.Lock()
	a.lastDNS = results
	a.mu.Unlock()
	a.recordHealthMetric()
	return results
}

func (a *Agent) runDiscovery(parent context.Context) []storage.Device {
	ctx, cancel := context.WithTimeout(parent, a.effectiveTests().Discovery.Timeout())
	defer cancel()
	devices := runner.DiscoveryRunner{CIDRs: a.discoveryCIDRs()}.Run(ctx, a.cfg.Site.ID)
	newCount, err := a.db.UpsertDevices(devices)
	if err != nil {
		a.logger.Error("failed to save discovered devices", "error", err)
		_ = a.db.SaveEvent("discovery", "device discovery save failed", err.Error())
	}
	a.enrichDevices(ctx, devices)
	allDevices, _ := a.db.Devices(a.cfg.Site.ID)
	newDevices, _ := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	missingDevices, _ := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	a.metrics.RecordLAN(a.cfg.Site.ID, len(allDevices), len(newDevices), len(missingDevices))
	if newCount > 0 {
		_ = a.db.SaveEvent("discovery", "new devices detected", strconv.Itoa(newCount))
	}
	a.mu.Lock()
	a.lastDiscovery = devices
	a.mu.Unlock()
	return devices
}

func (a *Agent) enrichDevices(ctx context.Context, devices []storage.Device) {
	enricher := runner.IdentityEnricher{}
	updated := 0
	for _, device := range devices {
		if device.IP == "" || (device.Hostname != "" && device.Vendor != "") {
			continue
		}
		result := enricher.Enrich(ctx, runner.IdentityTarget{IP: device.IP, MAC: device.MAC})
		if result.Hostname == "" && result.Vendor == "" && len(result.Services) == 0 {
			continue
		}
		source := identitySourceLabel(result.Sources)
		if source == "" {
			source = "identity-auto"
		}
		identified, err := a.db.UpdateDeviceIdentityByIP(a.cfg.Site.ID, device.IP, result.Hostname, result.Vendor, source)
		if err != nil {
			a.logger.Debug("device identity enrichment skipped", "error", err, "ip", device.IP)
			continue
		}
		if len(result.Services) > 0 {
			a.persistDeviceServices(identified, result.Services)
		}
		updated++
	}
	if updated > 0 {
		a.logger.Info("device identity enrichment completed", "updated", updated)
	}
}

func identitySourceLabel(sources []runner.IdentitySource) string {
	var names []string
	for _, source := range sources {
		if source.Status == "ok" && source.Source != "" {
			names = append(names, source.Source)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "identity-auto:" + strings.Join(names, "+")
}

func (a *Agent) runSpeedtest(parent context.Context) []storage.SpeedtestResult {
	targetCfg := a.effectiveTargets().Speedtest
	if !targetCfg.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, a.effectiveTests().Speedtest.Timeout())
	defer cancel()
	target := runner.SpeedtestTarget{
		SiteID:        a.cfg.Site.ID,
		Name:          targetCfg.Name,
		DownloadURL:   targetCfg.DownloadURL,
		UploadURL:     targetCfg.UploadURL,
		DownloadBytes: targetCfg.DownloadBytes,
		UploadBytes:   targetCfg.UploadBytes,
	}
	result := a.speedtest.Run(ctx, target)
	if err := a.db.SaveSpeedtest(result); err != nil {
		a.logger.Error("failed to save speedtest result", "error", err)
	}
	if result.DownloadError != "" || result.UploadError != "" {
		_ = a.db.SaveEvent("speedtest", "wan speed test failed", strings.TrimSpace(result.DownloadError+" "+result.UploadError))
	}
	a.metrics.RecordSpeedtest(result)
	results := []storage.SpeedtestResult{result}
	a.mu.Lock()
	a.lastSpeedtest = results
	a.mu.Unlock()
	return results
}

func waitForNextRun(ctx context.Context, interval time.Duration) bool {
	if interval <= 0 {
		interval = time.Minute
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (a *Agent) pingTargets() []runner.PingTarget {
	targetCfg := a.effectiveTargets()
	var targets []runner.PingTarget
	if targetCfg.Gateway.Enabled {
		host := targetCfg.Gateway.Address
		if host == "auto" {
			host = runner.ResolveGateway()
		}
		if host != "" {
			targets = append(targets, runner.PingTarget{
				SiteID: a.cfg.Site.ID,
				Name:   "Gateway",
				Host:   host,
				Type:   "gateway",
			})
		}
	}
	for _, target := range targetCfg.Internet {
		targets = append(targets, runner.PingTarget{
			SiteID: a.cfg.Site.ID,
			Name:   target.Name,
			Host:   target.Host,
			Type:   "internet",
		})
	}
	return targets
}

func (a *Agent) dnsTargets() []runner.DNSTarget {
	targetCfg := a.effectiveTargets()
	recordTypes := []string{"A", "AAAA"}
	targets := make([]runner.DNSTarget, 0, len(targetCfg.DNS.Domains)*len(targetCfg.DNS.Resolvers)*len(recordTypes))
	for _, resolver := range targetCfg.DNS.Resolvers {
		for _, domain := range targetCfg.DNS.Domains {
			for _, recordType := range recordTypes {
				targets = append(targets, runner.DNSTarget{
					SiteID:          a.cfg.Site.ID,
					ResolverName:    resolver.Name,
					ResolverAddress: resolver.Address,
					Domain:          domain,
					RecordType:      recordType,
				})
			}
		}
	}
	return targets
}

func (a *Agent) httpTargets() []runner.HTTPTarget {
	targetCfg := a.effectiveTargets()
	targets := make([]runner.HTTPTarget, 0, len(targetCfg.HTTP))
	for _, target := range targetCfg.HTTP {
		targets = append(targets, runner.HTTPTarget{
			SiteID:         a.cfg.Site.ID,
			Name:           target.Name,
			URL:            target.URL,
			ExpectedStatus: target.ExpectedStatus,
			ExpectedText:   target.ExpectedText,
		})
	}
	return targets
}

func (a *Agent) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *Agent) readyz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *Agent) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       "Infracheck Agent",
		"version":    "0.1.0",
		"site":       a.cfg.Site,
		"started_at": a.started,
		"tests":      a.effectiveTests(),
		"features": []string{
			"health",
			"prometheus_metrics",
			"scheduled_ping",
			"dns_diagnostics",
			"http_checks",
			"wan_speedtest",
			"iperf3_server",
			"mdns_discovery",
			"verdict_engine",
			"sqlite_storage",
		},
	})
}

func (a *Agent) iperfStatus(w http.ResponseWriter, _ *http.Request) {
	status := a.iperf.Status()
	a.metrics.RecordIperfServer(a.cfg.Site.ID, status.Port, status.Running)
	writeJSON(w, http.StatusOK, status)
}

func (a *Agent) iperfStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := a.iperf.Start(ctx)
	a.metrics.RecordIperfServer(a.cfg.Site.ID, status.Port, status.Running)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, status)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *Agent) iperfStop(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := a.iperf.Stop(ctx)
	a.metrics.RecordIperfServer(a.cfg.Site.ID, status.Port, status.Running)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, status)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *Agent) devices(w http.ResponseWriter, _ *http.Request) {
	devices, err := a.db.Devices(a.cfg.Site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	devices = a.ensureDeviceIntelligence(devices)
	a.attachManagedSwitchLocations(devices)
	a.markDeviceInventoryState(devices)
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (a *Agent) newDevices(w http.ResponseWriter, _ *http.Request) {
	devices, err := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for i := range devices {
		devices[i].New = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (a *Agent) missingDevices(w http.ResponseWriter, _ *http.Request) {
	devices, err := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for i := range devices {
		devices[i].Missing = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (a *Agent) markDeviceInventoryState(devices []storage.Device) {
	newDevices, _ := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	missingDevices, _ := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	newIDs := map[int64]struct{}{}
	missingIDs := map[int64]struct{}{}
	for _, device := range newDevices {
		newIDs[device.ID] = struct{}{}
	}
	for _, device := range missingDevices {
		missingIDs[device.ID] = struct{}{}
	}
	for i := range devices {
		_, devices[i].New = newIDs[devices[i].ID]
		_, devices[i].Missing = missingIDs[devices[i].ID]
	}
}

type updateDeviceRequest struct {
	Hostname       string `json:"hostname"`
	Notes          string `json:"notes"`
	MonitorMissing bool   `json:"monitor_missing"`
}

func (a *Agent) updateDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}
	var req updateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	device, err := a.db.UpdateDevice(a.cfg.Site.ID, id, strings.TrimSpace(req.Hostname), strings.TrimSpace(req.Notes), req.MonitorMissing)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
}

func (a *Agent) markDeviceKnown(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}
	device, err := a.db.MarkDeviceKnown(a.cfg.Site.ID, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	device.New = false
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
}

func (a *Agent) markAllDevicesKnown(w http.ResponseWriter, _ *http.Request) {
	count, err := a.db.MarkAllNewDevicesKnown(a.cfg.Site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"marked": count})
}

func (a *Agent) runDiscoveryNow(w http.ResponseWriter, r *http.Request) {
	devices := a.runDiscovery(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (a *Agent) latestHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	results, err := a.db.LatestHTTP(target, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) runHTTPNow(w http.ResponseWriter, r *http.Request) {
	results := a.runAllHTTPTargets(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) latestSpeedtest(w http.ResponseWriter, _ *http.Request) {
	results, err := a.db.LatestSpeedtest(50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) runSpeedtestNow(w http.ResponseWriter, r *http.Request) {
	results := a.runSpeedtest(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) latestPing(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	results, err := a.db.LatestPing(target, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) latestDNS(w http.ResponseWriter, r *http.Request) {
	resolver := r.URL.Query().Get("resolver")
	domain := r.URL.Query().Get("domain")
	results, err := a.db.LatestDNS(resolver, domain, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) runDNSNow(w http.ResponseWriter, r *http.Request) {
	results := a.runAllDNSTargets(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) runPingNow(w http.ResponseWriter, r *http.Request) {
	results := a.runAllPingTargets(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *Agent) health(w http.ResponseWriter, _ *http.Request) {
	health, err := a.evaluateHealth()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (a *Agent) verdicts(w http.ResponseWriter, _ *http.Request) {
	health, err := a.evaluateHealth()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdicts": health.Verdicts})
}

func (a *Agent) recommendations(w http.ResponseWriter, _ *http.Request) {
	health, err := a.evaluateHealth()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recommendations": health.Recommendations})
}

func (a *Agent) mobileBootstrap(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        "Infracheck Agent",
		"version":     "0.1.0",
		"site":        a.cfg.Site,
		"server_time": time.Now().UTC(),
		"auth": map[string]any{
			"read_endpoints_public": a.cfg.Security.AllowPublicReads,
			"metrics_protected":     a.cfg.Security.ProtectMetrics,
			"token_headers":         []string{"Authorization: Bearer <token>", "X-Infracheck-Token"},
		},
		"features": []string{
			"health_summary",
			"ping",
			"dns",
			"http",
			"wan_speedtest",
			"mdns_discovery",
			"iperf3",
			"lan_inventory",
			"reports",
			"alerts",
		},
		"endpoints": map[string]string{
			"summary":         "/api/v1/mobile/summary",
			"health":          "/api/v1/health",
			"verdicts":        "/api/v1/verdicts/latest",
			"recommendations": "/api/v1/recommendations",
			"ping_latest":     "/api/v1/tests/ping/latest",
			"dns_latest":      "/api/v1/tests/dns/latest",
			"http_latest":     "/api/v1/tests/http/latest",
			"speed_latest":    "/api/v1/tests/speed/latest",
			"devices":         "/api/v1/devices",
			"reports":         "/api/v1/reports",
		},
	})
}

func (a *Agent) mobileSummary(w http.ResponseWriter, _ *http.Request) {
	health, err := a.evaluateHealth()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	devices, err := a.db.Devices(a.cfg.Site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	devices = a.ensureDeviceIntelligence(devices)
	newDevices, err := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	missingDevices, err := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	speed, err := a.db.LatestSpeedtest(1)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"site":   a.cfg.Site,
		"health": health,
		"devices": map[string]int{
			"total":   len(devices),
			"new":     len(newDevices),
			"missing": len(missingDevices),
		},
		"latest_speedtest": firstOrNil(speed),
	})
}

type generateReportRequest struct {
	Type           string `json:"type"`
	Format         string `json:"format"`
	Hours          int    `json:"hours"`
	IncludeHistory *bool  `json:"include_history"`
}

func (a *Agent) generateReport(w http.ResponseWriter, r *http.Request) {
	req := generateReportRequest{Type: "daily", Hours: 24}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if req.Hours <= 0 || req.Hours > 24*31 {
		req.Hours = 24
	}
	if req.Type == "" {
		req.Type = "daily"
	}
	if req.Format == "" {
		req.Format = "html"
	}
	currentOnly := strings.EqualFold(req.Type, "current-status-only")
	if currentOnly {
		req.Type = "current-status-only"
		req.Hours = 48
	}
	includeHistory := true
	if req.IncludeHistory != nil {
		includeHistory = *req.IncludeHistory
	}
	if currentOnly {
		includeHistory = false
	}
	periodEnd := time.Now().UTC()
	periodStart := periodEnd.Add(-time.Duration(req.Hours) * time.Hour)
	health, err := a.evaluateHealth()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pingResults, err := a.db.PingSince(a.cfg.Site.ID, periodStart, 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	dnsResults, err := a.db.DNSSince(a.cfg.Site.ID, periodStart, 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpResults, err := a.db.HTTPSince(a.cfg.Site.ID, periodStart, 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	speedResults, err := a.db.SpeedtestSince(a.cfg.Site.ID, periodStart, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	advancedResults, err := a.db.AdvancedSince(a.cfg.Site.ID, periodStart, 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var alerts []storage.AlertRecord
	if includeHistory {
		alerts, err = a.db.AlertRecordsSince(periodStart, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	} else {
		alerts, err = a.db.AlertRecords(true, true, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	devices, err := a.db.Devices(a.cfg.Site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	newDevices, err := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	missingDevices, err := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	input := reportgen.Input{
		Site:           a.cfg.Site,
		Type:           req.Type,
		CurrentOnly:    currentOnly,
		StatsLabel:     reportStatsLabel(req.Hours, currentOnly),
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		Targets:        a.effectiveTargets(),
		Tests:          a.cfg.Tests,
		Health:         health,
		Ping:           pingResults,
		DNS:            dnsResults,
		HTTP:           httpResults,
		Speedtest:      speedResults,
		Advanced:       advancedResults,
		Alerts:         alerts,
		Devices:        devices,
		NewDevices:     newDevices,
		MissingDevices: missingDevices,
	}
	var output reportgen.Output
	if strings.EqualFold(req.Format, "pdf") {
		output, err = reportgen.GeneratePDF(input)
	} else {
		output, err = reportgen.Generate(input)
		req.Format = "html"
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	path, err := reportgen.Write(a.cfg.Reports.Path, output)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	record := storage.Report{
		ID:          output.ID,
		SiteID:      a.cfg.Site.ID,
		Type:        req.Type,
		Title:       output.Title,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Format:      strings.ToLower(req.Format),
		Path:        path,
		CreatedAt:   time.Now().UTC(),
	}
	if err := a.db.SaveReport(record); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (a *Agent) reports(w http.ResponseWriter, _ *http.Request) {
	reports, err := a.db.Reports(a.cfg.Site.ID, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}

func (a *Agent) cleanupReports(w http.ResponseWriter, _ *http.Request) {
	reportsCfg := a.effectiveRuntimeConfig().Reports
	deletedReports := 0
	deletedAlerts := 0
	var err error
	if reportsCfg.RetentionDays > 0 {
		deletedReports, err = a.db.DeleteReportsBefore(a.cfg.Site.ID, time.Now().UTC().Add(-time.Duration(reportsCfg.RetentionDays)*24*time.Hour))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if reportsCfg.AlertHistoryRetentionDays > 0 {
		deletedAlerts, err = a.db.DeleteClosedAlertsBefore(time.Now().UTC().Add(-time.Duration(reportsCfg.AlertHistoryRetentionDays) * 24 * time.Hour))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted_reports":       deletedReports,
		"deleted_alert_records": deletedAlerts,
		"report_retention_days": reportsCfg.RetentionDays,
		"alert_retention_days":  reportsCfg.AlertHistoryRetentionDays,
	})
}

func (a *Agent) report(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	record, err := a.db.Report(a.cfg.Site.ID, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	content, err := os.ReadFile(record.Path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if record.Format == "pdf" {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+record.ID+`.pdf"`)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *Agent) evaluateHealth() (verdict.Health, error) {
	gateway, err := a.db.LatestPingByTargetType("gateway", 20)
	if err != nil {
		return verdict.Health{}, err
	}
	internet, err := a.db.LatestPingByTargetType("internet", 100)
	if err != nil {
		return verdict.Health{}, err
	}
	dnsResults, err := a.db.RecentDNS(200)
	if err != nil {
		return verdict.Health{}, err
	}
	httpResults, err := a.db.RecentHTTP(100)
	if err != nil {
		return verdict.Health{}, err
	}
	health := verdict.Evaluate(verdict.Input{
		Gateway:  gateway,
		Internet: internet,
		DNS:      dnsResults,
		HTTP:     httpResults,
		Now:      time.Now().UTC(),
	})
	a.applyDeviceInventoryHealth(&health)
	a.applyThresholdHealth(&health)
	a.applyAdvancedHealth(&health)
	return health, nil
}

func (a *Agent) applyDeviceInventoryHealth(health *verdict.Health) {
	newDevices, newErr := a.db.NewDevices(a.cfg.Site.ID, 24*time.Hour)
	missingDevices, missingErr := a.db.MissingDevices(a.cfg.Site.ID, 24*time.Hour)
	if newErr != nil || missingErr != nil {
		return
	}
	if len(newDevices) == 0 && len(missingDevices) == 0 {
		return
	}
	health.Verdicts = removeHealthyVerdict(health.Verdicts)
	if len(newDevices) > 0 {
		health.Verdicts = append(health.Verdicts, verdict.Verdict{
			Timestamp:      health.Timestamp,
			Severity:       "info",
			Category:       "inventory",
			Code:           "new_device_detected",
			Title:          "New LAN device detected",
			Summary:        strconv.Itoa(len(newDevices)) + " unreviewed new LAN device(s): " + deviceListSummary(newDevices, 8) + ".",
			Evidence:       append([]string{"new devices: " + strconv.Itoa(len(newDevices))}, deviceEvidence(newDevices, "new device")...),
			Recommendation: "Review the new device list and label expected devices so future inventory changes are easier to triage.",
		})
		if health.DeviceInventoryScore > 90 {
			health.DeviceInventoryScore = 90
		}
	}
	if len(missingDevices) > 0 {
		health.Verdicts = append(health.Verdicts, verdict.Verdict{
			Timestamp:      health.Timestamp,
			Severity:       "warning",
			Category:       "inventory",
			Code:           "known_device_missing",
			Title:          "Known LAN device missing",
			Summary:        strconv.Itoa(len(missingDevices)) + " known LAN device(s) have not been seen recently: " + deviceListSummary(missingDevices, 8) + ".",
			Evidence:       append([]string{"missing devices: " + strconv.Itoa(len(missingDevices))}, deviceEvidence(missingDevices, "missing device")...),
			Recommendation: "Check whether these devices were removed intentionally, powered off, moved to another VLAN, or blocked by switching/firewall policy.",
		})
		if health.DeviceInventoryScore > 70 {
			health.DeviceInventoryScore = 70
		}
		if health.Status == "healthy" {
			health.Status = "warning"
		}
	}
	health.Recommendations = recommendationsFromVerdicts(health.Verdicts)
	health.OverallHealthScore = averageInt(health.WANScore, health.DNSScore, health.GatewayLANScore, health.ServiceAvailability, health.DeviceInventoryScore)
}

func deviceListSummary(devices []storage.Device, limit int) string {
	if len(devices) == 0 {
		return "none"
	}
	if limit <= 0 {
		limit = len(devices)
	}
	parts := make([]string, 0, minInt(len(devices), limit))
	for i, device := range devices {
		if i >= limit {
			break
		}
		label := device.IP
		if device.Hostname != "" {
			label = device.Hostname + " / " + device.IP
		}
		if device.MAC != "" {
			label += " / " + device.MAC
		}
		parts = append(parts, label)
	}
	if len(devices) > limit {
		parts = append(parts, "+"+strconv.Itoa(len(devices)-limit)+" more")
	}
	return strings.Join(parts, ", ")
}

func deviceEvidence(devices []storage.Device, prefix string) []string {
	limit := 12
	out := make([]string, 0, minInt(len(devices), limit))
	for i, device := range devices {
		if i >= limit {
			break
		}
		label := device.IP
		if device.Hostname != "" {
			label = device.Hostname + " (" + device.IP + ")"
		}
		if device.MAC != "" {
			label += " mac " + device.MAC
		}
		if device.Vendor != "" {
			label += " vendor " + device.Vendor
		}
		out = append(out, prefix+": "+label)
	}
	if len(devices) > limit {
		out = append(out, prefix+": +"+strconv.Itoa(len(devices)-limit)+" more devices in LAN inventory")
	}
	return out
}

func removeHealthyVerdict(verdicts []verdict.Verdict) []verdict.Verdict {
	filtered := verdicts[:0]
	for _, item := range verdicts {
		if item.Code != "healthy" {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func recommendationsFromVerdicts(verdicts []verdict.Verdict) []string {
	recommendations := make([]string, 0, len(verdicts))
	for _, item := range verdicts {
		if item.Recommendation != "" {
			recommendations = append(recommendations, item.Recommendation)
		}
	}
	return recommendations
}

func averageInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	total := 0
	for _, value := range values {
		total += value
	}
	return total / len(values)
}

func firstOrNil[T any](items []T) any {
	if len(items) == 0 {
		return nil
	}
	return items[0]
}

func reportStatsLabel(hours int, currentOnly bool) string {
	if currentOnly {
		return "Statistics use the last 48 hours. Historical cleared alerts are not included."
	}
	if hours%24 == 0 {
		days := hours / 24
		if days == 1 {
			return "Statistics use the selected period: last 24 hours."
		}
		return "Statistics use the selected period: last " + strconv.Itoa(days) + " days."
	}
	return "Statistics use the selected period: last " + strconv.Itoa(hours) + " hours."
}

func (a *Agent) recordHealthMetric() {
	health, err := a.evaluateHealth()
	if err != nil {
		a.logger.Debug("failed to evaluate health metrics", "error", err)
		return
	}
	a.metrics.RecordHealth(a.cfg.Site.ID, map[string]int{
		"overall":              health.OverallHealthScore,
		"wan":                  health.WANScore,
		"dns":                  health.DNSScore,
		"gateway_lan":          health.GatewayLANScore,
		"service_availability": health.ServiceAvailability,
		"device_inventory":     health.DeviceInventoryScore,
	})
}

func (a *Agent) maybeProtectRead(next http.Handler) http.Handler {
	if a.cfg.Security.AllowPublicReads {
		return next
	}
	return a.requireRead(next)
}

func (a *Agent) maybeProtectMetrics(next http.Handler) http.Handler {
	if !a.cfg.Security.ProtectMetrics {
		return next
	}
	return a.requireRead(next)
}

func (a *Agent) requireRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.validToken(r, a.cfg.Security.ReadToken) && !a.validToken(r, a.adminToken()) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Agent) maybeProtectReadFunc(next http.HandlerFunc) http.HandlerFunc {
	return a.maybeProtectRead(next).ServeHTTP
}

func (a *Agent) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.validToken(r, a.adminToken()) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *Agent) adminToken() string {
	if a.db != nil {
		raw, ok, err := a.db.Setting(adminTokenSetting)
		if err == nil && ok && strings.TrimSpace(raw) != "" {
			return strings.TrimSpace(raw)
		}
	}
	return a.cfg.Security.AdminToken
}

func (a *Agent) validToken(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	header := r.Header.Get("Authorization")
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header {
		token = r.Header.Get("X-Infracheck-Token")
	}
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
