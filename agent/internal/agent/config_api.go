package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
)

const (
	discoveryCIDRsSetting = "discovery.cidrs"
	runtimeConfigSetting  = "runtime.config"
	adminTokenSetting     = "security.admin_token"
)

type runtimeConfigData struct {
	Targets    config.TargetsConfig    `json:"targets"`
	Thresholds config.ThresholdsConfig `json:"thresholds"`
	Reports    config.ReportsConfig    `json:"reports"`
	Tests      config.TestsConfig      `json:"tests"`
}

type runtimeConfigResponse struct {
	Effective runtimeConfigData  `json:"effective"`
	Runtime   *runtimeConfigData `json:"runtime,omitempty"`
	YAML      runtimeConfigData  `json:"yaml"`
	Source    string             `json:"source"`
}

type discoveryConfigResponse struct {
	CIDRs     []string `json:"cidrs"`
	Source    string   `json:"source"`
	YAMLCIDRs []string `json:"yaml_cidrs"`
}

type updateDiscoveryConfigRequest struct {
	CIDRs []string `json:"cidrs"`
}

func (a *Agent) discoveryConfig(w http.ResponseWriter, _ *http.Request) {
	cidrs, source := a.discoveryCIDRsWithSource()
	writeJSON(w, http.StatusOK, discoveryConfigResponse{
		CIDRs:     cidrs,
		Source:    source,
		YAMLCIDRs: a.cfg.Targets.Discovery.CIDRs,
	})
}

func (a *Agent) updateDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	var req updateDiscoveryConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cidrs := normalizeCIDRs(req.CIDRs)
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CIDR: " + cidr})
			return
		}
	}
	raw, err := json.Marshal(cidrs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := a.db.SetSetting(discoveryCIDRsSetting, string(raw)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if runtime, ok := a.runtimeConfigFromDB(); ok {
		runtime.Targets.Discovery.CIDRs = cidrs
		_ = a.saveRuntimeConfig(runtime)
	}
	writeJSON(w, http.StatusOK, discoveryConfigResponse{
		CIDRs:     cidrs,
		Source:    "database",
		YAMLCIDRs: a.cfg.Targets.Discovery.CIDRs,
	})
}

func (a *Agent) runtimeConfig(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := a.runtimeConfigFromDB()
	source := "yaml"
	var runtimePtr *runtimeConfigData
	if ok {
		source = "database"
		runtimePtr = &runtime
	}
	writeJSON(w, http.StatusOK, runtimeConfigResponse{
		Effective: a.effectiveRuntimeConfig(),
		Runtime:   runtimePtr,
		YAML:      a.yamlRuntimeConfig(),
		Source:    source,
	})
}

func (a *Agent) updateRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	var req runtimeConfigData
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if runtimeConfigLooksEmpty(req) {
		var wrapped runtimeConfigResponse
		if err := json.Unmarshal(raw, &wrapped); err == nil {
			switch {
			case !runtimeConfigLooksEmpty(wrapped.Effective):
				req = wrapped.Effective
			case !runtimeConfigLooksEmpty(wrapped.YAML):
				req = wrapped.YAML
			}
		}
	}
	req.Targets.Discovery.CIDRs = normalizeCIDRs(req.Targets.Discovery.CIDRs)
	if err := validateRuntimeConfig(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.saveRuntimeConfig(req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cidrRaw, _ := json.Marshal(req.Targets.Discovery.CIDRs)
	_ = a.db.SetSetting(discoveryCIDRsSetting, string(cidrRaw))
	writeJSON(w, http.StatusOK, runtimeConfigResponse{
		Effective: req,
		Runtime:   &req,
		YAML:      a.yamlRuntimeConfig(),
		Source:    "database",
	})
}

func runtimeConfigLooksEmpty(runtime runtimeConfigData) bool {
	return runtime.Targets.Gateway.Address == "" &&
		len(runtime.Targets.Internet) == 0 &&
		len(runtime.Targets.HTTP) == 0 &&
		len(runtime.Targets.DNS.Domains) == 0 &&
		len(runtime.Targets.DNS.Resolvers) == 0 &&
		runtime.Targets.Speedtest.Name == "" &&
		len(runtime.Targets.Discovery.CIDRs) == 0 &&
		advancedConfigEmpty(runtime.Targets.Advanced) &&
		reportsConfigEmpty(runtime.Reports) &&
		testsConfigEmpty(runtime.Tests)
}

func (a *Agent) yamlRuntimeConfig() runtimeConfigData {
	return runtimeConfigData{Targets: a.cfg.Targets, Thresholds: a.cfg.Thresholds, Reports: a.cfg.Reports, Tests: a.cfg.Tests}
}

func (a *Agent) effectiveRuntimeConfig() runtimeConfigData {
	if runtime, ok := a.runtimeConfigFromDB(); ok {
		base := a.yamlRuntimeConfig()
		if runtime.Targets.Gateway.Address != "" {
			base.Targets.Gateway = runtime.Targets.Gateway
		}
		if len(runtime.Targets.Internet) > 0 {
			base.Targets.Internet = runtime.Targets.Internet
		}
		if len(runtime.Targets.HTTP) > 0 {
			base.Targets.HTTP = runtime.Targets.HTTP
		}
		if len(runtime.Targets.DNS.Domains) > 0 || len(runtime.Targets.DNS.Resolvers) > 0 {
			base.Targets.DNS = runtime.Targets.DNS
		}
		if runtime.Targets.Speedtest.Name != "" {
			base.Targets.Speedtest = runtime.Targets.Speedtest
		}
		if len(runtime.Targets.Discovery.CIDRs) > 0 {
			base.Targets.Discovery = runtime.Targets.Discovery
		}
		if !advancedConfigEmpty(runtime.Targets.Advanced) {
			base.Targets.Advanced = runtime.Targets.Advanced
		}
		if !thresholdSetEmpty(runtime.Thresholds.Global) {
			base.Thresholds.Global = runtime.Thresholds.Global
		}
		if runtime.Thresholds.PerTarget != nil {
			base.Thresholds.PerTarget = runtime.Thresholds.PerTarget
		}
		if !reportsConfigEmpty(runtime.Reports) {
			if runtime.Reports.Path == "" {
				runtime.Reports.Path = base.Reports.Path
			}
			base.Reports = runtime.Reports
		}
		if !testsConfigEmpty(runtime.Tests) {
			base.Tests = mergeTests(base.Tests, runtime.Tests)
		}
		return base
	}
	out := a.yamlRuntimeConfig()
	if cidrs, source := a.discoveryCIDRsWithSource(); source == "database" {
		out.Targets.Discovery.CIDRs = cidrs
	}
	return out
}

func reportsConfigEmpty(reports config.ReportsConfig) bool {
	return reports.Path == "" && reports.RetentionDays == 0 && reports.AlertHistoryRetentionDays == 0
}

func testsConfigEmpty(tests config.TestsConfig) bool {
	return tests.Ping.Duration() == 0 &&
		tests.DNS.Duration() == 0 &&
		tests.HTTP.Duration() == 0 &&
		tests.Discovery.Duration() == 0 &&
		tests.Speedtest.Duration() == 0 &&
		tests.Advanced.Duration() == 0 &&
		tests.TLSDetails.Duration() == 0
}

func mergeTests(base, override config.TestsConfig) config.TestsConfig {
	if override.Ping.Duration() > 0 {
		base.Ping = override.Ping
	}
	if override.DNS.Duration() > 0 {
		base.DNS = override.DNS
	}
	if override.HTTP.Duration() > 0 {
		base.HTTP = override.HTTP
	}
	if override.Discovery.Duration() > 0 {
		base.Discovery = override.Discovery
	}
	if override.Speedtest.Duration() > 0 {
		base.Speedtest = override.Speedtest
	}
	if override.Advanced.Duration() > 0 {
		base.Advanced = override.Advanced
	}
	if override.TLSDetails.Duration() > 0 {
		base.TLSDetails = override.TLSDetails
	}
	return base
}

func advancedConfigEmpty(advanced config.AdvancedTargets) bool {
	return len(advanced.TCP) == 0 &&
		!advanced.PublicIPEnabled &&
		!advanced.GatewayIdentity &&
		!advanced.NetworkEnv &&
		!advanced.ProbeHealth &&
		!advanced.TLSDetails &&
		len(advanced.Trace) == 0 &&
		len(advanced.NTP) == 0 &&
		!advanced.PortScan.Enabled &&
		len(advanced.DNSExpectations) == 0
}

func thresholdSetEmpty(set config.ThresholdSet) bool {
	return set.PacketLossWarningPercent == 0 &&
		set.PacketLossCriticalPercent == 0 &&
		set.LatencyWarningMS == 0 &&
		set.LatencyCriticalMS == 0 &&
		set.LatencyRelativeWarningPercent == 0 &&
		set.LatencyRelativeWindowDays == 0 &&
		set.DNSDurationWarningMS == 0 &&
		set.DNSDurationCriticalMS == 0 &&
		set.HTTPDurationWarningMS == 0 &&
		set.HTTPDurationCriticalMS == 0 &&
		set.HTTPRelativeWarningPercent == 0 &&
		set.HTTPRelativeWindowDays == 0 &&
		set.TLSExpiryWarningDays == 0 &&
		set.TLSExpiryCriticalDays == 0 &&
		set.SpeedDownloadWarningMbps == 0 &&
		set.SpeedUploadWarningMbps == 0 &&
		set.SpeedRelativeWarningPercent == 0
}

func (a *Agent) effectiveTargets() config.TargetsConfig {
	return a.effectiveRuntimeConfig().Targets
}

func (a *Agent) effectiveThresholds() config.ThresholdsConfig {
	thresholds := a.effectiveRuntimeConfig().Thresholds
	if thresholds.PerTarget == nil {
		thresholds.PerTarget = map[string]config.ThresholdSet{}
	}
	return thresholds
}

func (a *Agent) effectiveTests() config.TestsConfig {
	return a.effectiveRuntimeConfig().Tests
}

func (a *Agent) runtimeConfigFromDB() (runtimeConfigData, bool) {
	raw, ok, err := a.db.Setting(runtimeConfigSetting)
	if err != nil || !ok {
		return runtimeConfigData{}, false
	}
	var runtime runtimeConfigData
	if err := json.Unmarshal([]byte(raw), &runtime); err != nil {
		return runtimeConfigData{}, false
	}
	if runtime.Thresholds.PerTarget == nil {
		runtime.Thresholds.PerTarget = map[string]config.ThresholdSet{}
	}
	return runtime, true
}

func (a *Agent) saveRuntimeConfig(runtime runtimeConfigData) error {
	raw, err := json.Marshal(runtime)
	if err != nil {
		return err
	}
	return a.db.SetSetting(runtimeConfigSetting, string(raw))
}

func validateRuntimeConfig(runtime runtimeConfigData) error {
	cfg := config.Default()
	cfg.Targets = runtime.Targets
	cfg.Thresholds = runtime.Thresholds
	cfg.Reports = runtime.Reports
	cfg.Tests = mergeTests(cfg.Tests, runtime.Tests)
	if cfg.Reports.Path == "" {
		cfg.Reports.Path = config.Default().Reports.Path
	}
	return cfg.Validate()
}

func (a *Agent) discoveryCIDRs() []string {
	return a.effectiveTargets().Discovery.CIDRs
}

func (a *Agent) discoveryCIDRsWithSource() ([]string, string) {
	raw, ok, err := a.db.Setting(discoveryCIDRsSetting)
	if err == nil && ok {
		var cidrs []string
		if json.Unmarshal([]byte(raw), &cidrs) == nil {
			return normalizeCIDRs(cidrs), "database"
		}
	}
	return normalizeCIDRs(a.cfg.Targets.Discovery.CIDRs), "yaml"
}

func normalizeCIDRs(input []string) []string {
	out := make([]string, 0, len(input))
	seen := map[string]struct{}{}
	for _, value := range input {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (a *Agent) activeAlerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9090/api/v1/alerts", nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
