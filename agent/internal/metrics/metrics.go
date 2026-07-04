package metrics

import (
	"strconv"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
)

type Registry struct {
	reg          *prometheus.Registry
	pingLatency  *prometheus.GaugeVec
	pingLoss     *prometheus.GaugeVec
	pingJitter   *prometheus.GaugeVec
	targetUp     *prometheus.GaugeVec
	dnsDuration  *prometheus.GaugeVec
	dnsSuccess   *prometheus.GaugeVec
	dnsFailures  *prometheus.CounterVec
	httpUp       *prometheus.GaugeVec
	httpStatus   *prometheus.GaugeVec
	httpDuration *prometheus.GaugeVec
	httpTLSValid *prometheus.GaugeVec
	httpTLSDays  *prometheus.GaugeVec
	speedDown    *prometheus.GaugeVec
	speedUp      *prometheus.GaugeVec
	speedSuccess *prometheus.GaugeVec
	iperfUp      *prometheus.GaugeVec
	lanDevices   *prometheus.GaugeVec
	lanNew       *prometheus.GaugeVec
	lanMissing   *prometheus.GaugeVec
	healthScore  *prometheus.GaugeVec
}

func New() *Registry {
	reg := prometheus.NewRegistry()
	m := &Registry{
		reg: reg,
		pingLatency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_ping_latency_ms",
			Help: "Latest ping average latency in milliseconds.",
		}, []string{"site_id", "target_name", "target_host", "target_type"}),
		pingLoss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_ping_loss_percent",
			Help: "Latest ping packet loss percentage.",
		}, []string{"site_id", "target_name", "target_host", "target_type"}),
		pingJitter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_ping_jitter_ms",
			Help: "Latest ping jitter estimate in milliseconds.",
		}, []string{"site_id", "target_name", "target_host", "target_type"}),
		targetUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_target_up",
			Help: "Whether the target is reachable. 1 is up, 0 is down.",
		}, []string{"site_id", "target_name", "target_host", "target_type"}),
		dnsDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_dns_lookup_duration_ms",
			Help: "Latest DNS lookup duration in milliseconds.",
		}, []string{"site_id", "resolver_name", "resolver_address", "domain", "record_type"}),
		dnsSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_dns_lookup_success",
			Help: "Whether the latest DNS lookup succeeded. 1 is success, 0 is failure.",
		}, []string{"site_id", "resolver_name", "resolver_address", "domain", "record_type"}),
		dnsFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "network_probe_dns_failure_total",
			Help: "Total DNS lookup failures.",
		}, []string{"site_id", "resolver_name", "resolver_address", "domain", "record_type"}),
		httpUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_http_up",
			Help: "Whether the latest HTTP check succeeded. 1 is up, 0 is down.",
		}, []string{"site_id", "target_name", "url"}),
		httpStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_http_status_code",
			Help: "Latest HTTP status code.",
		}, []string{"site_id", "target_name", "url"}),
		httpDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_http_duration_ms",
			Help: "Latest HTTP request duration in milliseconds.",
		}, []string{"site_id", "target_name", "url"}),
		httpTLSValid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_http_tls_valid",
			Help: "Whether the latest HTTPS TLS certificate validation succeeded. 1 is valid, 0 is invalid.",
		}, []string{"site_id", "target_name", "url"}),
		httpTLSDays: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_http_tls_days_until_expiry",
			Help: "Days until the HTTPS peer certificate expires.",
		}, []string{"site_id", "target_name", "url"}),
		speedDown: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_speedtest_download_mbps",
			Help: "Latest WAN download throughput in Mbps.",
		}, []string{"site_id", "target_name"}),
		speedUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_speedtest_upload_mbps",
			Help: "Latest WAN upload throughput in Mbps.",
		}, []string{"site_id", "target_name"}),
		speedSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_speedtest_success",
			Help: "Whether the latest WAN speed test succeeded. 1 is success, 0 is failure.",
		}, []string{"site_id", "target_name"}),
		iperfUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_iperf_server_up",
			Help: "Whether the iperf3 server process is running. 1 is up, 0 is down.",
		}, []string{"site_id", "port"}),
		lanDevices: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_lan_devices_total",
			Help: "Total known LAN devices.",
		}, []string{"site_id"}),
		lanNew: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_lan_new_devices_total",
			Help: "LAN devices first seen within the recent new-device window.",
		}, []string{"site_id"}),
		lanMissing: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_lan_missing_devices_total",
			Help: "LAN devices missing from recent discovery.",
		}, []string{"site_id"}),
		healthScore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_probe_health_score",
			Help: "Latest health score by category.",
		}, []string{"site_id", "category"}),
	}
	reg.MustRegister(m.pingLatency, m.pingLoss, m.pingJitter, m.targetUp, m.dnsDuration, m.dnsSuccess, m.dnsFailures, m.httpUp, m.httpStatus, m.httpDuration, m.httpTLSValid, m.httpTLSDays, m.speedDown, m.speedUp, m.speedSuccess, m.iperfUp, m.lanDevices, m.lanNew, m.lanMissing, m.healthScore)
	return m
}

func (m *Registry) RecordSpeedtest(result storage.SpeedtestResult) {
	labels := prometheus.Labels{
		"site_id":     result.SiteID,
		"target_name": result.TargetName,
	}
	success := 0.0
	if result.Success {
		success = 1
	}
	m.speedDown.With(labels).Set(result.DownloadMbps)
	m.speedUp.With(labels).Set(result.UploadMbps)
	m.speedSuccess.With(labels).Set(success)
}

func (m *Registry) RecordLAN(siteID string, devicesTotal, newTotal, missingTotal int) {
	labels := prometheus.Labels{"site_id": siteID}
	m.lanDevices.With(labels).Set(float64(devicesTotal))
	m.lanNew.With(labels).Set(float64(newTotal))
	m.lanMissing.With(labels).Set(float64(missingTotal))
}

func (m *Registry) RecordHealth(siteID string, scores map[string]int) {
	for category, score := range scores {
		m.healthScore.With(prometheus.Labels{
			"site_id":  siteID,
			"category": category,
		}).Set(float64(score))
	}
}

func (m *Registry) RecordDNS(result storage.DNSResult) {
	labels := prometheus.Labels{
		"site_id":          result.SiteID,
		"resolver_name":    result.ResolverName,
		"resolver_address": result.ResolverAddress,
		"domain":           result.Domain,
		"record_type":      result.RecordType,
	}
	m.dnsDuration.With(labels).Set(result.DurationMS)
	success := 0.0
	if result.Success {
		success = 1
	}
	m.dnsSuccess.With(labels).Set(success)
	if !result.Success {
		m.dnsFailures.With(labels).Inc()
	}
}

func (m *Registry) RecordHTTP(result storage.HTTPResult) {
	labels := prometheus.Labels{
		"site_id":     result.SiteID,
		"target_name": result.Name,
		"url":         result.URL,
	}
	up := 0.0
	if result.Up {
		up = 1
	}
	tlsValid := 0.0
	if result.TLSValid {
		tlsValid = 1
	}
	m.httpUp.With(labels).Set(up)
	m.httpStatus.With(labels).Set(float64(result.StatusCode))
	m.httpDuration.With(labels).Set(result.DurationMS)
	m.httpTLSValid.With(labels).Set(tlsValid)
	m.httpTLSDays.With(labels).Set(float64(result.TLSDaysUntilExpiry))
}

func (m *Registry) RecordIperfServer(siteID string, port int, running bool) {
	up := 0.0
	if running {
		up = 1
	}
	m.iperfUp.With(prometheus.Labels{
		"site_id": siteID,
		"port":    strconv.Itoa(port),
	}).Set(up)
}

func (m *Registry) Registry() *prometheus.Registry {
	return m.reg
}

func (m *Registry) RecordPing(result storage.PingResult) {
	labels := prometheus.Labels{
		"site_id":     result.SiteID,
		"target_name": result.TargetName,
		"target_host": result.TargetHost,
		"target_type": result.TargetType,
	}
	m.pingLatency.With(labels).Set(result.LatencyMS)
	m.pingLoss.With(labels).Set(result.LossPercent)
	m.pingJitter.With(labels).Set(result.JitterMS)
	up := 0.0
	if result.Up {
		up = 1
	}
	m.targetUp.With(labels).Set(up)
}
