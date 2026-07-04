package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Site       SiteConfig       `yaml:"site" json:"site"`
	Agent      AgentConfig      `yaml:"agent" json:"agent"`
	Storage    StorageConfig    `yaml:"storage" json:"storage"`
	Reports    ReportsConfig    `yaml:"reports" json:"reports"`
	Security   SecurityConfig   `yaml:"security" json:"security"`
	Targets    TargetsConfig    `yaml:"targets" json:"targets"`
	Thresholds ThresholdsConfig `yaml:"thresholds" json:"thresholds"`
	Tests      TestsConfig      `yaml:"tests" json:"tests"`
}

type SiteConfig struct {
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	Location string `yaml:"location" json:"location"`
}

type AgentConfig struct {
	BindAddress string `yaml:"bind_address" json:"bind_address"`
	Port        int    `yaml:"port" json:"port"`
	LogLevel    string `yaml:"log_level" json:"log_level"`
}

type StorageConfig struct {
	Path string `yaml:"path" json:"path"`
}

type ReportsConfig struct {
	Path                      string `yaml:"path" json:"path"`
	RetentionDays             int    `yaml:"retention_days" json:"retention_days"`
	AlertHistoryRetentionDays int    `yaml:"alert_history_retention_days" json:"alert_history_retention_days"`
}

type SecurityConfig struct {
	ReadToken        string `yaml:"read_token" json:"-"`
	AdminToken       string `yaml:"admin_token" json:"-"`
	ProtectMetrics   bool   `yaml:"protect_metrics" json:"protect_metrics"`
	AllowPublicReads bool   `yaml:"allow_public_reads" json:"allow_public_reads"`
}

type TargetsConfig struct {
	Gateway   GatewayTarget   `yaml:"gateway" json:"gateway"`
	Internet  []HostTarget    `yaml:"internet" json:"internet"`
	HTTP      []HTTPTarget    `yaml:"http" json:"http"`
	DNS       DNSTargets      `yaml:"dns" json:"dns"`
	Speedtest SpeedtestTarget `yaml:"speedtest" json:"speedtest"`
	Discovery DiscoveryTarget `yaml:"discovery" json:"discovery"`
	Advanced  AdvancedTargets `yaml:"advanced" json:"advanced"`
}

type GatewayTarget struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
}

type HostTarget struct {
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
}

type HTTPTarget struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	ExpectedStatus int    `yaml:"expected_status" json:"expected_status"`
	ExpectedText   string `yaml:"expected_text" json:"expected_text"`
}

type DNSTargets struct {
	Domains   []string      `yaml:"domains" json:"domains"`
	Resolvers []ResolverRef `yaml:"resolvers" json:"resolvers"`
}

type SpeedtestTarget struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	Name          string `yaml:"name" json:"name"`
	DownloadURL   string `yaml:"download_url" json:"download_url"`
	UploadURL     string `yaml:"upload_url" json:"upload_url"`
	DownloadBytes int64  `yaml:"download_bytes" json:"download_bytes"`
	UploadBytes   int64  `yaml:"upload_bytes" json:"upload_bytes"`
}

type DiscoveryTarget struct {
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
}

type AdvancedTargets struct {
	TCP             []TCPTarget      `yaml:"tcp" json:"tcp"`
	PublicIPEnabled bool             `yaml:"public_ip_enabled" json:"public_ip_enabled"`
	GatewayIdentity bool             `yaml:"gateway_identity" json:"gateway_identity"`
	NetworkEnv      bool             `yaml:"network_env" json:"network_env"`
	ProbeHealth     bool             `yaml:"probe_health" json:"probe_health"`
	TLSDetails      bool             `yaml:"tls_details" json:"tls_details"`
	Trace           []HostTarget     `yaml:"trace" json:"trace"`
	NTP             []HostTarget     `yaml:"ntp" json:"ntp"`
	PortScan        PortScanConfig   `yaml:"port_scan" json:"port_scan"`
	DNSExpectations []DNSExpectation `yaml:"dns_expectations" json:"dns_expectations"`
}

type TCPTarget struct {
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

type PortScanConfig struct {
	Enabled bool  `yaml:"enabled" json:"enabled"`
	Ports   []int `yaml:"ports" json:"ports"`
	Limit   int   `yaml:"limit" json:"limit"`
}

type DNSExpectation struct {
	Name            string   `yaml:"name" json:"name"`
	ResolverName    string   `yaml:"resolver_name" json:"resolver_name"`
	ResolverAddress string   `yaml:"resolver_address" json:"resolver_address"`
	Domain          string   `yaml:"domain" json:"domain"`
	RecordType      string   `yaml:"record_type" json:"record_type"`
	Expected        []string `yaml:"expected" json:"expected"`
}

type ThresholdsConfig struct {
	Global    ThresholdSet            `yaml:"global" json:"global"`
	PerTarget map[string]ThresholdSet `yaml:"per_target" json:"per_target"`
}

type ThresholdSet struct {
	PacketLossWarningPercent      float64 `yaml:"packet_loss_warning_percent" json:"packet_loss_warning_percent"`
	PacketLossCriticalPercent     float64 `yaml:"packet_loss_critical_percent" json:"packet_loss_critical_percent"`
	LatencyWarningMS              float64 `yaml:"latency_warning_ms" json:"latency_warning_ms"`
	LatencyCriticalMS             float64 `yaml:"latency_critical_ms" json:"latency_critical_ms"`
	LatencyRelativeWarningPercent float64 `yaml:"latency_relative_warning_percent" json:"latency_relative_warning_percent"`
	LatencyRelativeWindowDays     int     `yaml:"latency_relative_window_days" json:"latency_relative_window_days"`
	DNSDurationWarningMS          float64 `yaml:"dns_duration_warning_ms" json:"dns_duration_warning_ms"`
	DNSDurationCriticalMS         float64 `yaml:"dns_duration_critical_ms" json:"dns_duration_critical_ms"`
	HTTPDurationWarningMS         float64 `yaml:"http_duration_warning_ms" json:"http_duration_warning_ms"`
	HTTPDurationCriticalMS        float64 `yaml:"http_duration_critical_ms" json:"http_duration_critical_ms"`
	HTTPRelativeWarningPercent    float64 `yaml:"http_relative_warning_percent" json:"http_relative_warning_percent"`
	HTTPRelativeWindowDays        int     `yaml:"http_relative_window_days" json:"http_relative_window_days"`
	TLSExpiryWarningDays          int     `yaml:"tls_expiry_warning_days" json:"tls_expiry_warning_days"`
	TLSExpiryCriticalDays         int     `yaml:"tls_expiry_critical_days" json:"tls_expiry_critical_days"`
	SpeedDownloadWarningMbps      float64 `yaml:"speed_download_warning_mbps" json:"speed_download_warning_mbps"`
	SpeedUploadWarningMbps        float64 `yaml:"speed_upload_warning_mbps" json:"speed_upload_warning_mbps"`
	SpeedRelativeWarningPercent   float64 `yaml:"speed_relative_warning_percent" json:"speed_relative_warning_percent"`
}

type ResolverRef struct {
	Name    string `yaml:"name" json:"name"`
	Address string `yaml:"address" json:"address"`
}

type TestsConfig struct {
	Ping       IntervalConfig `yaml:"ping" json:"ping"`
	DNS        IntervalConfig `yaml:"dns" json:"dns"`
	HTTP       IntervalConfig `yaml:"http" json:"http"`
	Discovery  IntervalConfig `yaml:"discovery" json:"discovery"`
	Speedtest  IntervalConfig `yaml:"speedtest" json:"speedtest"`
	Advanced   IntervalConfig `yaml:"advanced" json:"advanced"`
	TLSDetails IntervalConfig `yaml:"tls_details" json:"tls_details"`
}

type IntervalConfig struct {
	IntervalSeconds int `yaml:"interval_seconds" json:"interval_seconds"`
	IntervalMinutes int `yaml:"interval_minutes" json:"interval_minutes"`
	IntervalHours   int `yaml:"interval_hours" json:"interval_hours"`
	TimeoutSeconds  int `yaml:"timeout_seconds" json:"timeout_seconds"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			applyEnv(&cfg)
			return cfg, cfg.Validate()
		}
		return Config{}, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	applyEnv(&cfg)
	return cfg, cfg.Validate()
}

func Default() Config {
	return Config{
		Site: SiteConfig{ID: "default-site", Name: "Infracheck Site", Location: "Unknown"},
		Agent: AgentConfig{
			BindAddress: "0.0.0.0",
			Port:        8080,
			LogLevel:    "info",
		},
		Storage: StorageConfig{Path: "/var/lib/infracheck/infracheck.db"},
		Reports: ReportsConfig{Path: "/var/lib/infracheck/reports", RetentionDays: 30, AlertHistoryRetentionDays: 90},
		Security: SecurityConfig{
			AllowPublicReads: true,
		},
		Targets: TargetsConfig{
			Gateway: GatewayTarget{Enabled: true, Address: "auto"},
			Internet: []HostTarget{
				{Name: "Cloudflare DNS", Host: "1.1.1.1"},
				{Name: "Google DNS", Host: "8.8.8.8"},
			},
			HTTP: []HTTPTarget{
				{Name: "Google", URL: "https://www.google.com"},
				{Name: "Microsoft", URL: "https://www.microsoft.com"},
			},
			DNS: DNSTargets{
				Domains: []string{"google.com", "cloudflare.com", "microsoft.com"},
				Resolvers: []ResolverRef{
					{Name: "system", Address: "auto"},
					{Name: "cloudflare", Address: "1.1.1.1"},
					{Name: "google", Address: "8.8.8.8"},
				},
			},
			Speedtest: SpeedtestTarget{
				Enabled:       true,
				Name:          "Cloudflare Speed",
				DownloadURL:   "https://speed.cloudflare.com/__down?bytes=25000000",
				UploadURL:     "https://speed.cloudflare.com/__up",
				DownloadBytes: 25_000_000,
				UploadBytes:   5_000_000,
			},
			Discovery: DiscoveryTarget{},
			Advanced: AdvancedTargets{
				PublicIPEnabled: false,
				GatewayIdentity: true,
				NetworkEnv:      true,
				ProbeHealth:     true,
				TLSDetails:      true,
				PortScan:        PortScanConfig{Enabled: false, Ports: []int{22, 80, 443, 445, 3389, 8080, 8443}, Limit: 32},
			},
		},
		Thresholds: ThresholdsConfig{
			Global: ThresholdSet{
				PacketLossWarningPercent:      2,
				PacketLossCriticalPercent:     10,
				LatencyWarningMS:              150,
				LatencyCriticalMS:             400,
				LatencyRelativeWarningPercent: 200,
				LatencyRelativeWindowDays:     7,
				DNSDurationWarningMS:          750,
				DNSDurationCriticalMS:         2000,
				HTTPDurationWarningMS:         2500,
				HTTPDurationCriticalMS:        8000,
				HTTPRelativeWarningPercent:    400,
				HTTPRelativeWindowDays:        7,
				TLSExpiryWarningDays:          30,
				TLSExpiryCriticalDays:         7,
				SpeedRelativeWarningPercent:   50,
			},
			PerTarget: map[string]ThresholdSet{},
		},
		Tests: TestsConfig{
			Ping:       IntervalConfig{IntervalSeconds: 30, TimeoutSeconds: 3},
			DNS:        IntervalConfig{IntervalSeconds: 60, TimeoutSeconds: 3},
			HTTP:       IntervalConfig{IntervalSeconds: 60, TimeoutSeconds: 5},
			Discovery:  IntervalConfig{IntervalMinutes: 15, TimeoutSeconds: 30},
			Speedtest:  IntervalConfig{IntervalHours: 6, TimeoutSeconds: 120},
			Advanced:   IntervalConfig{IntervalMinutes: 5, TimeoutSeconds: 90},
			TLSDetails: IntervalConfig{IntervalHours: 24, TimeoutSeconds: 20},
		},
	}
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("INFRACHECK_SITE_ID"); v != "" {
		cfg.Site.ID = v
	}
	if v := os.Getenv("INFRACHECK_SITE_NAME"); v != "" {
		cfg.Site.Name = v
	}
	if v := os.Getenv("INFRACHECK_SITE_LOCATION"); v != "" {
		cfg.Site.Location = v
	}
	if v := os.Getenv("INFRACHECK_ADMIN_TOKEN"); v != "" {
		cfg.Security.AdminToken = v
	}
	if v := os.Getenv("INFRACHECK_READ_TOKEN"); v != "" {
		cfg.Security.ReadToken = v
	}
	if v := os.Getenv("INFRACHECK_PROTECT_METRICS"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Security.ProtectMetrics = enabled
		}
	}
	if v := os.Getenv("INFRACHECK_ALLOW_PUBLIC_READS"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Security.AllowPublicReads = enabled
		}
	}
	if v := os.Getenv("INFRACHECK_STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("INFRACHECK_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Agent.Port = port
		}
	}
}

func (c Config) Validate() error {
	if c.Site.ID == "" {
		return errors.New("site.id is required")
	}
	if c.Agent.BindAddress == "" {
		return errors.New("agent.bind_address is required")
	}
	if c.Agent.Port <= 0 || c.Agent.Port > 65535 {
		return fmt.Errorf("agent.port must be between 1 and 65535")
	}
	if c.Storage.Path == "" {
		return errors.New("storage.path is required")
	}
	if c.Reports.Path == "" {
		return errors.New("reports.path is required")
	}
	if c.Reports.RetentionDays < 0 {
		return errors.New("reports.retention_days must be zero or greater")
	}
	if c.Reports.AlertHistoryRetentionDays < 0 {
		return errors.New("reports.alert_history_retention_days must be zero or greater")
	}
	if c.Security.ProtectMetrics && c.Security.ReadToken == "" && c.Security.AdminToken == "" {
		return errors.New("security.protect_metrics requires security.read_token or security.admin_token")
	}
	if !c.Security.AllowPublicReads && c.Security.ReadToken == "" && c.Security.AdminToken == "" {
		return errors.New("private read endpoints require security.read_token or security.admin_token")
	}
	if c.Tests.Ping.TimeoutSeconds <= 0 {
		return errors.New("tests.ping.timeout_seconds must be positive")
	}
	if c.Tests.Ping.Duration() <= 0 {
		return errors.New("tests.ping interval must be positive")
	}
	if c.Tests.DNS.TimeoutSeconds <= 0 {
		return errors.New("tests.dns.timeout_seconds must be positive")
	}
	if c.Tests.DNS.Duration() <= 0 {
		return errors.New("tests.dns interval must be positive")
	}
	if c.Tests.HTTP.TimeoutSeconds <= 0 {
		return errors.New("tests.http.timeout_seconds must be positive")
	}
	if c.Tests.HTTP.Duration() <= 0 {
		return errors.New("tests.http interval must be positive")
	}
	if c.Tests.Speedtest.TimeoutSeconds <= 0 {
		return errors.New("tests.speedtest.timeout_seconds must be positive")
	}
	if c.Tests.Speedtest.Duration() <= 0 {
		return errors.New("tests.speedtest interval must be positive")
	}
	if c.Tests.Advanced.TimeoutSeconds <= 0 {
		return errors.New("tests.advanced.timeout_seconds must be positive")
	}
	if c.Tests.Advanced.Duration() <= 0 {
		return errors.New("tests.advanced interval must be positive")
	}
	if c.Tests.TLSDetails.TimeoutSeconds <= 0 {
		return errors.New("tests.tls_details.timeout_seconds must be positive")
	}
	if c.Tests.TLSDetails.Duration() <= 0 {
		return errors.New("tests.tls_details interval must be positive")
	}
	for _, target := range c.Targets.Internet {
		if target.Name == "" || target.Host == "" {
			return errors.New("internet targets require name and host")
		}
	}
	for _, target := range c.Targets.HTTP {
		if target.Name == "" || target.URL == "" {
			return errors.New("http targets require name and url")
		}
	}
	for _, target := range c.Targets.Advanced.TCP {
		if target.Name == "" || target.Host == "" || target.Port <= 0 || target.Port > 65535 {
			return errors.New("tcp targets require name, host, and valid port")
		}
	}
	for _, domain := range c.Targets.DNS.Domains {
		if domain == "" {
			return errors.New("dns domains cannot be empty")
		}
	}
	for _, resolver := range c.Targets.DNS.Resolvers {
		if resolver.Name == "" || resolver.Address == "" {
			return errors.New("dns resolvers require name and address")
		}
	}
	if c.Targets.Speedtest.Enabled {
		if c.Targets.Speedtest.Name == "" || c.Targets.Speedtest.DownloadURL == "" {
			return errors.New("enabled speedtest requires name and download_url")
		}
		if c.Targets.Speedtest.DownloadBytes <= 0 {
			return errors.New("enabled speedtest requires positive download_bytes")
		}
		if c.Targets.Speedtest.UploadURL != "" && c.Targets.Speedtest.UploadBytes <= 0 {
			return errors.New("enabled speedtest upload_url requires positive upload_bytes")
		}
	}
	for _, cidr := range c.Targets.Discovery.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("targets.discovery.cidrs contains invalid CIDR %q", cidr)
		}
	}
	return nil
}

func (a AgentConfig) PortString() string {
	return strconv.Itoa(a.Port)
}

func (i IntervalConfig) Duration() time.Duration {
	switch {
	case i.IntervalSeconds > 0:
		return time.Duration(i.IntervalSeconds) * time.Second
	case i.IntervalMinutes > 0:
		return time.Duration(i.IntervalMinutes) * time.Minute
	case i.IntervalHours > 0:
		return time.Duration(i.IntervalHours) * time.Hour
	default:
		return 0
	}
}

func (i IntervalConfig) Timeout() time.Duration {
	if i.TimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(i.TimeoutSeconds) * time.Second
}

func LogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
