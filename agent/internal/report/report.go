package report

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
	"github.com/infracheck/infracheck/container/agent/internal/verdict"
)

type Input struct {
	Site           config.SiteConfig
	Type           string
	CurrentOnly    bool
	StatsLabel     string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	Targets        config.TargetsConfig
	Tests          config.TestsConfig
	Health         verdict.Health
	Ping           []storage.PingResult
	DNS            []storage.DNSResult
	HTTP           []storage.HTTPResult
	Speedtest      []storage.SpeedtestResult
	Advanced       []storage.AdvancedResult
	Alerts         []storage.AlertRecord
	Devices        []storage.Device
	NewDevices     []storage.Device
	MissingDevices []storage.Device
}

type NetworkLoad struct {
	PingTargets          int
	DNSLookups           int
	HTTPTargets          int
	DiscoveryHosts       int
	SpeedtestEnabled     bool
	SteadyKBPerHour      float64
	DiscoveryKBPerHour   float64
	SpeedtestMBPerRun    float64
	SpeedtestMBPerHour   float64
	TotalMBPerHour       float64
	PingInterval         string
	DNSInterval          string
	HTTPInterval         string
	DiscoveryInterval    string
	SpeedtestInterval    string
	BackgroundVerdict    string
	BackgroundVerdictCSS string
}

type Output struct {
	ID    string
	Title string
	HTML  []byte
	PDF   []byte
}

func Generate(input Input) (Output, error) {
	if input.Type == "" {
		input.Type = "daily"
	}
	id := reportID()
	title := "Infracheck " + input.Type + " report"
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, map[string]any{
		"ID":             id,
		"Title":          title,
		"Site":           input.Site,
		"Type":           input.Type,
		"PeriodStart":    input.PeriodStart,
		"PeriodEnd":      input.PeriodEnd,
		"GeneratedAt":    time.Now().UTC(),
		"Health":         input.Health,
		"Ping":           input.Ping,
		"DNS":            input.DNS,
		"HTTP":           input.HTTP,
		"Speedtest":      input.Speedtest,
		"Devices":        input.Devices,
		"NewDevices":     input.NewDevices,
		"MissingDevices": input.MissingDevices,
		"NetworkLoad":    networkLoad(input),
		"PrimaryDomain":  primaryDomain(input),
		"RadarDomains":   radarDomains(input),
		"AlertLife":      alertLifecycleSummary(input.Alerts),
	}); err != nil {
		return Output{}, err
	}
	return Output{ID: id, Title: title, HTML: buf.Bytes()}, nil
}

func Write(dir string, output Output) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	ext := ".html"
	data := output.HTML
	if len(output.PDF) > 0 {
		ext = ".pdf"
		data = output.PDF
	}
	path := filepath.Join(dir, output.ID+ext)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func reportID() string {
	return "report-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

func GeneratePDF(input Input) (Output, error) {
	if input.Type == "" {
		input.Type = "current"
	}
	id := reportID()
	title := "Infracheck current status report"
	if input.CurrentOnly {
		title = "Infracheck current status only"
	}
	pdf, err := visualPDF(input, title)
	if err != nil {
		return Output{}, err
	}
	return Output{ID: id, Title: title, PDF: pdf}, nil
}

func periodProblems(input Input) []string {
	var lines []string
	for _, r := range input.Ping {
		if !r.Up || r.LossPercent > 0 || r.Error != "" {
			lines = append(lines, fmt.Sprintf("- [PING] %s %s at %s: up=%t latency=%.1f ms loss=%.2f%% %s", r.TargetName, r.TargetHost, formatTime(r.Timestamp), r.Up, r.LatencyMS, r.LossPercent, r.Error))
		}
	}
	for _, r := range input.DNS {
		if !r.Success || r.Error != "" {
			lines = append(lines, fmt.Sprintf("- [DNS] %s via %s at %s: success=%t duration=%.0f ms %s", r.Domain, r.ResolverName, formatTime(r.Timestamp), r.Success, r.DurationMS, r.Error))
		}
	}
	for _, r := range input.HTTP {
		if !r.Up || r.Error != "" || (strings.HasPrefix(r.URL, "https://") && (!r.TLSValid || r.TLSDaysUntilExpiry <= 14)) {
			lines = append(lines, fmt.Sprintf("- [HTTP] %s at %s: up=%t status=%d duration=%.0f ms TLS=%t/%d days %s", r.URL, formatTime(r.Timestamp), r.Up, r.StatusCode, r.DurationMS, r.TLSValid, r.TLSDaysUntilExpiry, r.Error))
		}
	}
	for _, r := range input.Speedtest {
		if !r.Success || r.DownloadError != "" || r.UploadError != "" {
			lines = append(lines, fmt.Sprintf("- [WAN] %s at %s: %.1f down / %.1f up Mbps %s %s", r.TargetName, formatTime(r.Timestamp), r.DownloadMbps, r.UploadMbps, r.DownloadError, r.UploadError))
		}
	}
	for _, r := range input.Advanced {
		if !r.Success || r.Severity == "warning" || r.Severity == "critical" || r.Error != "" {
			lines = append(lines, fmt.Sprintf("- [ADVANCED] %s %s at %s: %s %s", r.CheckType, r.TargetName, formatTime(r.Timestamp), r.Summary, r.Error))
		}
	}
	sort.Strings(lines)
	return lines
}

func boolStatus(ok bool) string {
	if ok {
		return "success"
	}
	return "failed"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func scoreColor(score int) pdfColor {
	switch {
	case score >= 90:
		return pdfOK
	case score >= 70:
		return pdfWarn
	default:
		return pdfCritical
	}
}

func statusColor(status string) pdfColor {
	switch strings.ToLower(status) {
	case "critical", "failed", "down":
		return pdfCritical
	case "warning", "degraded":
		return pdfWarn
	case "ok", "healthy", "success":
		return pdfOK
	case "info":
		return pdfInfo
	default:
		return pdfMuted
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func severityFromLine(line string) string {
	if strings.Contains(line, "success=false") || strings.Contains(line, "up=false") {
		return "critical"
	}
	return "warning"
}

func areaFromLine(line string) string {
	line = strings.TrimPrefix(line, "- [")
	if i := strings.Index(line, "]"); i >= 0 {
		return strings.ToLower(line[:i])
	}
	return "check"
}

func titleFromLine(line string) string {
	line = strings.TrimPrefix(line, "- ")
	if i := strings.LastIndex(line, " at "); i >= 0 {
		return line[:i]
	}
	if i := strings.Index(line, ":"); i >= 0 {
		return line[:i]
	}
	return line
}

func whenFromLine(line string) string {
	line = strings.TrimPrefix(line, "- ")
	i := strings.LastIndex(line, " at ")
	if i < 0 {
		return ""
	}
	rest := line[i+4:]
	if j := strings.Index(rest, ": "); j >= 0 {
		return rest[:j]
	}
	return strings.TrimSpace(rest)
}

func defaultText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func truncate(value string, maxLen int) string {
	value = strings.Join(strings.Fields(value), " ")
	if maxLen <= 3 || len(value) <= maxLen {
		return value
	}
	return value[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func minMax(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 1
	}
	minV := values[0]
	maxV := values[0]
	for _, v := range values[1:] {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	return minV, maxV
}

func avgFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, v := range values {
		total += v
	}
	return total / float64(len(values))
}

func statsLine(values []float64, unit string) string {
	if len(values) == 0 {
		return "min - / avg - / max -"
	}
	minV, maxV := minMax(values)
	return fmt.Sprintf("min %.1f %s / avg %.1f %s / max %.1f %s", minV, unit, avgFloat(values), unit, maxV, unit)
}

func compactStatsLine(values []float64, unit string) string {
	if len(values) == 0 {
		return "min - / avg - / max -"
	}
	minV, maxV := minMax(values)
	return fmt.Sprintf("min %.1f / avg %.1f / max %.1f %s", minV, avgFloat(values), maxV, unit)
}

type metricStats struct {
	Min    float64
	Avg    float64
	Max    float64
	Latest float64
	Unit   string
	Empty  bool
}

func makeStats(values []float64, unit string) metricStats {
	if len(values) == 0 {
		return metricStats{Unit: unit, Empty: true}
	}
	minV, maxV := minMax(values)
	return metricStats{Min: minV, Avg: avgFloat(values), Max: maxV, Latest: values[len(values)-1], Unit: unit}
}

func statValue(value float64, unit string) string {
	if unit == "%" {
		return fmt.Sprintf("%.1f%%", value)
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}

func downsample(values []float64, maxPoints int) []float64 {
	if maxPoints <= 0 || len(values) <= maxPoints {
		return values
	}
	out := make([]float64, 0, maxPoints)
	for i := 0; i < maxPoints; i++ {
		start := int(math.Floor(float64(i) * float64(len(values)) / float64(maxPoints)))
		end := int(math.Floor(float64(i+1) * float64(len(values)) / float64(maxPoints)))
		if end <= start {
			end = start + 1
		}
		if end > len(values) {
			end = len(values)
		}
		total := 0.0
		for _, v := range values[start:end] {
			total += v
		}
		out = append(out, total/float64(end-start))
	}
	return out
}

func sumFloat(values []float64) float64 {
	total := 0.0
	for _, v := range values {
		total += v
	}
	return total
}

func networkLoad(input Input) NetworkLoad {
	gatewayCount := 1
	if !input.Targets.Gateway.Enabled {
		gatewayCount = 0
	}
	pingTargets := gatewayCount + len(input.Targets.Internet)
	dnsLookups := len(input.Targets.DNS.Domains) * len(input.Targets.DNS.Resolvers) * 2
	httpTargets := len(input.Targets.HTTP)
	discoveryHosts := 0
	for _, cidr := range input.Targets.Discovery.CIDRs {
		discoveryHosts += cidrUsableHosts(cidr)
	}
	pingSec := intervalSeconds(input.Tests.Ping, 30*time.Second)
	dnsSec := intervalSeconds(input.Tests.DNS, 60*time.Second)
	httpSec := intervalSeconds(input.Tests.HTTP, 60*time.Second)
	discoverySec := intervalSeconds(input.Tests.Discovery, 15*time.Minute)
	speedtestSec := intervalSeconds(input.Tests.Speedtest, 6*time.Hour)
	pingPerHour := cyclesPerHour(pingSec) * float64(pingTargets) * 3
	dnsPerHour := cyclesPerHour(dnsSec) * float64(dnsLookups)
	httpPerHour := cyclesPerHour(httpSec) * float64(httpTargets)
	discoveryPerHour := cyclesPerHour(discoverySec) * float64(discoveryHosts)
	speedtestMBPerRun := 0.0
	if input.Targets.Speedtest.Enabled {
		speedtestMBPerRun = float64(input.Targets.Speedtest.DownloadBytes+input.Targets.Speedtest.UploadBytes) / 1_000_000
	}
	load := NetworkLoad{
		PingTargets:        pingTargets,
		DNSLookups:         dnsLookups,
		HTTPTargets:        httpTargets,
		DiscoveryHosts:     discoveryHosts,
		SpeedtestEnabled:   input.Targets.Speedtest.Enabled,
		SteadyKBPerHour:    pingPerHour*0.2 + dnsPerHour*0.35 + httpPerHour*4,
		DiscoveryKBPerHour: discoveryPerHour * 0.12,
		SpeedtestMBPerRun:  speedtestMBPerRun,
		SpeedtestMBPerHour: speedtestMBPerRun * cyclesPerHour(speedtestSec),
		PingInterval:       durationLabel(pingSec),
		DNSInterval:        durationLabel(dnsSec),
		HTTPInterval:       durationLabel(httpSec),
		DiscoveryInterval:  durationLabel(discoverySec),
		SpeedtestInterval:  durationLabel(speedtestSec),
	}
	load.TotalMBPerHour = load.SteadyKBPerHour/1000 + load.DiscoveryKBPerHour/1000 + load.SpeedtestMBPerHour
	load.BackgroundVerdict = "low background load"
	load.BackgroundVerdictCSS = "ok"
	if load.TotalMBPerHour > 100 || load.SteadyKBPerHour > 5000 || load.DiscoveryHosts > 1024 {
		load.BackgroundVerdict = "review test load"
		load.BackgroundVerdictCSS = "warning"
	}
	return load
}

func intervalSeconds(interval config.IntervalConfig, fallback time.Duration) float64 {
	d := interval.Duration()
	if d <= 0 {
		d = fallback
	}
	return d.Seconds()
}

func cyclesPerHour(seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return 3600 / seconds
}

func durationLabel(seconds float64) string {
	switch {
	case seconds >= 3600:
		hours := seconds / 3600
		if math.Mod(seconds, 3600) == 0 {
			return fmt.Sprintf("%.0fh", hours)
		}
		return fmt.Sprintf("%.1fh", hours)
	case seconds >= 60:
		minutes := seconds / 60
		if math.Mod(seconds, 60) == 0 {
			return fmt.Sprintf("%.0fm", minutes)
		}
		return fmt.Sprintf("%.1fm", minutes)
	default:
		return fmt.Sprintf("%.0fs", seconds)
	}
}

func cidrUsableHosts(cidr string) int {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil {
		return 0
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return 0
	}
	if ones >= 31 {
		return 1 << (bits - ones)
	}
	hosts := (1 << (bits - ones)) - 2
	if hosts < 0 {
		return 0
	}
	return hosts
}

func tableBlockHeight(rows int) float64 {
	if rows <= 0 {
		return 24
	}
	return float64(rows*20 + 34)
}

func pingLatencySeries(rows []storage.PingResult) []float64 {
	values := make([]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		values = append(values, rows[i].LatencyMS)
	}
	return values
}

func dnsSeries(rows []storage.DNSResult) []float64 {
	values := make([]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		values = append(values, rows[i].DurationMS)
	}
	return values
}

func httpSeries(rows []storage.HTTPResult) []float64 {
	values := make([]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		values = append(values, rows[i].DurationMS)
	}
	return values
}

func speedDownSeries(rows []storage.SpeedtestResult) []float64 {
	values := make([]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		values = append(values, rows[i].DownloadMbps)
	}
	return values
}

func speedUpSeries(rows []storage.SpeedtestResult) []float64 {
	values := make([]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		values = append(values, rows[i].UploadMbps)
	}
	return values
}

type pdfColor struct {
	r float64
	g float64
	b float64
}

var (
	pdfInk      = pdfColor{0.09, 0.13, 0.19}
	pdfMuted    = pdfColor{0.38, 0.44, 0.52}
	pdfLine     = pdfColor{0.84, 0.88, 0.93}
	pdfPanel    = pdfColor{0.98, 0.99, 1.00}
	pdfHeader   = pdfColor{0.07, 0.11, 0.20}
	pdfOK       = pdfColor{0.09, 0.50, 0.24}
	pdfWarn     = pdfColor{0.63, 0.38, 0.03}
	pdfCritical = pdfColor{0.78, 0.15, 0.18}
	pdfInfo     = pdfColor{0.04, 0.41, 0.85}
	pdfBlue     = pdfColor{0.04, 0.41, 0.85}
	pdfTeal     = pdfColor{0.06, 0.46, 0.43}
)

type pdfRenderer struct {
	pages []string
	buf   strings.Builder
	y     float64
}

func visualPDF(input Input, title string) ([]byte, error) {
	p := &pdfRenderer{}
	p.newPage()
	p.header(title, input)
	p.scoreCards(input)
	p.section("Executive summary")
	p.executiveSummary(input)
	p.section("Problem radar")
	p.problemRadar(input)
	p.ensure(270)
	p.section("Health impact")
	p.healthImpact(input)
	p.section("Appliance network load")
	p.networkLoad(input)
	p.section("Triage board")
	p.triageBoard(input)
	p.section("Important findings")
	p.findings(input)
	p.y -= 10
	p.ensure(130)
	p.section("Fault domain")
	p.faultMap(input)
	p.ensure(288)
	p.section("Trends")
	p.trends(input)
	p.ensure(250)
	p.section("Alerts")
	p.alertLifecycle(input.Alerts)
	p.alertTable(input.Alerts)
	p.y -= 12
	p.ensure(160)
	p.section("Check details")
	p.checkTables(input)
	p.finishPage()
	return p.bytes(), nil
}

func (p *pdfRenderer) newPage() {
	if p.buf.Len() > 0 {
		p.finishPage()
	}
	p.buf.Reset()
	p.y = 800
}

func (p *pdfRenderer) finishPage() {
	if p.buf.Len() == 0 {
		return
	}
	p.pages = append(p.pages, p.buf.String())
	p.buf.Reset()
}

func (p *pdfRenderer) ensure(height float64) {
	if p.y-height < 42 {
		p.newPage()
	}
}

func (p *pdfRenderer) header(title string, input Input) {
	p.rect(0, 770, 595, 72, pdfHeader, "")
	p.text(34, 812, 20, true, pdfColor{1, 1, 1}, title)
	p.text(34, 792, 10, false, pdfColor{0.82, 0.87, 0.94}, input.Site.Name+" / "+input.Site.ID+" / "+input.Site.Location)
	p.text(34, 778, 9, false, pdfColor{0.82, 0.87, 0.94}, "Period: "+input.PeriodStart.Format("2006-01-02 15:04")+" to "+input.PeriodEnd.Format("2006-01-02 15:04")+" UTC")
	p.text(410, 792, 9, false, pdfColor{0.82, 0.87, 0.94}, "Generated: "+time.Now().UTC().Format("2006-01-02 15:04")+" UTC")
	p.y = 744
	if input.StatsLabel != "" {
		p.text(34, p.y, 9, false, pdfMuted, input.StatsLabel)
		p.y -= 18
	}
}

func (p *pdfRenderer) scoreCards(input Input) {
	p.ensure(120)
	cards := []struct {
		label string
		value int
	}{
		{"Overall", input.Health.OverallHealthScore},
		{"WAN", input.Health.WANScore},
		{"DNS", input.Health.DNSScore},
		{"Gateway/LAN", input.Health.GatewayLANScore},
		{"Services", input.Health.ServiceAvailability},
		{"Inventory", input.Health.DeviceInventoryScore},
	}
	x := 34.0
	w := 82.0
	for i, card := range cards {
		if i == 0 {
			w = 112
		} else {
			w = 76
		}
		c := scoreColor(card.value)
		p.rect(x, p.y-70, w, 64, pdfColor{0.98, 0.99, 1}, fmt.Sprintf("%.3f %.3f %.3f", c.r, c.g, c.b))
		p.rect(x, p.y-70, 6, 64, c, "")
		p.text(x+12, p.y-26, 9, true, pdfMuted, card.label)
		p.text(x+12, p.y-52, 24, true, c, strconv.Itoa(card.value))
		x += w + 8
	}
	p.y -= 90
	p.text(34, p.y, 12, true, statusColor(input.Health.Status), "Status: "+strings.ToUpper(defaultText(input.Health.Status, "unknown")))
	p.text(170, p.y, 10, false, pdfMuted, fmt.Sprintf("Devices: %d known / %d new / %d missing", len(input.Devices), len(input.NewDevices), len(input.MissingDevices)))
	if len(input.Speedtest) > 0 {
		s := input.Speedtest[0]
		p.text(370, p.y, 10, false, pdfMuted, fmt.Sprintf("WAN latest: %.0f down / %.0f up Mbps", s.DownloadMbps, s.UploadMbps))
	}
	p.y -= 26
}

func (p *pdfRenderer) section(title string) {
	p.ensure(40)
	p.text(34, p.y, 15, true, pdfInk, title)
	p.line(34, p.y-7, 561, p.y-7, pdfLine, 1)
	p.y -= 24
}

type summaryDomain struct {
	Name   string
	Score  int
	Status string
	Why    string
	Action string
}

func primaryDomain(input Input) summaryDomain {
	candidates := []summaryDomain{
		{"Gateway/LAN", input.Health.GatewayLANScore, scoreStatus(input.Health.GatewayLANScore), "router and local reachability", "Run ping and inspect gateway/LAN loss"},
		{"WAN", input.Health.WANScore, scoreStatus(input.Health.WANScore), "internet path", "Run WAN speed and internet ping"},
		{"DNS", input.Health.DNSScore, scoreStatus(input.Health.DNSScore), "name resolution", "Run DNS checks and compare resolvers"},
		{"Services", input.Health.ServiceAvailability, scoreStatus(input.Health.ServiceAvailability), "HTTP/TLS targets", "Run HTTP/TLS checks"},
		{"Inventory", input.Health.DeviceInventoryScore, scoreStatus(input.Health.DeviceInventoryScore), "LAN inventory changes", "Review new and missing devices"},
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Score < candidates[j].Score })
	if len(candidates) == 0 {
		return summaryDomain{"Incomplete", 0, "info", "health data missing", "Run core checks"}
	}
	first := candidates[0]
	if input.Health.OverallHealthScore > 0 && input.Health.OverallHealthScore < first.Score-5 {
		return summaryDomain{"Alerts/thresholds", input.Health.OverallHealthScore, scoreStatus(input.Health.OverallHealthScore), "active alerts or threshold caps lower the overall score", "Review active findings and thresholds"}
	}
	if first.Score >= 85 && input.Health.OverallHealthScore >= 85 {
		return summaryDomain{"Healthy", first.Score, "ok", "all main domains are green", "Watch trends or run phone Wi-Fi Live if users complain"}
	}
	if first.Score >= 85 {
		return summaryDomain{"Alerts/thresholds", input.Health.OverallHealthScore, "warning", "scores are high but status is not clean", "Review active findings and thresholds"}
	}
	return first
}

func (p *pdfRenderer) executiveSummary(input Input) {
	p.ensure(132)
	domain := primaryDomain(input)
	critical, warning, info := 0, 0, 0
	for _, alert := range input.Alerts {
		switch strings.ToLower(alert.Severity) {
		case "critical":
			critical++
		case "warning":
			warning++
		case "info":
			info++
		}
	}
	maxLoss := 0.0
	for _, row := range input.Ping {
		if row.LossPercent > maxLoss {
			maxLoss = row.LossPercent
		}
	}
	maxHTTP := 0.0
	for _, row := range input.HTTP {
		if row.DurationMS > maxHTTP {
			maxHTTP = row.DurationMS
		}
	}
	signal := "-"
	if len(input.Speedtest) > 0 {
		s := input.Speedtest[0]
		signal = fmt.Sprintf("%.0f down / %.0f up", s.DownloadMbps, s.UploadMbps)
	} else if maxHTTP > 0 {
		signal = fmt.Sprintf("%.0f ms HTTP", maxHTTP)
	}
	cards := []struct {
		label  string
		value  string
		detail string
		status string
	}{
		{"Primary suspect", domain.Name, domain.Why + " - " + scoreLabel(domain.Score), domain.Status},
		{"Next action", domain.Action, "Start here before broad troubleshooting.", domain.Status},
		{"Alert pressure", fmt.Sprintf("%d / %d / %d", critical, warning, info), "critical / warning / info in selected report data", alertStatus(critical, warning, info)},
		{"Current signal", signal, fmt.Sprintf("max loss %.2f%%; slowest HTTP %.0f ms; devices %d", maxLoss, maxHTTP, len(input.Devices)), signalStatus(maxLoss, maxHTTP)},
	}
	x := 34.0
	y := p.y - 86
	cardW := 125.0
	for i, card := range cards {
		c := statusColor(card.status)
		p.rect(x, y, cardW, 74, pdfPanel, "0.840 0.880 0.930")
		p.rect(x, y, 5, 74, c, "")
		p.text(x+12, y+56, 7.5, true, pdfMuted, strings.ToUpper(card.label))
		p.textWrapped(x+12, y+43, 10.0, true, c, card.value, int(cardW/5.2), 2, 10)
		p.textWrapped(x+12, y+17, 6.8, false, pdfMuted, card.detail, int(cardW/3.7), 2, 8)
		if i == 1 {
			cardW = 125
		}
		x += cardW + 9
	}
	p.y -= 104
}

type radarDomain struct {
	Name   string
	Short  string
	Score  int
	Action string
}

func radarDomains(input Input) []radarDomain {
	return []radarDomain{
		{"Gateway/LAN", "LAN", input.Health.GatewayLANScore, "Check gateway reachability, packet loss, VLAN/switch/Wi-Fi path."},
		{"WAN", "WAN", input.Health.WANScore, "Run WAN speed and public reachability checks; compare with baseline."},
		{"DNS", "DNS", input.Health.DNSScore, "Compare DNS resolvers and verify DHCP-provided DNS servers."},
		{"Services/TLS", "SVC", input.Health.ServiceAvailability, "Inspect slow/failing HTTP/TLS targets, proxy/firewall path, and certificates."},
		{"Inventory", "INV", input.Health.DeviceInventoryScore, "Review new/missing LAN devices and label expected hosts."},
	}
}

func (p *pdfRenderer) problemRadar(input Input) {
	domains := radarDomains(input)
	if len(domains) == 0 {
		return
	}
	p.ensure(230)
	x := 34.0
	y := p.y - 206
	w := 527.0
	h := 198.0
	p.rect(x, y, w, h, pdfPanel, "0.840 0.880 0.930")
	p.text(x+14, y+h-18, 8, false, pdfMuted, "Smallest spoke is the first appliance-side suspect. Scores are appliance-side fault domains.")

	cx := x + 138
	cy := y + 92
	radius := 64.0
	count := len(domains)
	for _, ring := range []float64{25, 50, 75, 100} {
		pts := radarPoints(cx, cy, radius*ring/100, count, nil)
		p.polygon(pts, pdfColor{0, 0, 0}, pdfLine, 0.7, false)
		if ring < 100 {
			p.text(cx+5, cy-radius*ring/100, 6.5, false, pdfMuted, fmt.Sprintf("%.0f", ring))
		}
	}
	var scores []float64
	weakest := 0
	for i, domain := range domains {
		if domain.Score < domains[weakest].Score {
			weakest = i
		}
		angle := -math.Pi/2 + float64(i)*2*math.Pi/float64(count)
		outerX := cx + math.Cos(angle)*radius
		outerY := cy + math.Sin(angle)*radius
		p.line(cx, cy, outerX, outerY, pdfLine, 0.6)
		p.text(cx+math.Cos(angle)*(radius+18)-8, cy+math.Sin(angle)*(radius+18), 7.2, true, pdfInk, domain.Short)
		scores = append(scores, float64(clampInt(domain.Score, 0, 100)))
	}
	p.polygon(radarPoints(cx, cy, radius, count, scores), pdfColor{0.86, 0.95, 0.94}, pdfTeal, 1.3, true)
	for i, domain := range domains {
		angle := -math.Pi/2 + float64(i)*2*math.Pi/float64(count)
		pointR := radius * float64(clampInt(domain.Score, 0, 100)) / 100
		pointX := cx + math.Cos(angle)*pointR
		pointY := cy + math.Sin(angle)*pointR
		r := 2.4
		if i == weakest {
			r = 3.8
		}
		p.circle(pointX, pointY, r, scoreColor(domain.Score))
	}

	focus := radarFocus(input, domains[weakest])
	focusColor := scoreColor(focus.Score)
	p.rect(x+292, y+122, 220, 52, pdfColor{1, 1, 1}, "0.840 0.880 0.930")
	p.rect(x+292, y+122, 6, 52, focusColor, "")
	p.text(x+306, y+158, 7.2, true, pdfMuted, "PRIMARY FOCUS")
	p.text(x+306, y+141, 12, true, focusColor, fmt.Sprintf("%s - %d/100", focus.Name, focus.Score))
	p.text(x+306, y+128, 7.2, false, pdfMuted, truncate(focus.Action, 56))

	barX := x + 292
	barY := y + 100
	for _, domain := range domains {
		color := scoreColor(domain.Score)
		p.text(barX, barY+4, 7.2, true, pdfInk, domain.Name)
		p.rect(barX+78, barY-2, 108, 8, pdfColor{0.91, 0.94, 0.97}, "")
		p.rect(barX+78, barY-2, 108*float64(clampInt(domain.Score, 0, 100))/100, 8, color, "")
		p.text(barX+194, barY+4, 7.2, false, pdfMuted, fmt.Sprintf("%d", domain.Score))
		barY -= 17
	}
	p.y -= 224
}

func radarFocus(input Input, fallback radarDomain) radarDomain {
	primary := primaryDomain(input)
	if primary.Name == "" || strings.EqualFold(primary.Name, fallback.Name) {
		return fallback
	}
	for _, domain := range radarDomains(input) {
		if strings.EqualFold(primary.Name, domain.Name) {
			return domain
		}
	}
	return radarDomain{Name: primary.Name, Short: primary.Name, Score: primary.Score, Action: primary.Action}
}

func radarPoints(cx, cy, radius float64, count int, scores []float64) [][2]float64 {
	points := make([][2]float64, 0, count)
	for i := 0; i < count; i++ {
		scale := 1.0
		if len(scores) > i {
			scale = clampFloat(scores[i], 0, 100) / 100
		}
		angle := -math.Pi/2 + float64(i)*2*math.Pi/float64(count)
		points = append(points, [2]float64{cx + math.Cos(angle)*radius*scale, cy + math.Sin(angle)*radius*scale})
	}
	return points
}

func htmlRadarPoints(domains []radarDomain) string {
	points := radarPoints(115, 105, 74, len(domains), radarDomainScores(domains))
	return htmlPointString(points)
}

func htmlRadarRing(percent float64, count int) string {
	return htmlPointString(radarPoints(115, 105, 74*percent/100, count, nil))
}

func htmlRadarAxisX(index, count int) string {
	if count <= 0 {
		return "115"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(count)
	return fmt.Sprintf("%.1f", 115+math.Cos(angle)*74)
}

func htmlRadarAxisY(index, count int) string {
	if count <= 0 {
		return "105"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(count)
	return fmt.Sprintf("%.1f", 105+math.Sin(angle)*74)
}

func htmlRadarPointX(index int, domains []radarDomain) string {
	if len(domains) == 0 || index < 0 || index >= len(domains) {
		return "115"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(len(domains))
	radius := 74 * float64(clampInt(domains[index].Score, 0, 100)) / 100
	return fmt.Sprintf("%.1f", 115+math.Cos(angle)*radius)
}

func htmlRadarPointY(index int, domains []radarDomain) string {
	if len(domains) == 0 || index < 0 || index >= len(domains) {
		return "105"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(len(domains))
	radius := 74 * float64(clampInt(domains[index].Score, 0, 100)) / 100
	return fmt.Sprintf("%.1f", 105+math.Sin(angle)*radius)
}

func htmlRadarLabelX(index, count int) string {
	if count <= 0 {
		return "115"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(count)
	return fmt.Sprintf("%.1f", 115+math.Cos(angle)*100)
}

func htmlRadarLabelY(index, count int) string {
	if count <= 0 {
		return "105"
	}
	angle := -math.Pi/2 + float64(index)*2*math.Pi/float64(count)
	return fmt.Sprintf("%.1f", 105+math.Sin(angle)*100)
}

func radarDomainScores(domains []radarDomain) []float64 {
	scores := make([]float64, 0, len(domains))
	for _, domain := range domains {
		scores = append(scores, float64(clampInt(domain.Score, 0, 100)))
	}
	return scores
}

func htmlPointString(points [][2]float64) string {
	parts := make([]string, 0, len(points))
	for _, point := range points {
		parts = append(parts, fmt.Sprintf("%.1f,%.1f", point[0], point[1]))
	}
	return strings.Join(parts, " ")
}

func scoreLabel(score int) string {
	return fmt.Sprintf("%d/100", score)
}

func alertStatus(critical, warning, info int) string {
	if critical > 0 {
		return "critical"
	}
	if warning > 0 {
		return "warning"
	}
	if info > 0 {
		return "info"
	}
	return "ok"
}

func signalStatus(maxLoss, maxHTTP float64) string {
	if maxLoss > 5 || maxHTTP > 3000 {
		return "critical"
	}
	if maxLoss > 1 || maxHTTP > 1500 {
		return "warning"
	}
	return "ok"
}

func (p *pdfRenderer) healthImpact(input Input) {
	rows := []struct {
		name   string
		score  int
		detail string
	}{
		{"WAN", input.Health.WANScore, "internet path"},
		{"DNS", input.Health.DNSScore, "resolver health"},
		{"Gateway/LAN", input.Health.GatewayLANScore, "local reachability"},
		{"Services", input.Health.ServiceAvailability, "HTTP/TLS targets"},
		{"Inventory", input.Health.DeviceInventoryScore, "device changes"},
	}
	p.ensure(210)
	valid := 0
	total := 0
	weakName := ""
	weakScore := 101
	for _, row := range rows {
		if row.score < 0 {
			continue
		}
		valid++
		total += row.score
		if row.score < weakScore {
			weakScore = row.score
			weakName = row.name
		}
	}
	baseAvg := 0
	if valid > 0 {
		baseAvg = int(math.Round(float64(total) / float64(valid)))
	}
	x := 34.0
	y := p.y - 168
	w := 527.0
	p.rect(x, y, w, 160, pdfPanel, "0.840 0.880 0.930")
	p.text(x+12, y+140, 9, true, pdfMuted, fmt.Sprintf("Base category average %d / overall %d", baseAvg, input.Health.OverallHealthScore))
	note := "Overall is the visible category average."
	if input.Health.OverallHealthScore < baseAvg {
		note = "Overall is lower than the category average, likely capped by active critical/warning verdicts."
	}
	if weakName != "" {
		note = fmt.Sprintf("Weakest: %s at %d/100. %s", weakName, weakScore, note)
	}
	p.text(x+12, y+126, 8, false, pdfMuted, truncate(note, 118))
	barX := x + 116
	barW := 310.0
	for i, row := range rows {
		rowY := y + 101 - float64(i)*23
		c := scoreColor(row.score)
		p.text(x+12, rowY+5, 8, true, pdfInk, row.name)
		p.rect(barX, rowY, barW, 12, pdfColor{0.91, 0.94, 0.97}, "")
		clamped := min(100, row.score)
		if clamped < 0 {
			clamped = 0
		}
		fillW := barW * float64(clamped) / 100
		if fillW < 2 && row.score > 0 {
			fillW = 2
		}
		p.rect(barX, rowY, fillW, 12, c, "")
		penalty := 100 - row.score
		if penalty < 0 {
			penalty = 0
		}
		p.text(barX+barW+12, rowY+5, 8, true, c, fmt.Sprintf("%d/100", row.score))
		p.text(barX+barW+68, rowY+5, 7, false, pdfMuted, fmt.Sprintf("-%d", penalty))
		p.text(x+12, rowY-9, 7, false, pdfMuted, row.detail)
	}
	p.y -= 184
}

func (p *pdfRenderer) networkLoad(input Input) {
	load := networkLoad(input)
	p.ensure(154)
	p.text(34, p.y, 8, false, pdfMuted, "Estimated scheduled traffic. Speed tests and discovery are bursty; ping/DNS/HTTP are low background checks.")
	p.y -= 14
	cards := []struct {
		label  string
		value  string
		detail string
		color  pdfColor
	}{
		{"Constant checks", formatKB(load.SteadyKBPerHour), fmt.Sprintf("%d ping / %d DNS / %d HTTP", load.PingTargets, load.DNSLookups, load.HTTPTargets), pdfOK},
		{"Discovery burst", fmt.Sprintf("%d hosts", load.DiscoveryHosts), "every " + load.DiscoveryInterval, statusColor(load.BackgroundVerdictCSS)},
		{"WAN speed test", fmt.Sprintf("%.1f MB/run", load.SpeedtestMBPerRun), "every " + load.SpeedtestInterval, pdfInfo},
		{"Average", fmt.Sprintf("%.2f MB/h", load.TotalMBPerHour), load.BackgroundVerdict, statusColor(load.BackgroundVerdictCSS)},
	}
	x := 34.0
	for _, card := range cards {
		p.rect(x, p.y-58, 122, 52, pdfPanel, "0.840 0.880 0.930")
		p.rect(x, p.y-58, 5, 52, card.color, "")
		p.text(x+12, p.y-22, 7.4, true, pdfMuted, strings.ToUpper(card.label))
		p.text(x+12, p.y-38, 12, true, card.color, card.value)
		p.text(x+12, p.y-52, 7, false, pdfMuted, truncate(card.detail, 24))
		x += 135
	}
	p.y -= 72
	values := []struct {
		label string
		value float64
		unit  string
		color pdfColor
	}{
		{"Constant", load.SteadyKBPerHour / 1000, "MB/h", pdfOK},
		{"Discovery", load.DiscoveryKBPerHour / 1000, "MB/h", pdfWarn},
		{"Speedtest", load.SpeedtestMBPerHour, "MB/h", pdfBlue},
	}
	maxV := 1.0
	for _, row := range values {
		if row.value > maxV {
			maxV = row.value
		}
	}
	for _, row := range values {
		p.text(44, p.y, 7.5, true, pdfInk, row.label)
		p.rect(116, p.y-6, 360, 9, pdfColor{0.91, 0.94, 0.97}, "")
		fill := 360 * row.value / maxV
		if fill < 2 && row.value > 0 {
			fill = 2
		}
		p.rect(116, p.y-6, fill, 9, row.color, "")
		p.text(488, p.y, 7.5, false, pdfMuted, fmt.Sprintf("%.2f %s", row.value, row.unit))
		p.y -= 16
	}
	p.y -= 12
}

func formatKB(kb float64) string {
	if kb >= 1000 {
		return fmt.Sprintf("%.2f MB/h", kb/1000)
	}
	return fmt.Sprintf("%.0f KB/h", kb)
}

type pdfTriageDomain struct {
	Name     string
	Score    int
	Status   string
	Evidence []string
	Action   string
}

func (p *pdfRenderer) triageBoard(input Input) {
	domains := triageDomains(input)
	p.ensure(float64(len(domains))*48 + 18)
	p.text(34, p.y, 8, false, pdfMuted, "Sorted by urgency. Each row combines health score, current evidence, and the next technician action.")
	p.y -= 14
	for _, domain := range domains {
		p.triageRow(domain)
	}
	p.y -= 12
}

func triageDomains(input Input) []pdfTriageDomain {
	domains := []pdfTriageDomain{
		{
			Name:     "Gateway / LAN",
			Score:    input.Health.GatewayLANScore,
			Evidence: gatewayEvidence(input),
			Action:   "Run Ping, then inspect gateway loss, VLAN, switch, cabling, or Wi-Fi path.",
		},
		{
			Name:     "WAN / ISP",
			Score:    input.Health.WANScore,
			Evidence: wanEvidence(input),
			Action:   "Run WAN speed and public reachability checks; compare against baseline.",
		},
		{
			Name:     "DNS",
			Score:    input.Health.DNSScore,
			Evidence: dnsEvidence(input),
			Action:   "Run DNS checks, compare resolvers, and verify DHCP-provided DNS.",
		},
		{
			Name:     "Services / TLS",
			Score:    input.Health.ServiceAvailability,
			Evidence: serviceEvidence(input),
			Action:   "Open HTTP/TLS targets; check remote service, firewall/proxy path, and certificates.",
		},
		{
			Name:     "Inventory",
			Score:    input.Health.DeviceInventoryScore,
			Evidence: inventoryEvidence(input),
			Action:   "Review new/missing devices and label expected hosts.",
		},
	}
	for i := range domains {
		domains[i].Status = triageStatus(domains[i].Score, domains[i].Evidence)
	}
	sort.SliceStable(domains, func(i, j int) bool {
		if severityRank(domains[i].Status) != severityRank(domains[j].Status) {
			return severityRank(domains[i].Status) > severityRank(domains[j].Status)
		}
		return domains[i].Score < domains[j].Score
	})
	return domains
}

func (p *pdfRenderer) triageRow(domain pdfTriageDomain) {
	p.ensure(54)
	c := statusColor(domain.Status)
	p.rect(34, p.y-42, 527, 38, pdfPanel, "0.840 0.880 0.930")
	p.rect(34, p.y-42, 6, 38, c, "")
	p.text(48, p.y-17, 9.5, true, pdfInk, domain.Name)
	p.text(170, p.y-17, 8.5, true, c, strings.ToUpper(domain.Status)+" / "+scoreLabel(domain.Score))
	p.text(48, p.y-31, 7.5, false, pdfMuted, truncate(strings.Join(evidenceLimit(domain.Evidence, 3), " | "), 64))
	p.text(354, p.y-17, 7.5, true, pdfMuted, "Next")
	p.text(354, p.y-31, 7.2, false, pdfMuted, truncate(domain.Action, 42))
	p.y -= 46
}

func triageStatus(score int, evidence []string) string {
	text := strings.ToLower(strings.Join(evidence, " "))
	if score < 0 {
		return "info"
	}
	if score < 50 || strings.Contains(text, "critical") || strings.Contains(text, "failed") || containsDownFailure(text) {
		return "critical"
	}
	if score < 80 || strings.Contains(text, "warning") || strings.Contains(text, "failed") {
		return "warning"
	}
	return "ok"
}

func containsDownFailure(text string) bool {
	phrases := []string{
		"target down",
		"gateway down",
		"internet down",
		"service down",
		"host down",
		"ping down",
		"is down",
		"is unreachable",
		"not reachable",
		"unreachable",
	}
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func evidenceLimit(items []string, maxItems int) []string {
	deduped := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		text := strings.TrimSpace(item)
		if text == "" {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(text), " "))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, text)
	}
	if len(deduped) == 0 {
		return []string{"No current issue evidence"}
	}
	if len(deduped) <= maxItems {
		return deduped
	}
	out := append([]string{}, deduped[:maxItems]...)
	out = append(out, fmt.Sprintf("+ %d more signals", len(deduped)-maxItems))
	return out
}

func gatewayEvidence(input Input) []string {
	var evidence []string
	for _, row := range input.Ping {
		if row.TargetType == "gateway" {
			evidence = append(evidence, fmt.Sprintf("gateway %s up=%t latency %.1f ms loss %.2f%%", row.TargetHost, row.Up, row.LatencyMS, row.LossPercent))
			break
		}
	}
	return append(evidence, findingEvidence(input, "gateway", "ping", "latency", "packet loss")...)
}

func wanEvidence(input Input) []string {
	var evidence []string
	if len(input.Speedtest) > 0 {
		row := input.Speedtest[0]
		status := "success"
		if !row.Success {
			status = "failed"
		}
		evidence = append(evidence, fmt.Sprintf("WAN speed %s %.1f down / %.1f up Mbps", status, row.DownloadMbps, row.UploadMbps))
	}
	return append(evidence, findingEvidence(input, "wan", "speed", "public ip", "trace", "internet")...)
}

func dnsEvidence(input Input) []string {
	total, okCount, slowest := len(input.DNS), 0, 0.0
	for _, row := range input.DNS {
		if row.Success {
			okCount++
		}
		if row.DurationMS > slowest {
			slowest = row.DurationMS
		}
	}
	var evidence []string
	if total > 0 {
		evidence = append(evidence, fmt.Sprintf("DNS %d/%d ok, slowest %.0f ms", okCount, total, slowest))
	}
	return append(evidence, findingEvidence(input, "dns", "resolver")...)
}

func serviceEvidence(input Input) []string {
	total, upCount, slowest := len(input.HTTP), 0, 0.0
	minTLS := 0
	for _, row := range input.HTTP {
		if row.Up {
			upCount++
		}
		if row.DurationMS > slowest {
			slowest = row.DurationMS
		}
		if row.TLSDaysUntilExpiry > 0 && (minTLS == 0 || row.TLSDaysUntilExpiry < minTLS) {
			minTLS = row.TLSDaysUntilExpiry
		}
	}
	var evidence []string
	if total > 0 {
		evidence = append(evidence, fmt.Sprintf("HTTP/TLS %d/%d up, slowest %.0f ms", upCount, total, slowest))
	}
	if minTLS > 0 {
		evidence = append(evidence, fmt.Sprintf("minimum TLS expiry %d days", minTLS))
	}
	return append(evidence, findingEvidence(input, "service", "http", "https", "tls", "certificate")...)
}

func inventoryEvidence(input Input) []string {
	evidence := []string{fmt.Sprintf("%d known / %d new / %d missing devices", len(input.Devices), len(input.NewDevices), len(input.MissingDevices))}
	return append(evidence, findingEvidence(input, "inventory", "device", "lan device")...)
}

func findingEvidence(input Input, terms ...string) []string {
	var evidence []string
	matches := func(value string) bool {
		value = strings.ToLower(value)
		for _, term := range terms {
			if strings.Contains(value, strings.ToLower(term)) {
				return true
			}
		}
		return false
	}
	for _, verdict := range input.Health.Verdicts {
		if verdict.Code == "healthy" {
			continue
		}
		hay := verdict.Category + " " + verdict.Code + " " + verdict.Title + " " + verdict.Summary
		if matches(hay) {
			evidence = append(evidence, verdict.Severity+": "+defaultText(verdict.Title, verdict.Summary))
		}
	}
	for _, alert := range input.Alerts {
		hay := alert.Category + " " + alert.Title + " " + alert.Summary
		if matches(hay) {
			evidence = append(evidence, alert.Severity+": "+defaultText(alert.Title, alert.Summary))
		}
	}
	for _, check := range input.Advanced {
		hay := check.CheckType + " " + check.TargetName + " " + check.Target + " " + check.Summary + " " + check.Error
		if matches(hay) && (!check.Success || check.Severity == "warning" || check.Severity == "critical") {
			evidence = append(evidence, check.Severity+": "+defaultText(check.CheckType, "advanced check")+" "+defaultText(check.TargetName, check.Target))
		}
	}
	return evidence
}

func (p *pdfRenderer) findings(input Input) {
	rows := prioritizedFindings(input)
	if len(rows) == 0 {
		p.callout("ok", "No critical findings", "No failed or warning checks were recorded in the selected period.")
		return
	}
	for i, row := range rows {
		if i >= 8 {
			p.text(48, p.y, 9, false, pdfMuted, fmt.Sprintf("+ %d more findings in detailed tables", len(rows)-i))
			p.y -= 16
			break
		}
		p.findingRow(row)
	}
}

type pdfFinding struct {
	Severity string
	Area     string
	Title    string
	Detail   string
	When     string
	Count    int
}

func prioritizedFindings(input Input) []pdfFinding {
	var rows []pdfFinding
	for _, v := range input.Health.Verdicts {
		if v.Code == "healthy" {
			continue
		}
		rows = append(rows, pdfFinding{Severity: v.Severity, Area: v.Category, Title: v.Title, Detail: v.Summary, When: formatTime(v.Timestamp)})
	}
	for _, a := range input.Alerts {
		rows = append(rows, pdfFinding{Severity: a.Severity, Area: "alert", Title: a.Title, Detail: a.Summary, When: formatTime(a.FirstSeen)})
	}
	for _, line := range periodProblems(input) {
		rows = append(rows, pdfFinding{Severity: severityFromLine(line), Area: areaFromLine(line), Title: titleFromLine(line), Detail: strings.TrimPrefix(line, "- "), When: whenFromLine(line)})
	}
	rows = groupFindings(rows)
	sort.SliceStable(rows, func(i, j int) bool {
		if severityRank(rows[i].Severity) != severityRank(rows[j].Severity) {
			return severityRank(rows[i].Severity) > severityRank(rows[j].Severity)
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Title < rows[j].Title
	})
	return rows
}

func groupFindings(rows []pdfFinding) []pdfFinding {
	grouped := make([]pdfFinding, 0, len(rows))
	index := map[string]int{}
	for _, row := range rows {
		if row.Count == 0 {
			row.Count = 1
		}
		key := findingGroupKey(row)
		if pos, ok := index[key]; ok {
			existing := &grouped[pos]
			existing.Count++
			if severityRank(row.Severity) > severityRank(existing.Severity) {
				existing.Severity = row.Severity
			}
			if existing.When == "" || row.When > existing.When {
				existing.When = row.When
			}
			if !strings.Contains(existing.Detail, "Examples:") {
				existing.Detail = fmt.Sprintf("%d similar findings. Examples: %s | %s", existing.Count, truncate(existing.Detail, 78), truncate(row.Detail, 78))
			} else {
				existing.Detail = strings.Replace(existing.Detail, fmt.Sprintf("%d similar findings.", existing.Count-1), fmt.Sprintf("%d similar findings.", existing.Count), 1)
			}
			existing.Title = "Multiple " + normalizeFindingTitle(row.Title)
			existing.Area = normalizeFindingArea(existing.Area)
			continue
		}
		row.Area = normalizeFindingArea(row.Area)
		row.Title = normalizeFindingTitle(row.Title)
		index[key] = len(grouped)
		grouped = append(grouped, row)
	}
	return grouped
}

func findingGroupKey(row pdfFinding) string {
	area := normalizeFindingArea(row.Area)
	title := normalizeFindingTitle(row.Title)
	lowerDetail := strings.ToLower(row.Detail)
	switch {
	case strings.Contains(strings.ToLower(title), "http response slow") || strings.Contains(lowerDetail, "http response slow"):
		return area + "|http response slow"
	case strings.Contains(strings.ToLower(title), "wan speed") || strings.Contains(lowerDetail, "wan speed"):
		return area + "|wan speed"
	case strings.Contains(strings.ToLower(title), "ping latency") || strings.Contains(lowerDetail, "ping latency"):
		return area + "|ping latency"
	case strings.Contains(strings.ToLower(title), "tcp port") || strings.Contains(lowerDetail, "tcp port"):
		return area + "|tcp port"
	case strings.Contains(strings.ToLower(title), "trace") || strings.Contains(lowerDetail, "traceroute"):
		return area + "|trace"
	case strings.Contains(strings.ToLower(title), "ntp") || strings.Contains(lowerDetail, "udp/123"):
		return area + "|ntp"
	case strings.Contains(strings.ToLower(title), "public ip") || strings.Contains(lowerDetail, "public ip"):
		return area + "|public ip"
	case strings.Contains(strings.ToLower(title), "new lan device") || strings.Contains(lowerDetail, "lan device"):
		return area + "|lan inventory"
	}
	return strings.ToLower(area + "|" + title)
}

func normalizeFindingArea(area string) string {
	area = strings.ToLower(strings.TrimSpace(area))
	switch area {
	case "http", "https", "tls", "service":
		return "service"
	case "wan", "speedtest", "internet":
		return "wan"
	case "ping", "gateway", "lan":
		return "lan"
	case "advanced":
		return "advanced"
	case "alert", "alerts":
		return "alert"
	case "":
		return "check"
	default:
		return area
	}
}

func normalizeFindingTitle(title string) string {
	title = strings.TrimSpace(title)
	title = strings.TrimPrefix(title, "[ADVANCED] ")
	title = strings.TrimPrefix(title, "[PING] ")
	title = strings.TrimPrefix(title, "[DNS] ")
	title = strings.TrimPrefix(title, "[HTTP] ")
	title = strings.TrimPrefix(title, "[WAN] ")
	lower := strings.ToLower(title)
	if strings.Contains(lower, "speed_history") || strings.Contains(lower, "wan speed trend") {
		return "WAN speed trend findings"
	}
	if strings.Contains(lower, "http response slow") {
		return "HTTP response slow findings"
	}
	if strings.Contains(lower, "ping latency above baseline") {
		return "Ping latency above baseline findings"
	}
	if strings.Contains(lower, "tcp port") {
		return "TCP port check findings"
	}
	if strings.Contains(lower, "trace") {
		return "Traceroute findings"
	}
	if strings.Contains(lower, "ntp") {
		return "NTP check findings"
	}
	if strings.Contains(lower, "public ip") {
		return "Public IP check findings"
	}
	if strings.Contains(lower, " at ") {
		title = title[:strings.Index(strings.ToLower(title), " at ")]
	}
	return title
}

func (p *pdfRenderer) findingRow(row pdfFinding) {
	p.ensure(54)
	c := statusColor(row.Severity)
	p.rect(34, p.y-44, 527, 40, pdfPanel, "0.840 0.880 0.930")
	p.rect(34, p.y-44, 5, 40, c, "")
	label := strings.ToUpper(defaultText(row.Severity, "info")) + " / " + strings.ToUpper(defaultText(row.Area, "general"))
	p.text(46, p.y-18, 9, true, c, label)
	title := row.Title
	if row.Count > 1 {
		title += fmt.Sprintf(" (%d events)", row.Count)
	}
	p.text(190, p.y-18, 10, true, pdfInk, truncate(title, 58))
	p.text(46, p.y-34, 8, false, pdfMuted, truncate(row.Detail, 108))
	p.y -= 48
}

func (p *pdfRenderer) callout(kind, title, body string) {
	c := statusColor(kind)
	p.rect(34, p.y-54, 527, 46, pdfPanel, "0.840 0.880 0.930")
	p.rect(34, p.y-54, 6, 46, c, "")
	p.text(48, p.y-24, 12, true, c, title)
	p.text(48, p.y-40, 9, false, pdfMuted, body)
	p.y -= 62
}

func scoreStatus(score int) string {
	switch {
	case score >= 90:
		return "ok"
	case score >= 70:
		return "warning"
	default:
		return "critical"
	}
}

func (p *pdfRenderer) faultMap(input Input) {
	p.ensure(112)
	cards := []struct {
		title  string
		status string
		detail string
	}{
		{
			title:  "LAN devices",
			status: scoreStatus(input.Health.DeviceInventoryScore),
			detail: fmt.Sprintf("%d known / %d new / %d missing", len(input.Devices), len(input.NewDevices), len(input.MissingDevices)),
		},
		{
			title:  "Gateway",
			status: scoreStatus(input.Health.GatewayLANScore),
			detail: fmt.Sprintf("score %d", input.Health.GatewayLANScore),
		},
		{
			title:  "DNS",
			status: scoreStatus(input.Health.DNSScore),
			detail: fmt.Sprintf("score %d", input.Health.DNSScore),
		},
		{
			title:  "WAN / services",
			status: scoreStatus(min(input.Health.WANScore, input.Health.ServiceAvailability)),
			detail: fmt.Sprintf("WAN %d / services %d", input.Health.WANScore, input.Health.ServiceAvailability),
		},
	}
	x := 34.0
	y := p.y - 76
	cardW := 112.0
	gap := 26.0
	for i, card := range cards {
		c := statusColor(card.status)
		p.rect(x, y, cardW, 64, pdfPanel, "0.840 0.880 0.930")
		p.rect(x, y+59, cardW, 5, c, "")
		p.text(x+10, y+43, 10, true, pdfInk, card.title)
		p.text(x+10, y+27, 8, false, pdfMuted, truncate(card.detail, 26))
		p.text(x+10, y+11, 8, true, c, strings.ToUpper(card.status))
		if i < len(cards)-1 {
			p.line(x+cardW+6, y+32, x+cardW+gap-5, y+32, pdfLine, 1.1)
			p.text(x+cardW+11, y+36, 10, true, pdfMuted, ">")
		}
		x += cardW + gap
	}
	p.y -= 94
}

func (p *pdfRenderer) trends(input Input) {
	p.ensure(240)
	left := 34.0
	top := p.y
	p.chart(left, top-120, 250, 104, "Ping latency", pingLatencySeries(input.Ping), "ms", pdfBlue)
	p.chart(left+277, top-120, 250, 104, "DNS duration", dnsSeries(input.DNS), "ms", pdfTeal)
	p.y = top - 144
	p.ensure(130)
	top = p.y
	p.chart(left, top-120, 250, 104, "HTTP duration", httpSeries(input.HTTP), "ms", pdfOK)
	p.multiChart(left+277, top-120, 250, 104, "WAN speed", speedDownSeries(input.Speedtest), speedUpSeries(input.Speedtest))
	p.y = top - 144
}

func (p *pdfRenderer) chart(x, y, w, h float64, title string, values []float64, unit string, color pdfColor) {
	p.rect(x, y, w, h, pdfColor{1, 1, 1}, "0.840 0.880 0.930")
	p.text(x+10, y+h-18, 10, true, pdfInk, title)
	if len(values) == 0 {
		p.text(x+10, y+h/2, 9, false, pdfMuted, "No samples")
		return
	}
	stats := makeStats(values, unit)
	p.text(x+w-86, y+h-18, 8, false, color, "latest "+statValue(stats.Latest, unit))
	p.statStrip(x+10, y+10, w-20, stats, color)
	p.sparkline(x+12, y+38, w-24, h-66, values, color)
}

func (p *pdfRenderer) multiChart(x, y, w, h float64, title string, a, b []float64) {
	p.rect(x, y, w, h, pdfColor{1, 1, 1}, "0.840 0.880 0.930")
	p.text(x+10, y+h-18, 10, true, pdfInk, title)
	p.legendDot(x+w-104, y+h-16, pdfBlue, "download")
	p.legendDot(x+w-52, y+h-16, pdfOK, "upload")
	values := append(append([]float64{}, a...), b...)
	if len(values) == 0 {
		p.text(x+10, y+h/2, 9, false, pdfMuted, "No samples")
		return
	}
	p.dualStatStrip(x+10, y+6, w-20, makeStats(a, "Mbps"), makeStats(b, "Mbps"))
	p.sparklineWithScale(x+12, y+48, w-24, h-78, a, values, pdfBlue)
	p.sparklineWithScale(x+12, y+48, w-24, h-78, b, values, pdfOK)
}

func (p *pdfRenderer) statStrip(x, y, w float64, stats metricStats, color pdfColor) {
	if stats.Empty {
		return
	}
	labels := []struct {
		name  string
		value float64
	}{
		{"min", stats.Min},
		{"avg", stats.Avg},
		{"max", stats.Max},
	}
	chipW := (w - 8) / 3
	for i, item := range labels {
		cx := x + float64(i)*(chipW+4)
		p.rect(cx, y, chipW, 18, pdfColor{0.96, 0.98, 1}, "0.870 0.910 0.950")
		p.text(cx+5, y+6, 7.2, false, pdfMuted, item.name)
		p.text(cx+24, y+6, 7.2, true, color, statValue(item.value, stats.Unit))
	}
}

func (p *pdfRenderer) dualStatStrip(x, y, w float64, down, up metricStats) {
	p.rect(x, y, w, 38, pdfColor{0.96, 0.98, 1}, "0.870 0.910 0.950")
	if !down.Empty {
		p.speedStatRow(x+7, y+24, w-14, "down", down, pdfBlue)
	}
	if !up.Empty {
		p.speedStatRow(x+7, y+10, w-14, "up", up, pdfOK)
	}
}

func (p *pdfRenderer) speedStatRow(x, y, w float64, label string, stats metricStats, color pdfColor) {
	p.text(x, y, 6.8, true, color, label)
	start := x + 34
	chipW := (w - 40) / 3
	items := []struct {
		name  string
		value float64
	}{
		{"min", stats.Min},
		{"avg", stats.Avg},
		{"max", stats.Max},
	}
	for i, item := range items {
		cx := start + float64(i)*chipW
		p.text(cx, y, 6.6, false, pdfMuted, item.name)
		p.text(cx+16, y, 6.6, true, color, fmt.Sprintf("%.0f Mbps", item.value))
	}
}

func (p *pdfRenderer) legendDot(x, y float64, color pdfColor, label string) {
	p.circle(x, y+2, 2.2, color)
	p.text(x+6, y, 7.0, false, color, label)
}

func (p *pdfRenderer) sparkline(x, y, w, h float64, values []float64, color pdfColor) {
	p.sparklineWithScale(x, y, w, h, values, values, color)
}

func (p *pdfRenderer) sparklineWithScale(x, y, w, h float64, values, scale []float64, color pdfColor) {
	if len(values) == 0 || len(scale) == 0 {
		return
	}
	values = downsample(values, 72)
	scale = downsample(scale, 72)
	minV, maxV := minMax(scale)
	if math.Abs(maxV-minV) < 0.001 {
		maxV += 1
		minV -= 1
	}
	p.line(x, y, x+w, y, pdfLine, 0.7)
	p.line(x, y+h, x+w, y+h, pdfLine, 0.5)
	if len(values) == 1 {
		px := x + w
		py := y + ((values[0] - minV) / (maxV - minV) * h)
		p.circle(px, py, 2, color)
		return
	}
	var path strings.Builder
	for i, v := range values {
		px := x + (float64(i)/float64(len(values)-1))*w
		py := y + ((v - minV) / (maxV - minV) * h)
		if i == 0 {
			path.WriteString(fmt.Sprintf("%.2f %.2f m ", px, py))
		} else {
			path.WriteString(fmt.Sprintf("%.2f %.2f l ", px, py))
		}
	}
	p.buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG 1.0 w %s S\n", color.r, color.g, color.b, path.String()))
}

func (p *pdfRenderer) alertTable(alerts []storage.AlertRecord) {
	if len(alerts) == 0 {
		p.callout("ok", "No alerts in selected period", "No active or historical alerts matched the selected period.")
		return
	}
	count := min(len(alerts), 12)
	p.ensure(tableBlockHeight(count))
	p.table([]string{"Severity", "State", "Alert", "First seen"}, []float64{62, 72, 288, 105}, count, func(i int) []string {
		a := alerts[i]
		state := "cleared"
		if a.Active {
			state = "active"
		}
		if a.Acknowledged {
			state += " / ack"
		}
		return []string{strings.ToUpper(a.Severity), state, truncate(a.Title+": "+a.Summary, 72), formatTime(a.FirstSeen)}
	})
	if len(alerts) > 12 {
		p.text(40, p.y, 8, false, pdfMuted, fmt.Sprintf("+ %d more alerts", len(alerts)-12))
		p.y -= 14
	}
}

type alertLifeSummary struct {
	Total        int
	Active       int
	Acknowledged int
	Closed       int
	Hidden       int
	BarActive    int
	BarAck       int
	BarClosed    int
	BarHidden    int
	Status       string
}

func alertLifecycleSummary(alerts []storage.AlertRecord) alertLifeSummary {
	out := alertLifeSummary{Total: len(alerts)}
	now := time.Now().UTC()
	for _, alert := range alerts {
		hidden := alert.SuppressedUntil != nil && alert.SuppressedUntil.After(now)
		if alert.Active {
			out.Active++
		}
		if alert.Acknowledged {
			out.Acknowledged++
		}
		if !alert.Active && alert.ClearedAt != nil {
			out.Closed++
		}
		if hidden {
			out.Hidden++
			out.BarHidden++
			continue
		}
		if alert.Active && alert.Acknowledged {
			out.BarAck++
			continue
		}
		if alert.Active {
			out.BarActive++
			continue
		}
		if !alert.Active {
			out.BarClosed++
		}
	}
	out.Status = alertLifecycleStatus(out.Active, out.Total)
	return out
}

func alertLifePercent(count, total int) string {
	if total <= 0 || count <= 0 {
		return "0%"
	}
	value := float64(count) * 100 / float64(total)
	return fmt.Sprintf("%.1f%%", value)
}

func (p *pdfRenderer) alertLifecycle(alerts []storage.AlertRecord) {
	life := alertLifecycleSummary(alerts)
	p.ensure(96)
	cards := []struct {
		Label string
		Value int
		Color pdfColor
	}{
		{"Total", life.Total, pdfInfo},
		{"Active", life.Active, statusColor(life.Status)},
		{"Acked", life.Acknowledged, pdfTeal},
		{"Closed", life.Closed, pdfOK},
		{"Hidden", life.Hidden, pdfMuted},
	}
	x := 34.0
	for _, card := range cards {
		p.rect(x, p.y-46, 96, 42, pdfPanel, fmt.Sprintf("%.3f %.3f %.3f", card.Color.r, card.Color.g, card.Color.b))
		p.rect(x, p.y-46, 5, 42, card.Color, "")
		p.text(x+12, p.y-19, 8, true, pdfMuted, card.Label)
		p.text(x+12, p.y-36, 16, true, card.Color, strconv.Itoa(card.Value))
		x += 106
	}
	p.y -= 58
	p.lifecycleBar(34, p.y-16, 527, 12, life.BarActive, life.BarAck, life.BarClosed, life.BarHidden, life.Total)
	p.text(34, p.y-34, 8, false, pdfMuted, "Lifecycle bar: red active, amber acknowledged, green closed, grey hidden. Segments are exclusive.")
	p.y -= 50
}

func alertLifecycleStatus(active, total int) string {
	if active == 0 {
		return "ok"
	}
	if total > 0 && active == total {
		return "critical"
	}
	return "warning"
}

func (p *pdfRenderer) lifecycleBar(x, y, w, h float64, active, acknowledged, closed, hidden, total int) {
	p.rect(x, y, w, h, pdfColor{0.91, 0.94, 0.97}, "")
	if total <= 0 {
		return
	}
	segments := []struct {
		Count int
		Color pdfColor
	}{
		{active, pdfCritical},
		{acknowledged, pdfWarn},
		{closed, pdfOK},
		{hidden, pdfMuted},
	}
	used := 0
	offset := x
	for _, segment := range segments {
		if segment.Count <= 0 {
			continue
		}
		width := w * float64(segment.Count) / float64(total)
		if used+segment.Count >= total {
			width = x + w - offset
		}
		p.rect(offset, y, width, h, segment.Color, "")
		offset += width
		used += segment.Count
	}
	if used < total {
		p.rect(offset, y, x+w-offset, h, pdfInfo, "")
	}
}

func (p *pdfRenderer) checkTables(input Input) {
	down := speedDownSeries(input.Speedtest)
	up := speedUpSeries(input.Speedtest)
	speedRows := min(len(input.Speedtest), 6)
	p.ensure(44 + tableBlockHeight(speedRows))
	p.text(34, p.y, 11, true, pdfInk, "WAN speed summary")
	p.y -= 14
	p.text(34, p.y, 8, false, pdfBlue, "Download "+compactStatsLine(down, "Mbps"))
	p.y -= 11
	p.text(34, p.y, 8, false, pdfOK, "Upload "+compactStatsLine(up, "Mbps"))
	p.y -= 14
	p.table([]string{"Time", "Success", "Download", "Upload"}, []float64{158, 82, 110, 110}, speedRows, func(i int) []string {
		s := input.Speedtest[i]
		return []string{formatTime(s.Timestamp), boolStatus(s.Success), fmt.Sprintf("%.1f Mbps", s.DownloadMbps), fmt.Sprintf("%.1f Mbps", s.UploadMbps)}
	})
	problems := prioritizedFindings(input)
	problemRows := min(len(problems), 12)
	p.ensure(22 + tableBlockHeight(problemRows))
	p.text(34, p.y, 11, true, pdfInk, "Latest failed/warning checks")
	p.y -= 14
	p.table([]string{"Priority", "Area", "Finding", "Events", "Latest", "Details"}, []float64{62, 62, 130, 48, 84, 141}, problemRows, func(i int) []string {
		f := problems[i]
		return []string{
			strings.ToUpper(f.Severity),
			strings.ToUpper(f.Area),
			truncate(f.Title, 38),
			strconv.Itoa(max(1, f.Count)),
			defaultText(f.When, "-"),
			truncate(f.Detail, 54),
		}
	})
}

func (p *pdfRenderer) table(headers []string, widths []float64, count int, row func(int) []string) {
	if count == 0 {
		p.text(40, p.y, 9, false, pdfMuted, "No rows")
		p.y -= 18
		return
	}
	rows := make([]pdfTableRow, 0, count)
	totalHeight := 30.0
	for i := 0; i < count; i++ {
		rows = append(rows, makePDFTableRow(row(i), widths))
		totalHeight += rows[len(rows)-1].Height
	}
	p.ensure(totalHeight)
	x := 34.0
	w := sumFloat(widths)
	headerH := 20.0
	p.rect(x, p.y-headerH, w, headerH, pdfColor{0.95, 0.97, 0.99}, "0.840 0.880 0.930")
	colX := x
	for i, h := range headers {
		p.text(colX+6, p.y-14, 8, true, pdfMuted, h)
		colX += widths[i]
	}
	p.y -= headerH
	for i, tableRow := range rows {
		fill := pdfColor{1, 1, 1}
		if i%2 == 1 {
			fill = pdfColor{0.98, 0.99, 1}
		}
		p.rect(x, p.y-tableRow.Height, w, tableRow.Height, fill, "0.900 0.925 0.955")
		colX = x
		for j, lines := range tableRow.Cells {
			color := pdfInk
			if j == 0 {
				color = statusColor(strings.ToLower(strings.Join(lines, " ")))
			}
			for lineIndex, line := range lines {
				p.text(colX+6, p.y-14-float64(lineIndex)*8.5, 7.3, false, color, line)
			}
			colX += widths[j]
		}
		p.y -= tableRow.Height
	}
	p.y -= 10
}

type pdfTableRow struct {
	Cells  [][]string
	Height float64
}

func makePDFTableRow(cells []string, widths []float64) pdfTableRow {
	out := pdfTableRow{Cells: make([][]string, 0, len(cells)), Height: 20}
	maxLines := 1
	for i, cell := range cells {
		width := 80.0
		if i < len(widths) {
			width = widths[i]
		}
		lines := wrapPDFCell(cell, int(width/4.1), 2)
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
		out.Cells = append(out.Cells, lines)
	}
	if maxLines > 1 {
		out.Height = 20 + float64(maxLines-1)*8.5
	}
	return out
}

func wrapPDFCell(value string, width int, maxLines int) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{"-"}
	}
	if width < 8 {
		width = 8
	}
	if maxLines < 1 {
		maxLines = 1
	}
	var lines []string
	for len(value) > width && len(lines) < maxLines-1 {
		cut := strings.LastIndex(value[:width], " ")
		if cut < 8 {
			cut = width
		}
		lines = append(lines, strings.TrimSpace(value[:cut]))
		value = strings.TrimSpace(value[cut:])
	}
	lines = append(lines, truncate(value, width))
	return lines
}

func (p *pdfRenderer) text(x, y, size float64, bold bool, c pdfColor, value string) {
	font := "F1"
	if bold {
		font = "F2"
	}
	p.buf.WriteString(fmt.Sprintf("BT /%s %.1f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n", font, size, c.r, c.g, c.b, x, y, pdfEscape(value)))
}

func (p *pdfRenderer) textWrapped(x, y, size float64, bold bool, c pdfColor, value string, width int, maxLines int, lineGap float64) {
	for i, line := range wrapPDFCell(value, width, maxLines) {
		p.text(x, y-float64(i)*lineGap, size, bold, c, line)
	}
}

func (p *pdfRenderer) rect(x, y, w, h float64, fill pdfColor, stroke string) {
	p.buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n", fill.r, fill.g, fill.b, x, y, w, h))
	if stroke != "" {
		p.buf.WriteString(fmt.Sprintf("%s RG %.2f %.2f %.2f %.2f re S\n", stroke, x, y, w, h))
	}
}

func (p *pdfRenderer) line(x1, y1, x2, y2 float64, c pdfColor, width float64) {
	p.buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S\n", c.r, c.g, c.b, width, x1, y1, x2, y2))
}

func (p *pdfRenderer) polygon(points [][2]float64, fill, stroke pdfColor, width float64, filled bool) {
	if len(points) == 0 {
		return
	}
	p.buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg %.3f %.3f %.3f RG %.2f w ", fill.r, fill.g, fill.b, stroke.r, stroke.g, stroke.b, width))
	p.buf.WriteString(fmt.Sprintf("%.2f %.2f m ", points[0][0], points[0][1]))
	for _, point := range points[1:] {
		p.buf.WriteString(fmt.Sprintf("%.2f %.2f l ", point[0], point[1]))
	}
	if filled {
		p.buf.WriteString("h B\n")
		return
	}
	p.buf.WriteString("h S\n")
}

func (p *pdfRenderer) circle(x, y, r float64, c pdfColor) {
	p.buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n", c.r, c.g, c.b, x-r, y-r, r*2, r*2))
}

func (p *pdfRenderer) bytes() []byte {
	if p.buf.Len() > 0 {
		p.finishPage()
	}
	var objects []string
	objects = append(objects, "<< /Type /Catalog /Pages 2 0 R >>")
	kids := make([]string, 0, len(p.pages))
	for i := range p.pages {
		kids = append(kids, strconv.Itoa(3+i*2)+" 0 R")
	}
	objects = append(objects, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(p.pages)))
	font1 := 3 + len(p.pages)*2
	font2 := font1 + 1
	for i, stream := range p.pages {
		pageObj := 3 + i*2
		contentObj := pageObj + 1
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>", font1, font2, contentObj))
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, obj := range objects {
		offsets = append(offsets, buf.Len())
		buf.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, obj))
	}
	xref := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(objects)+1))
	for i := 1; i < len(offsets); i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref))
	return buf.Bytes()
}

func simplePDF(lines []string) ([]byte, error) {
	pages := paginate(wrapLines(lines, 92), 48)
	var objects []string
	objects = append(objects, "<< /Type /Catalog /Pages 2 0 R >>")
	kids := make([]string, 0, len(pages))
	for i := range pages {
		pageObj := 3 + i*2
		kids = append(kids, strconv.Itoa(pageObj)+" 0 R")
	}
	objects = append(objects, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	for i, page := range pages {
		pageObj := 3 + i*2
		contentObj := pageObj + 1
		stream := pdfTextStream(page)
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", 3+len(pages)*2, contentObj))
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, obj := range objects {
		offsets = append(offsets, buf.Len())
		buf.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, obj))
	}
	xref := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(objects)+1))
	for i := 1; i < len(offsets); i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref))
	return buf.Bytes(), nil
}

func wrapLines(lines []string, width int) []string {
	var out []string
	for _, line := range lines {
		line = strings.TrimRight(line, " ")
		if line == "" {
			out = append(out, "")
			continue
		}
		for len(line) > width {
			cut := strings.LastIndex(line[:width], " ")
			if cut < 35 {
				cut = width
			}
			out = append(out, line[:cut])
			line = strings.TrimSpace(line[cut:])
		}
		out = append(out, line)
	}
	return out
}

func paginate(lines []string, perPage int) [][]string {
	var pages [][]string
	for len(lines) > 0 {
		n := perPage
		if len(lines) < n {
			n = len(lines)
		}
		pages = append(pages, lines[:n])
		lines = lines[n:]
	}
	if len(pages) == 0 {
		pages = append(pages, []string{"Infracheck report"})
	}
	return pages
}

func pdfTextStream(lines []string) string {
	var b strings.Builder
	b.WriteString("BT /F1 10 Tf 40 806 Td 14 TL\n")
	for _, line := range lines {
		b.WriteString("(")
		b.WriteString(pdfEscape(line))
		b.WriteString(") Tj T*\n")
	}
	b.WriteString("ET")
	return b.String()
}

func pdfEscape(s string) string {
	s = asciiPDF(s)
	replacer := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`, "\t", "    ")
	return replacer.Replace(s)
}

func asciiPDF(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r <= 126) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('?')
	}
	return b.String()
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format(time.RFC3339)
	},
	"scoreStatus":      scoreStatus,
	"radarPoints":      htmlRadarPoints,
	"radarRing":        htmlRadarRing,
	"radarAxisX":       htmlRadarAxisX,
	"radarAxisY":       htmlRadarAxisY,
	"radarPointX":      htmlRadarPointX,
	"radarPointY":      htmlRadarPointY,
	"radarLabelX":      htmlRadarLabelX,
	"radarLabelY":      htmlRadarLabelY,
	"alertLifePercent": alertLifePercent,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #17202a; }
    h1, h2 { margin-bottom: 8px; }
    .meta { color: #52616b; margin-bottom: 24px; }
    .scores { display: grid; grid-template-columns: repeat(6, minmax(100px, 1fr)); gap: 12px; margin: 20px 0; }
    .score { border: 1px solid #d8dee4; padding: 12px; border-radius: 6px; }
    .score strong { display: block; font-size: 24px; }
    .radar { display: grid; grid-template-columns: minmax(220px, 0.8fr) 1.2fr; gap: 16px; border: 1px solid #d8dee4; border-radius: 8px; background: #fbfdff; padding: 16px; margin: 16px 0 24px; }
    .radar-visual { display: grid; grid-template-columns: 240px 1fr; gap: 14px; align-items: center; }
    .radar-svg { width: 240px; height: 220px; background: #fff; border: 1px solid #d8dee4; border-radius: 8px; }
    .radar-svg text { font-size: 11px; font-weight: 700; fill: #17202a; text-anchor: middle; dominant-baseline: middle; }
    .radar-svg .ring { fill: none; stroke: #d8dee4; stroke-width: 1; }
    .radar-svg .axis { stroke: #e6edf4; stroke-width: 1; }
    .radar-svg .shape { fill: rgba(15, 118, 110, 0.18); stroke: #0f766e; stroke-width: 2; }
    .radar-svg .point { fill: #17803d; }
    .radar-svg .point.warning { fill: #bf8700; }
    .radar-svg .point.critical { fill: #cf222e; }
    .focus-card { border: 1px solid #d8dee4; border-left: 7px solid #bf8700; border-radius: 6px; background: #fff; padding: 14px; }
    .focus-card.ok { border-left-color: #17803d; }
    .focus-card.warning { border-left-color: #bf8700; }
    .focus-card.critical { border-left-color: #cf222e; }
    .focus-card strong { display: block; font-size: 22px; margin: 4px 0 6px; }
    .focus-card span { color: #52616b; font-size: 12px; text-transform: uppercase; font-weight: 700; }
    .radar-bars { display: grid; gap: 10px; }
    .radar-row { display: grid; grid-template-columns: 120px 1fr 54px; align-items: center; gap: 10px; font-size: 13px; }
    .bar-track { height: 12px; background: #e6edf4; border-radius: 999px; overflow: hidden; }
    .bar-fill { height: 100%; background: #17803d; border-radius: 999px; }
    .bar-fill.warning { background: #bf8700; }
    .bar-fill.critical { background: #cf222e; }
    .life-grid { display: grid; grid-template-columns: repeat(5, minmax(95px, 1fr)); gap: 10px; margin: 14px 0; }
    .life-card { border: 1px solid #d8dee4; border-left: 6px solid #0969da; border-radius: 6px; background: #fbfdff; padding: 10px; }
    .life-card.ok { border-left-color: #17803d; }
    .life-card.warning { border-left-color: #bf8700; }
    .life-card.critical { border-left-color: #cf222e; }
    .life-card.muted { border-left-color: #6b7280; }
    .life-card span { color: #52616b; font-size: 12px; }
    .life-card strong { display: block; font-size: 22px; margin-top: 4px; }
    .life-bar { height: 14px; display: flex; border-radius: 999px; overflow: hidden; background: #e6edf4; margin: 10px 0 8px; }
    .life-active { background: #cf222e; }
    .life-closed { background: #17803d; }
    .life-hidden { background: #6b7280; }
    .life-ack { background: #bf8700; }
    .load-grid { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin: 16px 0; }
    .load-card { border: 1px solid #d8dee4; border-left: 6px solid #0969da; padding: 12px; border-radius: 6px; background: #fbfdff; }
    .load-card.ok { border-left-color: #17803d; }
    .load-card.warning { border-left-color: #bf8700; }
    .load-card strong { display: block; font-size: 20px; margin-top: 4px; }
    .load-card span { color: #52616b; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 14px; }
    th, td { border: 1px solid #d8dee4; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f6f8fa; }
    .verdict { border: 1px solid #d8dee4; border-left: 5px solid #57606a; padding: 12px; margin: 10px 0; border-radius: 4px; }
    .warning { border-left-color: #bf8700; }
    .critical { border-left-color: #cf222e; }
    .info { border-left-color: #0969da; }
    @media (max-width: 800px) { .scores { grid-template-columns: repeat(2, minmax(100px, 1fr)); } .radar, .radar-visual { grid-template-columns: 1fr; } .load-grid, .life-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>
  <div class="meta">
    Site: {{.Site.Name}} ({{.Site.ID}}), {{.Site.Location}}<br>
    Period: {{ts .PeriodStart}} to {{ts .PeriodEnd}}<br>
    Generated: {{ts .GeneratedAt}}
  </div>

  <h2>Executive Summary</h2>
  <div class="scores">
    <div class="score"><span>Overall</span><strong>{{.Health.OverallHealthScore}}</strong></div>
    <div class="score"><span>WAN</span><strong>{{.Health.WANScore}}</strong></div>
    <div class="score"><span>DNS</span><strong>{{.Health.DNSScore}}</strong></div>
    <div class="score"><span>Gateway/LAN</span><strong>{{.Health.GatewayLANScore}}</strong></div>
    <div class="score"><span>Services</span><strong>{{.Health.ServiceAvailability}}</strong></div>
    <div class="score"><span>Inventory</span><strong>{{.Health.DeviceInventoryScore}}</strong></div>
  </div>

  <h2>Problem Radar</h2>
  <div class="radar">
    <div class="radar-visual">
      <svg class="radar-svg" viewBox="0 0 230 210" role="img" aria-label="Problem radar">
        <polygon class="ring" points="{{radarRing 25 5}}"></polygon>
        <polygon class="ring" points="{{radarRing 50 5}}"></polygon>
        <polygon class="ring" points="{{radarRing 75 5}}"></polygon>
        <polygon class="ring" points="{{radarRing 100 5}}"></polygon>
        {{range $i, $d := .RadarDomains}}
        <line class="axis" x1="115" y1="105" x2="{{radarAxisX $i 5}}" y2="{{radarAxisY $i 5}}"></line>
        <text x="{{radarLabelX $i 5}}" y="{{radarLabelY $i 5}}">{{$d.Short}}</text>
        {{end}}
        <polygon class="shape" points="{{radarPoints .RadarDomains}}"></polygon>
        {{range $i, $d := .RadarDomains}}
        <circle class="point {{scoreStatus $d.Score}}" cx="{{radarPointX $i $.RadarDomains}}" cy="{{radarPointY $i $.RadarDomains}}" r="4"></circle>
        {{end}}
      </svg>
      <div class="focus-card {{.PrimaryDomain.Status}}">
        <span>Primary focus</span>
        <strong>{{.PrimaryDomain.Name}} - {{.PrimaryDomain.Score}}/100</strong>
        <div>{{.PrimaryDomain.Action}}</div>
        <p class="meta" style="margin: 10px 0 0;">{{.PrimaryDomain.Why}}</p>
      </div>
    </div>
    <div class="radar-bars">
      {{range .RadarDomains}}
      <div class="radar-row">
        <strong>{{.Name}}</strong>
        <div class="bar-track"><div class="bar-fill {{scoreStatus .Score}}" style="width: {{.Score}}%;"></div></div>
        <span>{{.Score}}/100</span>
      </div>
      {{end}}
    </div>
  </div>

  <h2>Alert Lifecycle</h2>
  <div class="life-grid">
    <div class="life-card"><span>Total</span><strong>{{.AlertLife.Total}}</strong></div>
    <div class="life-card {{.AlertLife.Status}}"><span>Active</span><strong>{{.AlertLife.Active}}</strong></div>
    <div class="life-card warning"><span>Acknowledged</span><strong>{{.AlertLife.Acknowledged}}</strong></div>
    <div class="life-card ok"><span>Closed</span><strong>{{.AlertLife.Closed}}</strong></div>
    <div class="life-card muted"><span>Hidden</span><strong>{{.AlertLife.Hidden}}</strong></div>
  </div>
  <div class="life-bar" aria-label="Alert lifecycle">
    <span class="life-active" style="width: {{alertLifePercent .AlertLife.BarActive .AlertLife.Total}};"></span>
    <span class="life-ack" style="width: {{alertLifePercent .AlertLife.BarAck .AlertLife.Total}};"></span>
    <span class="life-closed" style="width: {{alertLifePercent .AlertLife.BarClosed .AlertLife.Total}};"></span>
    <span class="life-hidden" style="width: {{alertLifePercent .AlertLife.BarHidden .AlertLife.Total}};"></span>
  </div>
  <p class="meta">Lifecycle bar: red active, amber acknowledged, green closed, grey hidden. Segments are exclusive; cards above also show operational counters.</p>

  <h2>Appliance Network Load</h2>
  <p><strong class="{{.NetworkLoad.BackgroundVerdictCSS}}">{{.NetworkLoad.BackgroundVerdict}}</strong>. Constant monitoring is small; discovery creates local LAN bursts; WAN speed tests are the main scheduled bandwidth consumer.</p>
  <div class="load-grid">
    <div class="load-card ok"><span>Constant checks</span><strong>{{printf "%.0f" .NetworkLoad.SteadyKBPerHour}} KB/h</strong><span>{{.NetworkLoad.PingTargets}} ping targets, {{.NetworkLoad.DNSLookups}} DNS lookups, {{.NetworkLoad.HTTPTargets}} HTTP targets</span></div>
    <div class="load-card {{.NetworkLoad.BackgroundVerdictCSS}}"><span>Discovery burst</span><strong>{{.NetworkLoad.DiscoveryHosts}} hosts</strong><span>every {{.NetworkLoad.DiscoveryInterval}}</span></div>
    <div class="load-card"><span>WAN speed test</span><strong>{{printf "%.1f" .NetworkLoad.SpeedtestMBPerRun}} MB/run</strong><span>every {{.NetworkLoad.SpeedtestInterval}}</span></div>
    <div class="load-card {{.NetworkLoad.BackgroundVerdictCSS}}"><span>Estimated average</span><strong>{{printf "%.2f" .NetworkLoad.TotalMBPerHour}} MB/h</strong><span>checks + discovery + scheduled speedtest</span></div>
  </div>

  <h2>Verdicts and Recommendations</h2>
  {{range .Health.Verdicts}}
  <div class="verdict {{.Severity}}">
    <strong>{{.Title}}</strong> ({{.Severity}}, {{.Category}})<br>
    {{.Summary}}
    <ul>{{range .Evidence}}<li>{{.}}</li>{{end}}</ul>
    <em>{{.Recommendation}}</em>
  </div>
  {{end}}

  <h2>Ping Summary</h2>
  <table><tr><th>Target</th><th>Host</th><th>Type</th><th>Up</th><th>Latency ms</th><th>Loss %</th><th>Jitter ms</th><th>Time</th></tr>
  {{range .Ping}}<tr><td>{{.TargetName}}</td><td>{{.TargetHost}}</td><td>{{.TargetType}}</td><td>{{.Up}}</td><td>{{printf "%.2f" .LatencyMS}}</td><td>{{printf "%.2f" .LossPercent}}</td><td>{{printf "%.2f" .JitterMS}}</td><td>{{ts .Timestamp}}</td></tr>{{end}}
  </table>

  <h2>DNS Summary</h2>
  <table><tr><th>Resolver</th><th>Domain</th><th>Record</th><th>Success</th><th>Duration ms</th><th>Answers</th><th>Time</th></tr>
  {{range .DNS}}<tr><td>{{.ResolverName}} {{.ResolverAddress}}</td><td>{{.Domain}}</td><td>{{.RecordType}}</td><td>{{.Success}}</td><td>{{printf "%.2f" .DurationMS}}</td><td>{{.AnswerCount}}</td><td>{{ts .Timestamp}}</td></tr>{{end}}
  </table>

  <h2>HTTP/TLS Summary</h2>
  <table><tr><th>Name</th><th>URL</th><th>Up</th><th>Status</th><th>Duration ms</th><th>TLS valid</th><th>TLS days left</th><th>Time</th></tr>
  {{range .HTTP}}<tr><td>{{.Name}}</td><td>{{.URL}}</td><td>{{.Up}}</td><td>{{.StatusCode}}</td><td>{{printf "%.2f" .DurationMS}}</td><td>{{.TLSValid}}</td><td>{{.TLSDaysUntilExpiry}}</td><td>{{ts .Timestamp}}</td></tr>{{end}}
  </table>

  <h2>WAN Speed Summary</h2>
  <table><tr><th>Target</th><th>Success</th><th>Download Mbps</th><th>Upload Mbps</th><th>Download bytes</th><th>Upload bytes</th><th>Time</th></tr>
  {{range .Speedtest}}<tr><td>{{.TargetName}}</td><td>{{.Success}}</td><td>{{printf "%.2f" .DownloadMbps}}</td><td>{{printf "%.2f" .UploadMbps}}</td><td>{{.DownloadBytes}}</td><td>{{.UploadBytes}}</td><td>{{ts .Timestamp}}</td></tr>{{end}}
  </table>

  <h2>LAN Inventory</h2>
  <p>Known devices: {{len .Devices}}. Unreviewed new devices: {{len .NewDevices}}. Missing in last 24h: {{len .MissingDevices}}.</p>
  <table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Source</th><th>First seen</th><th>Last seen</th></tr>
  {{range .Devices}}<tr><td>{{.IP}}</td><td>{{.MAC}}</td><td>{{.Vendor}}</td><td>{{.Hostname}}</td><td>{{.Source}}</td><td>{{ts .FirstSeen}}</td><td>{{ts .LastSeen}}</td></tr>{{end}}
  </table>
</body>
</html>`))
