package agent

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type dnsDiagnosticRow struct {
	ResolverName    string    `json:"resolver_name"`
	ResolverAddress string    `json:"resolver_address"`
	Domain          string    `json:"domain"`
	RecordType      string    `json:"record_type"`
	LatestSuccess   bool      `json:"latest_success"`
	LatestDuration  float64   `json:"latest_duration_ms"`
	LatestError     string    `json:"latest_error,omitempty"`
	LastSeen        time.Time `json:"last_seen"`
	Samples         int       `json:"samples"`
	SuccessRatio    float64   `json:"success_ratio"`
	MinDuration     float64   `json:"min_duration_ms"`
	AvgDuration     float64   `json:"avg_duration_ms"`
	MaxDuration     float64   `json:"max_duration_ms"`
}

type traceHop struct {
	Hop     int    `json:"hop"`
	Host    string `json:"host"`
	Address string `json:"address"`
	Raw     string `json:"raw"`
}

type traceDiagnostic struct {
	TargetName string     `json:"target_name"`
	Target     string     `json:"target"`
	Success    bool       `json:"success"`
	Severity   string     `json:"severity"`
	Summary    string     `json:"summary"`
	Error      string     `json:"error,omitempty"`
	Timestamp  time.Time  `json:"timestamp"`
	Hops       []traceHop `json:"hops"`
	Raw        string     `json:"raw,omitempty"`
}

type portHistoryRow struct {
	DeviceIP      string      `json:"device_ip"`
	Hostname      string      `json:"hostname,omitempty"`
	MAC           string      `json:"mac,omitempty"`
	Vendor        string      `json:"vendor,omitempty"`
	LatestPorts   []int       `json:"latest_ports"`
	PreviousPorts []int       `json:"previous_ports,omitempty"`
	OpenedPorts   []int       `json:"opened_ports,omitempty"`
	ClosedPorts   []int       `json:"closed_ports,omitempty"`
	LatestAt      time.Time   `json:"latest_at"`
	History       []portPoint `json:"history"`
}

type portPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Ports     []int     `json:"ports"`
}

func (a *Agent) dnsDiagnostics(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.RecentDNS(1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	grouped := map[string][]storage.DNSResult{}
	for _, row := range rows {
		key := strings.Join([]string{row.ResolverName, row.ResolverAddress, row.Domain, row.RecordType}, "|")
		grouped[key] = append(grouped[key], row)
	}
	out := make([]dnsDiagnosticRow, 0, len(grouped))
	for _, items := range grouped {
		sort.Slice(items, func(i, j int) bool { return items[i].Timestamp.After(items[j].Timestamp) })
		latest := items[0]
		var ok, count int
		var min, max, total float64
		for i, item := range items {
			if item.Success {
				ok++
			}
			if item.DurationMS > 0 {
				if count == 0 || item.DurationMS < min {
					min = item.DurationMS
				}
				if i == 0 || item.DurationMS > max {
					max = item.DurationMS
				}
				total += item.DurationMS
				count++
			}
		}
		avg := 0.0
		if count > 0 {
			avg = total / float64(count)
		}
		out = append(out, dnsDiagnosticRow{
			ResolverName:    latest.ResolverName,
			ResolverAddress: latest.ResolverAddress,
			Domain:          latest.Domain,
			RecordType:      latest.RecordType,
			LatestSuccess:   latest.Success,
			LatestDuration:  latest.DurationMS,
			LatestError:     latest.Error,
			LastSeen:        latest.Timestamp,
			Samples:         len(items),
			SuccessRatio:    float64(ok) / float64(len(items)),
			MinDuration:     min,
			AvgDuration:     avg,
			MaxDuration:     max,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LatestSuccess != out[j].LatestSuccess {
			return !out[i].LatestSuccess
		}
		if out[i].AvgDuration != out[j].AvgDuration {
			return out[i].AvgDuration > out[j].AvgDuration
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (a *Agent) traceDiagnostics(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.LatestAdvanced("trace", 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	latest := latestAdvancedByTarget(rows)
	out := make([]traceDiagnostic, 0, len(latest))
	for _, row := range latest {
		out = append(out, traceDiagnostic{
			TargetName: row.TargetName,
			Target:     row.Target,
			Success:    row.Success,
			Severity:   row.Severity,
			Summary:    row.Summary,
			Error:      row.Error,
			Timestamp:  row.Timestamp,
			Hops:       parseTraceHops(row.Details),
			Raw:        row.Details,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (a *Agent) portHistory(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.LatestAdvanced("port_scan", 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	devices, _ := a.db.Devices(a.cfg.Site.ID)
	devByIP := map[string]storage.Device{}
	for _, device := range devices {
		devByIP[device.IP] = device
	}
	grouped := map[string][]storage.AdvancedResult{}
	for _, row := range rows {
		grouped[row.Target] = append(grouped[row.Target], row)
	}
	out := make([]portHistoryRow, 0, len(grouped))
	for ip, items := range grouped {
		sort.Slice(items, func(i, j int) bool { return items[i].Timestamp.After(items[j].Timestamp) })
		latest := parsePortList(items[0].Details)
		previous := []int{}
		if len(items) > 1 {
			previous = parsePortList(items[1].Details)
		}
		history := make([]portPoint, 0, minInt(len(items), 12))
		for i, item := range items {
			if i >= 12 {
				break
			}
			history = append(history, portPoint{Timestamp: item.Timestamp, Ports: parsePortList(item.Details)})
		}
		device := devByIP[ip]
		out = append(out, portHistoryRow{
			DeviceIP:      ip,
			Hostname:      device.Hostname,
			MAC:           device.MAC,
			Vendor:        device.Vendor,
			LatestPorts:   latest,
			PreviousPorts: previous,
			OpenedPorts:   portDiff(latest, previous),
			ClosedPorts:   portDiff(previous, latest),
			LatestAt:      items[0].Timestamp,
			History:       history,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LatestAt.After(out[j].LatestAt) })
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (a *Agent) topology(w http.ResponseWriter, _ *http.Request) {
	devices, _ := a.db.Devices(a.cfg.Site.ID)
	ping, _ := a.db.LatestPing("", 100)
	dns, _ := a.db.RecentDNS(100)
	httpRows, _ := a.db.RecentHTTP(100)
	speed, _ := a.db.LatestSpeedtest(10)
	gateway := ""
	for _, row := range ping {
		if row.TargetType == "gateway" && row.TargetHost != "" {
			gateway = row.TargetHost
			break
		}
	}
	if gateway == "" {
		gateway = a.effectiveTargets().Gateway.Address
	}
	dnsResolvers := map[string]bool{}
	for _, row := range dns {
		label := firstNonEmpty(row.ResolverAddress, row.ResolverName)
		if label != "" {
			dnsResolvers[label] = true
		}
	}
	services := map[string]bool{}
	for _, row := range httpRows {
		label := firstNonEmpty(row.Name, row.URL)
		if label != "" {
			services[label] = row.Up
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"site":          a.cfg.Site,
		"gateway":       gateway,
		"devices":       devices,
		"dns_resolvers": mapKeys(dnsResolvers),
		"services":      services,
		"speed":         speed,
	})
}

func latestAdvancedByTarget(rows []storage.AdvancedResult) []storage.AdvancedResult {
	seen := map[string]storage.AdvancedResult{}
	for _, row := range rows {
		key := row.TargetName + "|" + row.Target
		if existing, ok := seen[key]; !ok || row.Timestamp.After(existing.Timestamp) {
			seen[key] = row
		}
	}
	out := make([]storage.AdvancedResult, 0, len(seen))
	for _, row := range seen {
		out = append(out, row)
	}
	return out
}

var traceHopRE = regexp.MustCompile(`^\s*(\d+)[\s:]+(.+)$`)
var traceIPRE = regexp.MustCompile(`\(?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?`)

func parseTraceHops(raw string) []traceHop {
	out := []traceHop{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		match := traceHopRE.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		hop, _ := strconv.Atoi(match[1])
		body := strings.TrimSpace(match[2])
		ip := ""
		if ipMatch := traceIPRE.FindStringSubmatch(body); len(ipMatch) == 2 && net.ParseIP(ipMatch[1]) != nil {
			ip = ipMatch[1]
		}
		host := strings.Fields(body)
		hostName := ""
		if len(host) > 0 {
			hostName = strings.Trim(host[0], "()")
		}
		out = append(out, traceHop{Hop: hop, Host: hostName, Address: ip, Raw: line})
	}
	return out
}

func parsePortList(raw string) []int {
	ports := []int{}
	if err := json.Unmarshal([]byte(raw), &ports); err != nil {
		return []int{}
	}
	if ports == nil {
		return []int{}
	}
	sort.Ints(ports)
	return ports
}

func portDiff(a, b []int) []int {
	lookup := map[int]bool{}
	for _, port := range b {
		lookup[port] = true
	}
	var out []int
	for _, port := range a {
		if !lookup[port] {
			out = append(out, port)
		}
	}
	return out
}

func mapKeys(input map[string]bool) []string {
	out := make([]string, 0, len(input))
	for key := range input {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
