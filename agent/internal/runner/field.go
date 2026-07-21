package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type PathRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Samples     int    `json:"samples"`
	MaxHops     int    `json:"max_hops"`
	DSCP        int    `json:"dscp"`
	DiscoverMTU bool   `json:"discover_mtu"`
}

type PathHop struct {
	Number    int       `json:"number"`
	Addresses []string  `json:"addresses"`
	RTTMS     []float64 `json:"rtt_ms"`
	Timeouts  int       `json:"timeouts"`
}

type PathDetails struct {
	Protocol string    `json:"protocol"`
	Port     int       `json:"port,omitempty"`
	DSCP     int       `json:"dscp,omitempty"`
	Samples  int       `json:"samples"`
	Hops     []PathHop `json:"hops"`
	PathHash string    `json:"path_hash"`
	MTURaw   string    `json:"mtu_raw,omitempty"`
	Raw      []string  `json:"raw"`
}

var traceRTTRE = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*ms`)
var traceIPRE = regexp.MustCompile(`(?:^|\s)([0-9a-fA-F:.]+)(?:\s|$)`)

func (r AdvancedRunner) ProgressivePath(ctx context.Context, siteID string, request PathRequest) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "progressive_path", request.Name, request.Host)
	if result.TargetName == "" {
		result.TargetName = request.Host
	}
	if net.ParseIP(request.Host) == nil {
		if _, err := net.LookupHost(request.Host); err != nil {
			result.Severity = "warning"
			result.Summary = "Path target could not be resolved"
			result.Error = err.Error()
			return result
		}
	}
	request.Protocol = strings.ToLower(strings.TrimSpace(request.Protocol))
	if request.Protocol == "" {
		request.Protocol = "icmp"
	}
	if request.Samples < 1 {
		request.Samples = 3
	}
	if request.Samples > 10 {
		request.Samples = 10
	}
	if request.MaxHops < 1 {
		request.MaxHops = 16
	}
	if request.MaxHops > 64 {
		request.MaxHops = 64
	}
	tool, err := exec.LookPath("traceroute")
	if err != nil {
		result.Severity = "warning"
		result.Summary = "Traceroute tool not installed"
		result.Error = err.Error()
		return result
	}
	details := PathDetails{Protocol: request.Protocol, Port: request.Port, DSCP: request.DSCP, Samples: request.Samples}
	combined := map[int]*PathHop{}
	for sample := 0; sample < request.Samples; sample++ {
		args := []string{"-n", "-m", strconv.Itoa(request.MaxHops), "-q", "1", "-w", "1"}
		switch request.Protocol {
		case "tcp":
			args = append(args, "-T")
			if request.Port > 0 {
				args = append(args, "-p", strconv.Itoa(request.Port))
			}
		case "udp":
			args = append(args, "-U")
			if request.Port > 0 {
				args = append(args, "-p", strconv.Itoa(request.Port))
			}
		default:
			args = append(args, "-I")
		}
		if request.DSCP > 0 && request.DSCP <= 63 {
			args = append(args, "-t", strconv.Itoa(request.DSCP<<2))
		}
		args = append(args, request.Host)
		out, runErr := exec.CommandContext(ctx, tool, args...).CombinedOutput()
		raw := strings.TrimSpace(string(out))
		details.Raw = append(details.Raw, raw)
		if runErr != nil && ctx.Err() != nil {
			result.Error = ctx.Err().Error()
			break
		}
		mergeTraceOutput(combined, raw)
	}
	keys := make([]int, 0, len(combined))
	for key := range combined {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	pathParts := []string{}
	for _, key := range keys {
		hop := combined[key]
		sort.Strings(hop.Addresses)
		details.Hops = append(details.Hops, *hop)
		pathParts = append(pathParts, strings.Join(hop.Addresses, ","))
	}
	hash := sha256.Sum256([]byte(strings.Join(pathParts, "|")))
	details.PathHash = hex.EncodeToString(hash[:8])
	if request.DiscoverMTU {
		if pathTool, err := exec.LookPath("tracepath"); err == nil {
			out, _ := exec.CommandContext(ctx, pathTool, "-n", "-m", strconv.Itoa(request.MaxHops), request.Host).CombinedOutput()
			details.MTURaw = strings.TrimSpace(string(out))
		}
	}
	raw, _ := json.Marshal(details)
	result.Details = string(raw)
	result.DurationMS = msSince(start)
	result.Success = len(details.Hops) > 0
	result.Summary = fmt.Sprintf("%s path: %d hop(s), %d sample(s), hash %s", strings.ToUpper(request.Protocol), len(details.Hops), request.Samples, details.PathHash)
	if !result.Success {
		result.Severity = "warning"
		result.Summary = "Path analysis returned no hops"
		if result.Error == "" {
			result.Error = "no traceroute hops returned"
		}
	}
	return result
}

func mergeTraceOutput(combined map[int]*PathHop, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		number, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		hop := combined[number]
		if hop == nil {
			hop = &PathHop{Number: number}
			combined[number] = hop
		}
		if strings.Contains(line, "*") {
			hop.Timeouts++
		}
		for _, match := range traceRTTRE.FindAllStringSubmatch(line, -1) {
			value, _ := strconv.ParseFloat(match[1], 64)
			hop.RTTMS = append(hop.RTTMS, value)
		}
		for _, match := range traceIPRE.FindAllStringSubmatch(line, -1) {
			value := strings.Trim(match[1], "() ")
			if net.ParseIP(value) != nil && !containsText(hop.Addresses, value) {
				hop.Addresses = append(hop.Addresses, value)
			}
		}
	}
}

type DHCPIntegrityDetails struct {
	Servers    []string `json:"servers"`
	Routers    []string `json:"routers"`
	DNSServers []string `json:"dns_servers"`
	Raw        string   `json:"raw"`
}

func (r AdvancedRunner) DHCPIntegrity(ctx context.Context, siteID, expectedServer string) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "dhcp_integrity", "DHCP integrity", "local broadcast")
	tool, err := exec.LookPath("nmap")
	if err != nil {
		result.Severity = "warning"
		result.Summary = "Nmap not installed"
		result.Error = err.Error()
		return result
	}
	out, runErr := exec.CommandContext(ctx, tool, "--script", "broadcast-dhcp-discover", "-e", defaultInterface()).CombinedOutput()
	raw := string(out)
	details := DHCPIntegrityDetails{Servers: extractDHCPValues(raw, "Server Identifier"), Routers: extractDHCPValues(raw, "Router"), DNSServers: extractDHCPValues(raw, "Domain Name Server"), Raw: strings.TrimSpace(raw)}
	encoded, _ := json.Marshal(details)
	result.Details = string(encoded)
	result.DurationMS = msSince(start)
	result.Success = runErr == nil && len(details.Servers) > 0
	result.Summary = fmt.Sprintf("DHCP offers from %d server(s)", len(details.Servers))
	if runErr != nil {
		result.Severity = "warning"
		result.Error = runErr.Error()
		result.Summary = "DHCP discovery failed"
	} else if len(details.Servers) > 1 {
		result.Success = false
		result.Severity = "warning"
		result.Error = "multiple DHCP servers responded"
	} else if expectedServer != "" && len(details.Servers) > 0 && details.Servers[0] != expectedServer {
		result.Success = false
		result.Severity = "warning"
		result.Error = "unexpected DHCP server " + details.Servers[0]
	}
	return result
}

func extractDHCPValues(raw, label string) []string {
	out := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, label) {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		for _, value := range strings.Fields(strings.ReplaceAll(parts[1], ",", " ")) {
			value = strings.Trim(value, "() ")
			if net.ParseIP(value) != nil && !containsText(out, value) {
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}

type DNSIntegrityDetails struct {
	Domain     string              `json:"domain"`
	Answers    map[string][]string `json:"answers"`
	Consistent bool                `json:"consistent"`
}

func (r AdvancedRunner) DNSIntegrity(ctx context.Context, siteID, domain string, resolvers map[string]string) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "dns_integrity", "DNS integrity", domain)
	if domain == "" {
		domain = "example.com"
		result.Target = domain
	}
	details := DNSIntegrityDetails{Domain: domain, Answers: map[string][]string{}, Consistent: true}
	canonical := ""
	for name, address := range resolvers {
		resolver := net.DefaultResolver
		if address != "" && address != "auto" {
			resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(address, "53"))
			}}
		}
		answers, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			details.Answers[name] = []string{"error: " + err.Error()}
			details.Consistent = false
			continue
		}
		sort.Strings(answers)
		details.Answers[name] = answers
		joined := strings.Join(answers, ",")
		if canonical == "" {
			canonical = joined
		} else if joined != canonical {
			details.Consistent = false
		}
	}
	raw, _ := json.Marshal(details)
	result.Details = string(raw)
	result.DurationMS = msSince(start)
	result.Success = details.Consistent && len(details.Answers) > 0
	result.Summary = fmt.Sprintf("Compared %d DNS resolver(s): consistent=%t", len(details.Answers), details.Consistent)
	if !result.Success {
		result.Severity = "warning"
		result.Error = "DNS answers differ or a resolver failed"
	}
	return result
}

type LLDPNeighbor struct {
	Host       string `json:"host"`
	LocalIndex string `json:"local_index"`
	RemoteName string `json:"remote_name"`
	RemotePort string `json:"remote_port"`
}

type SwitchPortLocation struct {
	MAC        string `json:"mac"`
	VLAN       string `json:"vlan,omitempty"`
	BridgePort string `json:"bridge_port"`
	IfIndex    string `json:"if_index,omitempty"`
	IfName     string `json:"if_name,omitempty"`
}

const lldpRemoteNameOID = ".1.0.8802.1.1.2.1.4.1.1.9"
const lldpRemotePortOID = ".1.0.8802.1.1.2.1.4.1.1.8"
const qBridgeFDBPortOID = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
const bridgePortIfIndexOID = ".1.3.6.1.2.1.17.1.4.1.2"
const ifNameOID = ".1.3.6.1.2.1.31.1.1.1.1"

func (r AdvancedRunner) SNMPTopology(ctx context.Context, siteID, host, community string) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "snmp_topology", host, host)
	if community == "" {
		result.Severity = "warning"
		result.Summary = "SNMP community not configured"
		result.Error = "community is required"
		return result
	}
	tool, err := exec.LookPath("snmpwalk")
	if err != nil {
		result.Severity = "warning"
		result.Summary = "snmpwalk not installed"
		result.Error = err.Error()
		return result
	}
	namesRaw, namesErr := exec.CommandContext(ctx, tool, "-v2c", "-c", community, "-t", "1", "-r", "0", "-On", host, strings.TrimPrefix(lldpRemoteNameOID, ".")).CombinedOutput()
	portsRaw, _ := exec.CommandContext(ctx, tool, "-v2c", "-c", community, "-t", "1", "-r", "0", "-On", host, strings.TrimPrefix(lldpRemotePortOID, ".")).CombinedOutput()
	fdbRaw, _ := exec.CommandContext(ctx, tool, "-v2c", "-c", community, "-t", "1", "-r", "0", "-On", host, strings.TrimPrefix(qBridgeFDBPortOID, ".")).CombinedOutput()
	bridgeRaw, _ := exec.CommandContext(ctx, tool, "-v2c", "-c", community, "-t", "1", "-r", "0", "-On", host, strings.TrimPrefix(bridgePortIfIndexOID, ".")).CombinedOutput()
	ifNamesRaw, _ := exec.CommandContext(ctx, tool, "-v2c", "-c", community, "-t", "1", "-r", "0", "-On", host, strings.TrimPrefix(ifNameOID, ".")).CombinedOutput()
	names := parseSNMPTable(string(namesRaw), lldpRemoteNameOID)
	ports := parseSNMPTable(string(portsRaw), lldpRemotePortOID)
	neighbors := []LLDPNeighbor{}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.Split(key, ".")
		local := key
		if len(parts) >= 2 {
			local = parts[len(parts)-2]
		}
		neighbors = append(neighbors, LLDPNeighbor{Host: host, LocalIndex: local, RemoteName: names[key], RemotePort: ports[key]})
	}
	fdb := parseSNMPTable(string(fdbRaw), qBridgeFDBPortOID)
	bridgePorts := parseSNMPTable(string(bridgeRaw), bridgePortIfIndexOID)
	ifNames := parseSNMPTable(string(ifNamesRaw), ifNameOID)
	locations := buildSwitchPortLocations(fdb, bridgePorts, ifNames)
	raw, _ := json.Marshal(map[string]any{"host": host, "neighbors": neighbors, "mac_table": locations})
	result.Details = string(raw)
	result.DurationMS = msSince(start)
	result.Success = namesErr == nil
	result.Summary = fmt.Sprintf("%d LLDP neighbor(s), %d learned MAC location(s) from %s", len(neighbors), len(locations), host)
	if namesErr != nil {
		result.Severity = "warning"
		result.Error = namesErr.Error()
		result.Summary = "SNMP/LLDP query failed"
	}
	return result
}

func buildSwitchPortLocations(fdb, bridgePorts, ifNames map[string]string) []SwitchPortLocation {
	locations := []SwitchPortLocation{}
	for key, port := range fdb {
		parts := strings.Split(key, ".")
		if len(parts) < 7 {
			continue
		}
		macParts := parts[len(parts)-6:]
		mac := make([]string, 0, 6)
		valid := true
		for _, part := range macParts {
			value, err := strconv.Atoi(part)
			if err != nil || value < 0 || value > 255 {
				valid = false
				break
			}
			mac = append(mac, fmt.Sprintf("%02x", value))
		}
		if !valid {
			continue
		}
		vlan := strings.Join(parts[:len(parts)-6], ".")
		port = firstNumber(port)
		ifIndex := firstNumber(bridgePorts[port])
		locations = append(locations, SwitchPortLocation{MAC: strings.Join(mac, ":"), VLAN: vlan, BridgePort: port, IfIndex: ifIndex, IfName: ifNames[ifIndex]})
	}
	sort.Slice(locations, func(i, j int) bool { return locations[i].MAC < locations[j].MAC })
	return locations
}

func firstNumber(value string) string {
	for _, field := range strings.Fields(value) {
		if _, err := strconv.Atoi(field); err == nil {
			return field
		}
	}
	return strings.TrimSpace(value)
}

func parseSNMPTable(raw, baseOID string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, baseOID+".") {
			continue
		}
		parts := strings.SplitN(line, " = ", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimPrefix(parts[0], baseOID+".")
		value := parts[1]
		if colon := strings.Index(value, ":"); colon >= 0 {
			value = value[colon+1:]
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		if value != "" && !strings.HasPrefix(value, "No Such") {
			out[key] = value
		}
	}
	return out
}
func containsText(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
func defaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1]
		}
	}
	return "eth0"
}
