package runner

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

type IdentityTarget struct {
	IP  string
	MAC string
}

type IdentitySource struct {
	Source   string `json:"source"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type IdentityResult struct {
	IP       string           `json:"ip"`
	MAC      string           `json:"mac,omitempty"`
	Hostname string           `json:"hostname,omitempty"`
	Vendor   string           `json:"vendor,omitempty"`
	Sources  []IdentitySource `json:"sources"`
}

type IdentityEnricher struct {
	DHCPLeasePaths []string
}

func (e IdentityEnricher) Enrich(ctx context.Context, target IdentityTarget) IdentityResult {
	result := IdentityResult{IP: target.IP, MAC: normalizeMAC(target.MAC)}
	if net.ParseIP(target.IP) == nil {
		result.Sources = append(result.Sources, IdentitySource{Source: "input", Status: "skipped", Error: "invalid IP"})
		return result
	}
	for _, source := range []IdentitySource{
		e.fromDHCPLeases(target),
		fromMDNS(ctx, target.IP),
		fromNetBIOS(ctx, target.IP),
		fromSNMP(ctx, target.IP),
		fromReverseDNS(target.IP),
	} {
		result.Sources = append(result.Sources, source)
		if result.Hostname == "" && source.Hostname != "" {
			result.Hostname = source.Hostname
		}
		if result.Vendor == "" && source.Vendor != "" {
			result.Vendor = source.Vendor
		}
	}
	return result
}

func (e IdentityEnricher) fromDHCPLeases(target IdentityTarget) IdentitySource {
	paths := e.DHCPLeasePaths
	if len(paths) == 0 {
		paths = []string{
			"/var/lib/infracheck/dhcp.leases",
			"/var/lib/misc/dnsmasq.leases",
			"/tmp/dhcp.leases",
			"/var/lib/dhcp/dhcpd.leases",
		}
	}
	targetMAC := normalizeMAC(target.MAC)
	for _, path := range paths {
		host, ok, err := lookupDHCPLease(path, target.IP, targetMAC)
		if err != nil {
			continue
		}
		if ok {
			return IdentitySource{Source: "dhcp-leases", Hostname: host, Status: "ok"}
		}
	}
	return IdentitySource{Source: "dhcp-leases", Status: "not_found"}
}

func lookupDHCPLease(path, ip, mac string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	text := string(data)
	if strings.Contains(text, "lease ") && strings.Contains(text, "hardware ethernet") {
		return lookupISCLease(text, ip, mac), lookupISCLease(text, ip, mac) != "", nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		rowMAC := normalizeMAC(fields[1])
		rowIP := fields[2]
		host := cleanHostname(fields[3])
		if rowIP == ip || (mac != "" && rowMAC == mac) {
			return host, true, nil
		}
	}
	return "", false, scanner.Err()
}

func lookupISCLease(text, ip, mac string) string {
	blocks := strings.Split(text, "lease ")
	for _, block := range blocks {
		if !strings.HasPrefix(block, ip+" ") && (mac == "" || !strings.Contains(strings.ToLower(block), strings.ToLower(mac))) {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "client-hostname ") {
				return cleanHostname(strings.Trim(line[len("client-hostname "):], "\"; "))
			}
		}
	}
	return ""
}

func fromReverseDNS(ip string) IdentitySource {
	host := reverseHostname(ip)
	if host == "" {
		return IdentitySource{Source: "reverse-dns", Status: "not_found"}
	}
	return IdentitySource{Source: "reverse-dns", Hostname: host, Status: "ok"}
}

func fromMDNS(parent context.Context, ip string) IdentitySource {
	ctx, cancel := context.WithTimeout(parent, 1000*time.Millisecond)
	defer cancel()
	services := []string{"_workstation._tcp", "_smb._tcp", "_ssh._tcp", "_http._tcp", "_ipp._tcp", "_airplay._tcp", "_googlecast._tcp"}
	for _, service := range services {
		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			return IdentitySource{Source: "mdns", Status: "not_available", Error: err.Error()}
		}
		entries := make(chan *zeroconf.ServiceEntry)
		serviceCtx, serviceCancel := context.WithTimeout(ctx, 140*time.Millisecond)
		err = resolver.Browse(serviceCtx, service, "local.", entries)
		if err != nil {
			serviceCancel()
			continue
		}
		for entry := range entries {
			if mdnsEntryHasIP(entry, ip) {
				serviceCancel()
				host := cleanHostname(entry.HostName)
				if host == "" {
					host = cleanHostname(entry.Instance)
				}
				return IdentitySource{Source: "mdns", Hostname: host, Status: "ok"}
			}
		}
		serviceCancel()
	}
	return IdentitySource{Source: "mdns", Status: "not_found"}
}

func mdnsEntryHasIP(entry *zeroconf.ServiceEntry, ip string) bool {
	for _, addr := range entry.AddrIPv4 {
		if addr.String() == ip {
			return true
		}
	}
	for _, addr := range entry.AddrIPv6 {
		if addr.String() == ip {
			return true
		}
	}
	return false
}

var netbiosNameRE = regexp.MustCompile(`(?m)^\s*([^\s<][^<]{0,15})\s+<00>\s+-\s+<ACTIVE>\s*$`)

func fromNetBIOS(ctx context.Context, ip string) IdentitySource {
	if _, err := exec.LookPath("nmblookup"); err != nil {
		return IdentitySource{Source: "netbios", Status: "not_available", Error: "nmblookup not installed"}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "nmblookup", "-A", ip).CombinedOutput()
	if err != nil && len(out) == 0 {
		return IdentitySource{Source: "netbios", Status: "not_found", Error: strings.TrimSpace(string(out))}
	}
	for _, match := range netbiosNameRE.FindAllStringSubmatch(string(out), -1) {
		name := cleanHostname(match[1])
		if name != "" && !strings.EqualFold(name, "WORKGROUP") {
			return IdentitySource{Source: "netbios", Hostname: name, Status: "ok"}
		}
	}
	return IdentitySource{Source: "netbios", Status: "not_found"}
}

func fromSNMP(ctx context.Context, ip string) IdentitySource {
	if _, err := exec.LookPath("snmpget"); err != nil {
		return IdentitySource{Source: "snmp", Status: "not_available", Error: "snmpget not installed"}
	}
	for _, community := range []string{"public"} {
		cmdCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
		out, err := exec.CommandContext(cmdCtx, "snmpget", "-v2c", "-c", community, "-t", "1", "-r", "0", ip, "1.3.6.1.2.1.1.5.0").CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		host := parseSNMPString(string(out))
		if host != "" {
			return IdentitySource{Source: "snmp", Hostname: host, Status: "ok"}
		}
	}
	return IdentitySource{Source: "snmp", Status: "not_found"}
}

func parseSNMPString(out string) string {
	if i := strings.Index(out, "STRING:"); i >= 0 {
		return cleanHostname(strings.TrimSpace(out[i+len("STRING:"):]))
	}
	return ""
}

func cleanHostname(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"' ;")
	value = strings.TrimSuffix(value, ".local")
	value = strings.TrimSuffix(value, ".")
	if value == "*" || value == "-" || value == "<unknown>" {
		return ""
	}
	return value
}
