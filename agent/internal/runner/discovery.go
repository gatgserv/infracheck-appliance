package runner

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type DiscoveryRunner struct {
	CIDRs []string
}

func (r DiscoveryRunner) Run(ctx context.Context, siteID string) []storage.Device {
	now := time.Now().UTC()
	seen := map[string]storage.Device{}
	for _, device := range runIPNeigh(ctx, siteID, now) {
		mergeDevice(seen, device)
	}
	for _, device := range runARP(ctx, siteID, now) {
		mergeDevice(seen, device)
	}
	for _, device := range r.runARPScan(ctx, siteID, now) {
		mergeDevice(seen, device)
	}
	for _, device := range r.runNmapPingSweep(ctx, siteID, now) {
		mergeDevice(seen, device)
	}
	devices := make([]storage.Device, 0, len(seen))
	for _, device := range seen {
		if device.Hostname == "" {
			device.Hostname = reverseHostname(device.IP)
		}
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].IP < devices[j].IP })
	return devices
}

func runIPNeigh(ctx context.Context, siteID string, now time.Time) []storage.Device {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, "ip", "neigh", "show").Output()
	if err != nil {
		return nil
	}
	var devices []storage.Device
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		mac := ""
		for i, field := range fields {
			if field == "lladdr" && i+1 < len(fields) {
				mac = normalizeMAC(fields[i+1])
			}
		}
		if mac == "" {
			continue
		}
		devices = append(devices, storage.Device{
			SiteID:    siteID,
			IP:        ip,
			MAC:       mac,
			Source:    "arp",
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return devices
}

var arpLineRE = regexp.MustCompile(`\(([^)]+)\)\s+at\s+([0-9a-fA-F:.-]+)`)

func runARP(ctx context.Context, siteID string, now time.Time) []storage.Device {
	if _, err := exec.LookPath("arp"); err != nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, "arp", "-an").Output()
	if err != nil {
		return nil
	}
	var devices []storage.Device
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		match := arpLineRE.FindStringSubmatch(scanner.Text())
		if len(match) != 3 || net.ParseIP(match[1]) == nil {
			continue
		}
		mac := normalizeMAC(match[2])
		if mac == "" || mac == "<incomplete>" {
			continue
		}
		devices = append(devices, storage.Device{
			SiteID:    siteID,
			IP:        match[1],
			MAC:       mac,
			Source:    "arp",
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return devices
}

func (r DiscoveryRunner) runARPScan(ctx context.Context, siteID string, now time.Time) []storage.Device {
	if _, err := exec.LookPath("arp-scan"); err != nil {
		return nil
	}
	cidrs := r.cidrs()
	if len(cidrs) == 0 {
		return nil
	}
	var devices []storage.Device
	for _, cidr := range cidrs {
		out, err := exec.CommandContext(ctx, "arp-scan", cidr, "--retry=1", "--timeout=500").Output()
		if err != nil && ctx.Err() != nil {
			return devices
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
				continue
			}
			mac := normalizeMAC(fields[1])
			if mac == "" {
				continue
			}
			vendor := ""
			if len(fields) > 2 {
				vendor = strings.Join(fields[2:], " ")
			}
			devices = append(devices, storage.Device{
				SiteID:    siteID,
				IP:        fields[0],
				MAC:       mac,
				Vendor:    vendor,
				Source:    "arp-scan",
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}
	return devices
}

var nmapReportRE = regexp.MustCompile(`^Nmap scan report for (?:(.*?)\s+\()?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?$`)

func (r DiscoveryRunner) runNmapPingSweep(ctx context.Context, siteID string, now time.Time) []storage.Device {
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil
	}
	cidrs := r.cidrs()
	if len(cidrs) == 0 {
		return nil
	}
	var devices []storage.Device
	for _, cidr := range cidrs {
		out, err := exec.CommandContext(ctx, "nmap", "-sn", cidr).CombinedOutput()
		if err != nil && ctx.Err() != nil {
			return devices
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			match := nmapReportRE.FindStringSubmatch(scanner.Text())
			if len(match) != 3 || net.ParseIP(match[2]) == nil {
				continue
			}
			hostname := strings.TrimSpace(match[1])
			if hostname == match[2] {
				hostname = ""
			}
			devices = append(devices, storage.Device{
				SiteID:    siteID,
				IP:        match[2],
				Hostname:  hostname,
				Source:    "nmap-ping",
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}
	return devices
}

func (r DiscoveryRunner) cidrs() []string {
	return discoveryCIDRs(r.CIDRs)
}

func discoveryCIDRs(configured []string) []string {
	if len(configured) > 0 {
		out := append([]string(nil), configured...)
		sort.Strings(out)
		return out
	}
	return localIPv4CIDRs()
}

func reverseHostname(ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
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

func localIPv4CIDRs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	cidrs := map[string]struct{}{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, network, ok := parseIPv4Network(addr)
			if !ok || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isDockerBridgeIPv4(ip) {
				continue
			}
			ones, bits := network.Mask.Size()
			if bits != 32 || ones < 24 {
				ones = 24
			}
			masked := ip.Mask(net.CIDRMask(ones, 32))
			cidrs[masked.String()+"/"+strconv.Itoa(ones)] = struct{}{}
		}
	}
	out := make([]string, 0, len(cidrs))
	for cidr := range cidrs {
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

func isDockerBridgeIPv4(ip net.IP) bool {
	return ip[0] == 172 && ip[1] >= 17 && ip[1] <= 31
}

func parseIPv4Network(addr net.Addr) (net.IP, *net.IPNet, bool) {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		return nil, nil, false
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, nil, false
	}
	return ip, ipNet, true
}

func mergeDevice(devices map[string]storage.Device, next storage.Device) {
	key := next.MAC
	if key == "" {
		key = next.IP
	}
	if next.MAC == "" {
		for existingKey, existing := range devices {
			if existing.IP == next.IP {
				devices[existingKey] = mergeDeviceFields(existing, next)
				return
			}
		}
	} else if ipOnly, ok := devices[next.IP]; ok && ipOnly.MAC == "" {
		delete(devices, next.IP)
		devices[key] = mergeDeviceFields(next, ipOnly)
		return
	}
	current, ok := devices[key]
	if !ok {
		devices[key] = next
		return
	}
	devices[key] = mergeDeviceFields(current, next)
}

func mergeDeviceFields(current, next storage.Device) storage.Device {
	if current.IP == "" {
		current.IP = next.IP
	}
	if current.MAC == "" {
		current.MAC = next.MAC
	}
	if current.Vendor == "" {
		current.Vendor = next.Vendor
	}
	if current.Hostname == "" {
		current.Hostname = next.Hostname
	}
	if current.Source != next.Source {
		current.Source = current.Source + "," + next.Source
	}
	if next.LastSeen.After(current.LastSeen) {
		current.LastSeen = next.LastSeen
	}
	return current
}

func normalizeMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" || mac == "(incomplete)" || mac == "<incomplete>" {
		return ""
	}
	return strings.ReplaceAll(mac, "-", ":")
}
