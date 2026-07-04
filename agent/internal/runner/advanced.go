package runner

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type AdvancedRunner struct{}

func (r AdvancedRunner) TCP(ctx context.Context, siteID string, target config.TCPTarget) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "tcp", target.Name, net.JoinHostPort(target.Host, fmt.Sprint(target.Port)))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", result.Target)
	result.DurationMS = msSince(start)
	if err != nil {
		result.Error = err.Error()
		result.Summary = "TCP connect failed"
		result.Severity = "warning"
		return result
	}
	_ = conn.Close()
	result.Success = true
	result.Summary = "TCP connect ok"
	return result
}

func (r AdvancedRunner) PublicIP(ctx context.Context, siteID string) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "public_ip", "Public IP", "https://api.ipify.org")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, result.Target, nil)
	resp, err := http.DefaultClient.Do(req)
	result.DurationMS = msSince(start)
	if err != nil {
		result.Error = err.Error()
		result.Severity = "warning"
		result.Summary = "Public IP lookup failed"
		return result
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	ip := strings.TrimSpace(string(body))
	result.Success = net.ParseIP(ip) != nil
	result.Summary = "Public IP: " + ip
	result.Details = ip
	if !result.Success {
		result.Severity = "warning"
		result.Error = "invalid public IP response"
	}
	return result
}

func (r AdvancedRunner) GatewayIdentity(ctx context.Context, siteID string) storage.AdvancedResult {
	result := baseAdvanced(siteID, "gateway_identity", "Gateway identity", "default gateway")
	gateway := ResolveGateway()
	if gateway == "" {
		result.Severity = "warning"
		result.Summary = "Default gateway not found"
		result.Error = "no default gateway"
		return result
	}
	result.Target = gateway
	mac := gatewayMAC(ctx, gateway)
	result.Success = mac != ""
	result.Summary = "Gateway " + gateway
	result.Details = mac
	if mac != "" {
		result.Summary += " MAC " + mac
		return result
	}
	result.Severity = "warning"
	result.Error = "gateway MAC not found in neighbor table"
	return result
}

func (r AdvancedRunner) NetworkEnv(siteID string) storage.AdvancedResult {
	result := baseAdvanced(siteID, "network_env", "Network environment", "local")
	env := map[string]any{"gateway": ResolveGateway(), "dns": resolvConfNameservers()}
	raw, _ := json.Marshal(env)
	result.Success = true
	result.Summary = "Gateway/DNS environment captured"
	result.Details = string(raw)
	return result
}

func (r AdvancedRunner) TLSDetails(ctx context.Context, siteID string, target config.HTTPTarget) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "tls_details", target.Name, target.URL)
	u, err := url.Parse(target.URL)
	if err != nil || u.Scheme != "https" {
		result.Success = true
		result.Summary = "TLS not applicable"
		return result
	}
	host := u.Hostname()
	conn, err := tls.DialWithDialer(&net.Dialer{}, "tcp", net.JoinHostPort(host, defaultPort(u.Port(), "443")), &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	result.DurationMS = msSince(start)
	if err != nil {
		result.Error = err.Error()
		result.Severity = "critical"
		result.Summary = "TLS connection failed"
		return result
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	details := map[string]any{"subject": cert.Subject.CommonName, "issuer": cert.Issuer.CommonName, "dns_names": cert.DNSNames, "not_after": cert.NotAfter, "days_until_expiry": int(time.Until(cert.NotAfter).Hours() / 24)}
	raw, _ := json.Marshal(details)
	result.Success = true
	result.Summary = fmt.Sprintf("TLS issuer %s, expires in %d days", cert.Issuer.CommonName, int(time.Until(cert.NotAfter).Hours()/24))
	result.Details = string(raw)
	return result
}

func (r AdvancedRunner) Trace(ctx context.Context, siteID string, target config.HostTarget) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "trace", target.Name, target.Host)
	tool, args := traceCommand(target.Host)
	if tool == "" {
		result.Severity = "warning"
		result.Summary = "Traceroute tool not installed"
		result.Error = "missing tracepath/traceroute"
		return result
	}
	out, err := exec.CommandContext(ctx, tool, args...).CombinedOutput()
	result.DurationMS = msSince(start)
	result.Details = string(out)
	result.Success = err == nil
	result.Summary = "Trace completed"
	if err != nil {
		result.Severity = "warning"
		result.Summary = "Trace failed"
		result.Error = err.Error()
	}
	return result
}

func (r AdvancedRunner) ProbeHealth(siteID string) storage.AdvancedResult {
	result := baseAdvanced(siteID, "probe_health", "Appliance health", "local")
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	details := map[string]any{"goroutines": runtime.NumGoroutine(), "alloc_bytes": mem.Alloc, "loadavg": readFirstLine("/proc/loadavg")}
	raw, _ := json.Marshal(details)
	result.Success = true
	result.Summary = fmt.Sprintf("Appliance runtime ok, %d goroutines", runtime.NumGoroutine())
	result.Details = string(raw)
	return result
}

func (r AdvancedRunner) NTP(ctx context.Context, siteID string, target config.HostTarget) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "ntp", target.Name, target.Host)
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(target.Host, "123"))
	if err != nil {
		result.Error = err.Error()
		result.Summary = "NTP connect failed"
		result.Severity = "warning"
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x1b
	if _, err := conn.Write(req); err != nil {
		result.Error = err.Error()
		result.Severity = "warning"
		return result
	}
	resp := make([]byte, 48)
	if _, err := io.ReadFull(conn, resp); err != nil {
		result.Error = err.Error()
		result.Severity = "warning"
		return result
	}
	secs := binary.BigEndian.Uint32(resp[40:44])
	remote := time.Unix(int64(secs)-2208988800, 0)
	drift := time.Since(remote).Seconds()
	result.DurationMS = msSince(start)
	result.Success = abs(drift) < 5
	result.Summary = fmt.Sprintf("NTP drift %.2f seconds", drift)
	result.Details = fmt.Sprintf(`{"drift_seconds":%.3f}`, drift)
	if !result.Success {
		result.Severity = "warning"
	}
	return result
}

func (r AdvancedRunner) PortScan(ctx context.Context, siteID string, device storage.Device, ports []int) storage.AdvancedResult {
	start := time.Now()
	result := baseAdvanced(siteID, "port_scan", device.IP, device.IP)
	var open []int
	for _, port := range ports {
		dialCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(device.IP, fmt.Sprint(port)))
		cancel()
		if err == nil {
			_ = conn.Close()
			open = append(open, port)
		}
	}
	raw, _ := json.Marshal(open)
	result.DurationMS = msSince(start)
	result.Success = true
	result.Summary = fmt.Sprintf("%d open common ports", len(open))
	result.Details = string(raw)
	return result
}

func baseAdvanced(siteID, checkType, name, target string) storage.AdvancedResult {
	return storage.AdvancedResult{Timestamp: time.Now().UTC(), SiteID: siteID, CheckType: checkType, TargetName: name, Target: target, Severity: "info", Summary: "ok"}
}

func gatewayMAC(ctx context.Context, gateway string) string {
	out, err := exec.CommandContext(ctx, "ip", "neigh", "show", gateway).Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) {
			return strings.ToLower(fields[i+1])
		}
	}
	return ""
}

func resolvConfNameservers() []string {
	raw, _ := os.ReadFile("/etc/resolv.conf")
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func traceCommand(host string) (string, []string) {
	if _, err := exec.LookPath("tracepath"); err == nil {
		return "tracepath", []string{"-n", "-m", "8", host}
	}
	if _, err := exec.LookPath("traceroute"); err == nil {
		return "traceroute", []string{"-n", "-m", "8", host}
	}
	return "", nil
}

func defaultPort(port, fallback string) string {
	if port != "" {
		return port
	}
	return fallback
}

func msSince(start time.Time) float64 { return float64(time.Since(start).Microseconds()) / 1000 }
func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
func readFirstLine(path string) string {
	raw, _ := os.ReadFile(path)
	return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
}
