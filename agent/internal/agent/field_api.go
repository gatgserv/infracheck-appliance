package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/runner"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

const maxThroughputBytes int64 = 64 << 20

var throughputBlock = make([]byte, 64<<10)

type udpEchoManager struct {
	mu      sync.Mutex
	port    int
	conn    *net.UDPConn
	token   string
	expires time.Time
}

func newUDPEchoManager(port int) *udpEchoManager { return &udpEchoManager{port: port} }

func (m *udpEchoManager) Start(parent context.Context, duration time.Duration) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: m.port})
	if err != nil {
		return "", time.Time{}, err
	}
	if duration < 30*time.Second || duration > 10*time.Minute {
		duration = 2 * time.Minute
	}
	m.conn = conn
	m.token = base64.RawURLEncoding.EncodeToString(raw)
	m.expires = time.Now().UTC().Add(duration)
	token := m.token
	expires := m.expires
	go m.serve(parent, conn, token, expires)
	return token, expires, nil
}

func (m *udpEchoManager) serve(parent context.Context, conn *net.UDPConn, token string, expires time.Time) {
	prefix := []byte(token + "|")
	buf := make([]byte, 1500)
	for {
		deadline := time.Now().Add(time.Second)
		if expires.Before(deadline) {
			deadline = expires
		}
		_ = conn.SetReadDeadline(deadline)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || parent.Err() != nil || time.Now().After(expires) {
				break
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			continue
		}
		if n >= len(prefix) && string(buf[:len(prefix)]) == string(prefix) {
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}
	m.mu.Lock()
	if m.conn == conn {
		_ = m.conn.Close()
		m.conn = nil
		m.token = ""
	}
	m.mu.Unlock()
}

func (m *udpEchoManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		_ = m.conn.Close()
	}
	m.conn = nil
	m.token = ""
	m.expires = time.Time{}
}

func requestedBytes(r *http.Request) int64 {
	value, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
	if value < 256<<10 {
		value = 8 << 20
	}
	if value > maxThroughputBytes {
		value = maxThroughputBytes
	}
	return value
}

func (a *Agent) fieldThroughputDownload(w http.ResponseWriter, r *http.Request) {
	size := requestedBytes(r)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Encoding", "identity")
	w.WriteHeader(http.StatusOK)
	remaining := size
	for remaining > 0 {
		chunk := int64(len(throughputBlock))
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := w.Write(throughputBlock[:chunk]); err != nil {
			return
		}
		remaining -= chunk
	}
}

func (a *Agent) fieldThroughputUpload(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, maxThroughputBytes)
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bytes": n, "server_duration_ms": float64(time.Since(started).Microseconds()) / 1000})
}

func (a *Agent) fieldUDPStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DurationSeconds int `json:"duration_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	duration := time.Duration(req.DurationSeconds) * time.Second
	token, expires, err := a.udpEcho.Start(context.Background(), duration)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"port": a.udpEcho.port, "token": token, "expires_at": expires})
}

func (a *Agent) fieldUDPStop(w http.ResponseWriter, _ *http.Request) {
	a.udpEcho.Stop()
	writeJSON(w, http.StatusOK, map[string]bool{"stopped": true})
}

func (a *Agent) fieldAutoTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	profile := strings.ToLower(strings.TrimSpace(req.Profile))
	if profile != "wifi" && profile != "voip" {
		profile = "standard"
	}
	started := time.Now().UTC()
	result := map[string]any{
		"profile": profile, "started_at": started,
		"ping": a.runAllPingTargets(r.Context()), "dns": a.runAllDNSTargets(r.Context()), "http": a.runAllHTTPTargets(r.Context()),
	}
	advanced := a.runAdvanced(r.Context(), true)
	if profile == "wifi" || profile == "voip" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		dhcp := a.advanced.DHCPIntegrity(ctx, a.cfg.Site.ID, "")
		cancel()
		a.saveFieldAdvanced(dhcp)
		result["dhcp_integrity"] = dhcp
		resolvers := configuredResolvers(a)
		domain := "example.com"
		if targets := a.effectiveTargets().DNS.Domains; len(targets) > 0 {
			domain = targets[0]
		}
		ctx, cancel = context.WithTimeout(r.Context(), 12*time.Second)
		dnsIntegrity := a.advanced.DNSIntegrity(ctx, a.cfg.Site.ID, domain, resolvers)
		cancel()
		a.saveFieldAdvanced(dnsIntegrity)
		result["dns_integrity"] = dnsIntegrity
	}
	if profile == "voip" {
		token, expires, err := a.udpEcho.Start(context.Background(), 2*time.Minute)
		if err == nil {
			result["udp_echo"] = map[string]any{"port": a.udpEcho.port, "token": token, "expires_at": expires}
		} else {
			result["udp_echo_error"] = err.Error()
		}
	}
	result["advanced"] = advanced
	result["duration_ms"] = float64(time.Since(started).Microseconds()) / 1000
	writeJSON(w, http.StatusOK, result)
}

func (a *Agent) saveFieldAdvanced(result storage.AdvancedResult) {
	a.applyChangeDetection(&result)
	if err := a.db.SaveAdvanced(result); err != nil {
		a.logger.Error("failed to save field diagnostic", "error", err, "type", result.CheckType)
	}
}

func (a *Agent) fieldProgressivePath(w http.ResponseWriter, r *http.Request) {
	var req runner.PathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Host) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	result := a.advanced.ProgressivePath(ctx, a.cfg.Site.ID, req)
	a.saveFieldAdvanced(result)
	writeJSON(w, http.StatusOK, result)
}

func (a *Agent) fieldDHCPIntegrity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpectedServer string `json:"expected_server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result := a.advanced.DHCPIntegrity(ctx, a.cfg.Site.ID, strings.TrimSpace(req.ExpectedServer))
	a.saveFieldAdvanced(result)
	writeJSON(w, http.StatusOK, result)
}

func configuredResolvers(a *Agent) map[string]string {
	result := map[string]string{"system": "auto"}
	for _, resolver := range a.effectiveTargets().DNS.Resolvers {
		name := nonEmpty(resolver.Name, resolver.Address)
		result[name] = resolver.Address
	}
	return result
}

func (a *Agent) fieldDNSIntegrity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain    string            `json:"domain"`
		Resolvers map[string]string `json:"resolvers"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if len(req.Resolvers) == 0 {
		req.Resolvers = configuredResolvers(a)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result := a.advanced.DNSIntegrity(ctx, a.cfg.Site.ID, strings.TrimSpace(req.Domain), req.Resolvers)
	a.saveFieldAdvanced(result)
	writeJSON(w, http.StatusOK, result)
}

func (a *Agent) fieldSNMPTopology(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host      string `json:"host"`
		Community string `json:"community"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || net.ParseIP(strings.TrimSpace(req.Host)) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid host IP is required"})
		return
	}
	community := strings.TrimSpace(req.Community)
	if community == "" {
		community = os.Getenv("INFRACHECK_SNMP_COMMUNITY")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result := a.advanced.SNMPTopology(ctx, a.cfg.Site.ID, strings.TrimSpace(req.Host), community)
	a.saveFieldAdvanced(result)
	writeJSON(w, http.StatusOK, result)
}
