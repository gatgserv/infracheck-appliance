package agent

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func (a *Agent) unifiedAlerts(w http.ResponseWriter, r *http.Request) {
	history := r.URL.Query().Get("history") == "1"
	includeAck := r.URL.Query().Get("include_ack") == "1"
	if !history {
		records, err := a.currentAlertRecords(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := a.db.UpsertAlertRecords(records); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	records, err := a.db.AlertRecords(!history, includeAck, 300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	records = dedupeAlertRecords(records)
	writeJSON(w, http.StatusOK, map[string]any{"alerts": records})
}

func (a *Agent) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	err := a.db.AcknowledgeAlert(r.PathValue("fingerprint"))
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

type suppressAlertRequest struct {
	DurationHours float64 `json:"duration_hours"`
}

func (a *Agent) suppressAlert(w http.ResponseWriter, r *http.Request) {
	var req suppressAlertRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	until := time.Now().UTC().Add(24 * time.Hour)
	if req.DurationHours > 0 {
		until = time.Now().UTC().Add(time.Duration(req.DurationHours * float64(time.Hour)))
	}
	err := a.db.SuppressAlert(r.PathValue("fingerprint"), until)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "suppressed", "suppressed_until": until})
}

func (a *Agent) closeAlert(w http.ResponseWriter, r *http.Request) {
	err := a.db.CloseAlert(r.PathValue("fingerprint"))
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (a *Agent) currentAlertRecords(ctx context.Context) ([]storage.AlertRecord, error) {
	health, err := a.evaluateHealth()
	if err != nil {
		return nil, err
	}
	var records []storage.AlertRecord
	for _, v := range health.Verdicts {
		if v.Code == "healthy" {
			continue
		}
		labelMap := map[string]string{"code": v.Code, "category": v.Category}
		if target := alertStableTarget(v.Evidence); target != "" {
			labelMap["target"] = target
		}
		labels, _ := json.Marshal(labelMap)
		annotations, _ := json.Marshal(map[string]string{"summary": v.Summary, "recommendation": v.Recommendation})
		record := storage.AlertRecord{
			Source:         "internal",
			Severity:       v.Severity,
			State:          "active",
			Category:       v.Category,
			Title:          v.Title,
			Summary:        v.Summary,
			Recommendation: v.Recommendation,
			Evidence:       v.Evidence,
			Labels:         string(labels),
			Annotations:    string(annotations),
		}
		record.Fingerprint = alertFingerprint(record)
		records = append(records, record)
	}
	prometheus, err := a.prometheusAlertRecords(ctx)
	if err == nil {
		records = append(records, prometheus...)
	}
	records = append(records, a.deviceIntelligenceAlertRecords()...)
	devices, deviceErr := a.db.Devices(a.cfg.Site.ID)
	if deviceErr == nil {
		a.attachManagedSwitchLocations(devices)
		records = append(records, expectationAlertRecords(devices)...)
	}
	return dedupeAlertRecords(records), nil
}

func (a *Agent) deviceIntelligenceAlertRecords() []storage.AlertRecord {
	devices, err := a.db.Devices(a.cfg.Site.ID)
	if err != nil {
		return nil
	}
	devices = a.ensureDeviceIntelligence(devices)
	records := []storage.AlertRecord{}
	for _, device := range devices {
		if len(device.RiskFlags) == 0 {
			continue
		}
		name := firstNonEmpty(device.Hostname, device.IP, device.MAC)
		labels, _ := json.Marshal(map[string]string{"category": "inventory", "device_id": strconv.FormatInt(device.ID, 10), "target": device.IP})
		record := storage.AlertRecord{Source: "device-intelligence", Severity: "warning", State: "active", Category: "inventory", Title: "Device exposure needs review: " + name, Summary: strings.Join(device.RiskFlags, "; "), Recommendation: "Confirm these services are expected for the device role, restrict access where appropriate, or document the accepted exposure.", Evidence: append([]string{"device: " + name, "category: " + device.Category}, device.RiskFlags...), Labels: string(labels)}
		record.Fingerprint = alertFingerprint(record)
		records = append(records, record)
	}
	events, err := a.db.DeviceEvents(a.cfg.Site.ID, 300)
	if err != nil {
		return records
	}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	for _, event := range events {
		if event.Type != "ports_changed" || event.Timestamp.Before(cutoff) || event.Before == "" {
			continue
		}
		labels, _ := json.Marshal(map[string]string{"category": "inventory", "device_id": strconv.FormatInt(event.DeviceID, 10), "target": strconv.FormatInt(event.DeviceID, 10)})
		record := storage.AlertRecord{Source: "device-intelligence", Severity: "info", State: "active", Category: "inventory", Title: "Observed ports changed on device", Summary: event.Summary, Recommendation: "Review the device timeline and confirm the newly observed service set is expected.", Evidence: []string{"device id: " + strconv.FormatInt(event.DeviceID, 10), "before: " + event.Before, "after: " + event.After}, Labels: string(labels)}
		record.Fingerprint = alertFingerprint(record)
		records = append(records, record)
	}
	return records
}

func (a *Agent) prometheusAlertRecords(ctx context.Context) ([]storage.AlertRecord, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://127.0.0.1:9090/api/v1/alerts", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Data struct {
			Alerts []struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
				State       string            `json:"state"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	var records []storage.AlertRecord
	for _, item := range payload.Data.Alerts {
		labels, _ := json.Marshal(item.Labels)
		annotations, _ := json.Marshal(item.Annotations)
		record := storage.AlertRecord{
			Source:         "prometheus",
			Severity:       firstNonEmpty(item.Labels["severity"], "info"),
			State:          firstNonEmpty(item.State, "active"),
			Category:       firstNonEmpty(item.Labels["category"], "-"),
			Title:          item.Labels["alertname"],
			Summary:        firstNonEmpty(item.Annotations["description"], item.Annotations["summary"]),
			Recommendation: item.Annotations["recommendation"],
			Labels:         string(labels),
			Annotations:    string(annotations),
		}
		record.Fingerprint = alertFingerprint(record)
		records = append(records, record)
	}
	return records, nil
}

func alertFingerprint(record storage.AlertRecord) string {
	h := sha1.Sum([]byte(record.Source + "|" + record.Category + "|" + alertStableName(record) + "|" + alertStableTarget(record.Evidence)))
	return hex.EncodeToString(h[:])
}

func alertStableName(record storage.AlertRecord) string {
	labels := map[string]string{}
	_ = json.Unmarshal([]byte(record.Labels), &labels)
	return firstNonEmpty(labels["code"], labels["alertname"], record.Title)
}

func alertStableTargetFromLabels(record storage.AlertRecord) string {
	labels := map[string]string{}
	_ = json.Unmarshal([]byte(record.Labels), &labels)
	return labels["target"]
}

func alertStableTarget(evidence []string) string {
	for _, item := range evidence {
		lower := strings.ToLower(strings.TrimSpace(item))
		for _, prefix := range []string{"url:", "host:", "target:", "resolver:", "domain:", "service:"} {
			if strings.HasPrefix(lower, prefix) {
				return strings.TrimSpace(item[len(prefix):])
			}
		}
	}
	return ""
}

func dedupeAlertRecords(records []storage.AlertRecord) []storage.AlertRecord {
	byKey := map[string]storage.AlertRecord{}
	order := []string{}
	for _, record := range records {
		key := alertDedupeKey(record)
		if key == "" {
			key = "fingerprint:" + record.Fingerprint
		}
		existing, ok := byKey[key]
		if !ok {
			byKey[key] = record
			order = append(order, key)
			continue
		}
		byKey[key] = betterAlertRecord(existing, record)
	}
	out := make([]storage.AlertRecord, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

func betterAlertRecord(a, b storage.AlertRecord) storage.AlertRecord {
	if a.Source != b.Source {
		if b.Source == "internal" {
			return b
		}
		if a.Source == "internal" {
			return a
		}
	}
	if len(b.Evidence) != len(a.Evidence) {
		if len(b.Evidence) > len(a.Evidence) {
			return b
		}
		return a
	}
	if len(b.Summary)+len(b.Recommendation) > len(a.Summary)+len(a.Recommendation) {
		return b
	}
	return a
}

func alertDedupeKey(record storage.AlertRecord) string {
	combined := normalizeAlertText(record.Category + " " + record.Title + " " + record.Summary + " " + record.Labels + " " + record.Annotations)
	if strings.Contains(combined, "lan") || strings.Contains(combined, "device") || strings.Contains(combined, "inventory") {
		if strings.Contains(combined, "missing") || strings.Contains(combined, "not seen") {
			return "inventory:device-missing"
		}
		if strings.Contains(combined, "new") || strings.Contains(combined, "first seen") {
			return "inventory:device-new"
		}
	}
	if strings.Contains(combined, "wan") && strings.Contains(combined, "speed") {
		return "wan:speed"
	}
	if strings.Contains(combined, "ping") {
		if strings.Contains(combined, "gateway") {
			return "ping:gateway"
		}
		if strings.Contains(combined, "target down") || strings.Contains(combined, "unreachable") {
			return "ping:target-down"
		}
	}
	if strings.Contains(combined, "http") || strings.Contains(combined, "tls") {
		return "service:" + firstToken(record.Title)
	}
	if strings.Contains(combined, "dns") {
		return "dns:" + firstToken(record.Title)
	}
	if record.Category != "" && record.Title != "" {
		return normalizeAlertText(record.Category + ":" + record.Title)
	}
	return ""
}

var alertNonWordRE = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeAlertText(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", " ")
	value = alertNonWordRE.ReplaceAllString(value, " ")
	return strings.TrimSpace(value)
}

func firstToken(value string) string {
	value = normalizeAlertText(value)
	if value == "" {
		return "unknown"
	}
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return "unknown"
	}
	return parts[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
