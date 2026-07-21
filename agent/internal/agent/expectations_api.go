package agent

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func (a *Agent) deviceExpectations(w http.ResponseWriter, _ *http.Request) {
	items, err := a.db.DeviceExpectations(a.cfg.Site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"expectations": items})
}

func (a *Agent) updateDeviceExpectation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}
	if _, err := a.db.Device(a.cfg.Site.ID, id); errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var req storage.DeviceExpectation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.DeviceID = id
	req.SiteID = a.cfg.Site.ID
	req.Authorization = strings.ToLower(strings.TrimSpace(req.Authorization))
	if req.Authorization == "" {
		req.Authorization = "authorized"
	}
	if req.Authorization != "authorized" && req.Authorization != "blocked" && req.Authorization != "review" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization must be authorized, review, or blocked"})
		return
	}
	if req.ExpectedIP != "" && net.ParseIP(req.ExpectedIP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected_ip must be a valid IP"})
		return
	}
	req.ExpectedPorts = sanitizePorts(req.ExpectedPorts)
	req.ExpectedServices = sanitizeExpectedServices(req.ExpectedServices)
	req.ExpectedCategory = strings.ToLower(strings.TrimSpace(req.ExpectedCategory))
	req.ExpectedVLAN = strings.TrimSpace(req.ExpectedVLAN)
	req.ExpectedAP = strings.TrimSpace(req.ExpectedAP)
	req.ExpectedSwitch = strings.TrimSpace(req.ExpectedSwitch)
	req.ExpectedPort = strings.TrimSpace(req.ExpectedPort)
	updated, err := a.db.UpsertDeviceExpectation(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"expectation": updated})
}

func sanitizeExpectedServices(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func expectationAlertRecords(devices []storage.Device) []storage.AlertRecord {
	now := time.Now().UTC()
	var records []storage.AlertRecord
	for _, device := range devices {
		exp := device.Expectation
		if exp == nil || (!exp.MaintenanceUntil.IsZero() && exp.MaintenanceUntil.After(now)) {
			continue
		}
		name := firstNonEmpty(device.Hostname, device.IP, device.MAC)
		var mismatches []string
		severity := "warning"
		if exp.Authorization == "blocked" {
			severity = "critical"
			mismatches = append(mismatches, "device is present but marked blocked")
		} else if exp.Authorization == "review" {
			mismatches = append(mismatches, "device authorization requires review")
		}
		if exp.ExpectedIP != "" && exp.ExpectedIP != device.IP {
			mismatches = append(mismatches, "IP expected "+exp.ExpectedIP+", observed "+device.IP)
		}
		if exp.ExpectedCategory != "" && !strings.EqualFold(exp.ExpectedCategory, device.Category) {
			mismatches = append(mismatches, "category expected "+exp.ExpectedCategory+", observed "+firstNonEmpty(device.Category, "unknown"))
		}
		observedPorts := []int{}
		_ = json.Unmarshal([]byte(device.OpenPorts), &observedPorts)
		if len(exp.ExpectedPorts) > 0 && !sameInts(exp.ExpectedPorts, observedPorts) {
			mismatches = append(mismatches, "TCP ports expected "+intsText(exp.ExpectedPorts)+", observed "+intsText(observedPorts))
		}
		if len(exp.ExpectedServices) > 0 {
			lowerServices := strings.ToLower(device.Services)
			for _, expected := range exp.ExpectedServices {
				if !strings.Contains(lowerServices, strings.ToLower(expected)) {
					mismatches = append(mismatches, "expected service not observed: "+expected)
				}
			}
		}
		if exp.ExpectedVLAN != "" && exp.ExpectedVLAN != device.VLAN {
			mismatches = append(mismatches, "VLAN expected "+exp.ExpectedVLAN+", observed "+firstNonEmpty(device.VLAN, "unknown"))
		}
		if exp.ExpectedSwitch != "" && !strings.EqualFold(exp.ExpectedSwitch, device.SwitchHost) {
			mismatches = append(mismatches, "switch expected "+exp.ExpectedSwitch+", observed "+firstNonEmpty(device.SwitchHost, "unknown"))
		}
		if exp.ExpectedPort != "" && exp.ExpectedPort != device.SwitchPort && !strings.EqualFold(exp.ExpectedPort, device.SwitchIfName) {
			mismatches = append(mismatches, "switch port expected "+exp.ExpectedPort+", observed "+firstNonEmpty(device.SwitchIfName, device.SwitchPort, "unknown"))
		}
		if len(mismatches) == 0 {
			continue
		}
		labels, _ := json.Marshal(map[string]string{"category": "expected-state", "device_id": strconv.FormatInt(device.ID, 10), "target": device.IP})
		record := storage.AlertRecord{Source: "expected-state", Severity: severity, State: "active", Category: "inventory", Title: "Expected state mismatch: " + name, Summary: strings.Join(mismatches, "; "), Recommendation: "Confirm the device identity and placement, then update the approved baseline or correct the network state.", Evidence: append([]string{"device: " + name}, mismatches...), Labels: string(labels)}
		record.Fingerprint = alertFingerprint(record)
		record.LastSeen = now
		records = append(records, record)
	}
	return records
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]int(nil), a...), append([]int(nil), b...)
	sort.Ints(aa)
	sort.Ints(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func intsText(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}
