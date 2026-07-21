package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

const deviceClassifierVersion = "container-1.0"

type deviceClassification struct {
	Category   string
	Confidence string
	Evidence   []string
	RiskFlags  []string
	Services   []string
}

func classifyDevice(device storage.Device, ports []int) deviceClassification {
	portSet := map[int]bool{}
	for _, port := range ports {
		if port > 0 && port <= 65535 {
			portSet[port] = true
		}
	}
	host := strings.ToLower(device.Hostname)
	vendor := strings.ToLower(device.Vendor)
	servicesText := strings.ToLower(device.Services)
	services := serviceNames(ports)
	evidence := []string{}
	has := func(values ...int) bool {
		for _, value := range values {
			if portSet[value] {
				return true
			}
		}
		return false
	}
	contains := func(value string, terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(value, term) {
				return true
			}
		}
		return false
	}
	addPorts := func(values ...int) {
		found := []string{}
		for _, value := range values {
			if portSet[value] {
				found = append(found, strconv.Itoa(value))
			}
		}
		if len(found) > 0 {
			evidence = append(evidence, "ports "+strings.Join(found, ","))
		}
	}
	addText := func(label, value string, terms ...string) {
		for _, term := range terms {
			if strings.Contains(value, term) {
				evidence = append(evidence, label+" ("+term+")")
				return
			}
		}
	}

	category := "Unclassified device"
	switch {
	case has(631, 9100, 515) || contains(servicesText, "ipp", "printer", "airprint"):
		category = "Printer"
		addPorts(631, 9100, 515)
		addText("printer service", servicesText, "ipp", "printer", "airprint")
	case has(554, 8554) || contains(servicesText, "rtsp", "onvif") || contains(host, "camera", "cam-", "nvr", "dvr"):
		category = "Camera / video"
		addPorts(554, 8554)
		addText("camera service", servicesText, "rtsp", "onvif")
		addText("camera hostname", host, "camera", "cam-", "nvr", "dvr")
	case contains(servicesText, "airplay", "googlecast", "chromecast", "roku", "homekit", "sonos", "upnp"):
		category = "Media / IoT"
		addText("discovery service", servicesText, "airplay", "googlecast", "chromecast", "roku", "homekit", "sonos", "upnp")
	case contains(host, "router", "gateway", "switch", "firewall", "accesspoint", "access-point", "ap-", "-ap") || contains(vendor, "ubiquiti", "cisco", "meraki", "aruba", "mikrotik", "fortinet", "juniper"):
		category = "Network infrastructure"
		addText("infrastructure hostname", host, "router", "gateway", "switch", "firewall", "accesspoint", "access-point", "ap-", "-ap")
		addText("network vendor", vendor, "ubiquiti", "cisco", "meraki", "aruba", "mikrotik", "fortinet", "juniper")
	case has(445, 2049, 111) || contains(servicesText, "smb", "nfs", "nas") || contains(host, "nas", "server", "synology", "qnap"):
		category = "Server / NAS"
		addPorts(445, 2049, 111)
		addText("file service", servicesText, "smb", "nfs", "nas")
		addText("server hostname", host, "nas", "server", "synology", "qnap")
	case has(3389) || contains(servicesText, "workstation", "rdp") || contains(host, "desktop", "laptop", "macbook", "workstation"):
		category = "Workstation"
		addPorts(3389)
		addText("client hostname", host, "desktop", "laptop", "macbook", "workstation")
	case len(portSet) > 0:
		category = "Service host"
		addPorts(ports...)
	case strings.Contains(strings.ToLower(device.Source), "dhcp") || strings.Contains(strings.ToLower(device.Source), "arp"):
		category = "Client device"
		evidence = append(evidence, "seen through "+device.Source)
	case device.Vendor != "":
		evidence = append(evidence, "vendor "+device.Vendor)
	}
	confidence := "Low"
	if len(evidence) >= 2 {
		confidence = "High"
	} else if len(evidence) == 1 && category != "Client device" && category != "Unclassified device" {
		confidence = "Medium"
	}
	risks := []string{}
	for port, label := range map[int]string{21: "FTP clear-text service", 23: "Telnet clear-text administration", 445: "SMB file sharing exposed", 3389: "RDP remote administration", 3306: "MySQL database service", 5432: "PostgreSQL database service", 6379: "Redis database service", 27017: "MongoDB database service"} {
		if portSet[port] {
			risks = append(risks, fmt.Sprintf("%s (TCP %d)", label, port))
		}
	}
	sort.Strings(risks)
	return deviceClassification{Category: category, Confidence: confidence, Evidence: evidence, RiskFlags: risks, Services: services}
}

func serviceNames(ports []int) []string {
	names := map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 111: "rpcbind", 443: "https", 445: "smb", 515: "lpd", 554: "rtsp", 631: "ipp", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 8554: "rtsp-alt", 9100: "jetdirect", 27017: "mongodb"}
	out := []string{}
	seen := map[string]bool{}
	for _, port := range ports {
		if name := names[port]; name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func mergeServices(existing string, observed []string) string {
	values := []string{}
	if strings.TrimSpace(existing) != "" {
		if err := json.Unmarshal([]byte(existing), &values); err != nil {
			values = append(values, strings.TrimSpace(existing))
		}
	}
	seen := map[string]bool{}
	merged := []string{}
	for _, value := range append(values, observed...) {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			merged = append(merged, value)
		}
	}
	sort.Strings(merged)
	raw, _ := json.Marshal(merged)
	return string(raw)
}

func (a *Agent) persistDevicePortScan(device storage.Device, scan storage.AdvancedResult) storage.Device {
	ports := parsePortList(scan.Details)
	classification := classifyDevice(device, ports)
	portsJSON, _ := json.Marshal(ports)
	servicesJSON := mergeServices(device.Services, classification.Services)
	updated, err := a.db.UpdateDeviceIntelligence(a.cfg.Site.ID, device.ID, string(portsJSON), servicesJSON, classification.Category, classification.Confidence, classification.Evidence, classification.RiskFlags, deviceClassifierVersion, scan.Timestamp)
	if err != nil {
		a.logger.Error("failed to persist device intelligence", "error", err, "device", device.IP)
		return device
	}
	return updated
}

func (a *Agent) persistDeviceServices(device storage.Device, services []string) storage.Device {
	ports := parsePortList(device.OpenPorts)
	device.Services = mergeServices(device.Services, services)
	classification := classifyDevice(device, ports)
	portsJSON, _ := json.Marshal(ports)
	updated, err := a.db.UpdateDeviceIntelligence(a.cfg.Site.ID, device.ID, string(portsJSON), device.Services, classification.Category, classification.Confidence, classification.Evidence, classification.RiskFlags, deviceClassifierVersion, device.PortsObservedAt)
	if err != nil {
		a.logger.Error("failed to persist device services", "error", err, "device", device.IP)
		return device
	}
	return updated
}

func (a *Agent) ensureDeviceIntelligence(devices []storage.Device) []storage.Device {
	for i := range devices {
		if devices[i].ClassificationVersion != "" {
			continue
		}
		ports := parsePortList(devices[i].OpenPorts)
		classification := classifyDevice(devices[i], ports)
		portsJSON, _ := json.Marshal(ports)
		servicesJSON := mergeServices(devices[i].Services, classification.Services)
		updated, err := a.db.UpdateDeviceIntelligence(a.cfg.Site.ID, devices[i].ID, string(portsJSON), servicesJSON, classification.Category, classification.Confidence, classification.Evidence, classification.RiskFlags, deviceClassifierVersion, time.Time{})
		if err == nil {
			devices[i] = updated
		}
	}
	return devices
}

func (a *Agent) deviceEvents(w http.ResponseWriter, _ *http.Request) {
	events, err := a.db.DeviceEvents(a.cfg.Site.ID, 300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (a *Agent) wifiObservations(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.WiFiObservations(a.cfg.Site.ID, 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": rows})
}

func (a *Agent) uploadWiFiObservations(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source       string                    `json:"source"`
		Observations []storage.WiFiObservation `json:"observations"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid Wi-Fi survey: " + err.Error()})
		return
	}
	if len(req.Observations) > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "survey is limited to 1000 observations"})
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "android"
	}
	if len(source) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source is limited to 64 characters"})
		return
	}
	for i := range req.Observations {
		if _, err := net.ParseMAC(strings.TrimSpace(req.Observations[i].BSSID)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("observation %d has an invalid BSSID", i+1)})
			return
		}
		if len(req.Observations[i].SSID) > 128 || len(req.Observations[i].Capabilities) > 1024 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("observation %d contains an oversized field", i+1)})
			return
		}
	}
	count, err := a.db.UpsertWiFiObservations(a.cfg.Site.ID, source, req.Observations)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = a.db.SaveEvent("wifi_survey", "Wi-Fi survey uploaded", strconv.Itoa(count)+" observation(s) from "+source)
	writeJSON(w, http.StatusOK, map[string]any{"stored": count, "source": source})
}
