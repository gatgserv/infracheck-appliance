package agent

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func TestClassifyDeviceUsesPortsAndRiskFlags(t *testing.T) {
	result := classifyDevice(storage.Device{Hostname: "office-nas"}, []int{445, 2049, 23})
	if result.Category != "Server / NAS" {
		t.Fatalf("category = %q, want Server / NAS", result.Category)
	}
	if result.Confidence != "High" {
		t.Fatalf("confidence = %q, want High", result.Confidence)
	}
	if len(result.RiskFlags) != 2 {
		t.Fatalf("risk flags = %#v, want Telnet and SMB flags", result.RiskFlags)
	}
}

func TestExpectationAlertsDetectMismatchAndRespectMaintenance(t *testing.T) {
	device := storage.Device{ID: 9, IP: "192.0.2.9", Hostname: "nas", Category: "Server / NAS", OpenPorts: "[22,445]", Services: "[\"ssh\",\"smb\"]", SwitchHost: "192.0.2.2", SwitchIfName: "Gi1/0/7", VLAN: "20", Expectation: &storage.DeviceExpectation{Authorization: "authorized", ExpectedCategory: "server / nas", ExpectedIP: "192.0.2.10", ExpectedPorts: []int{22, 445}, ExpectedServices: []string{"ssh"}, ExpectedSwitch: "192.0.2.2", ExpectedPort: "Gi1/0/7", ExpectedVLAN: "20"}}
	records := expectationAlertRecords([]storage.Device{device})
	if len(records) != 1 || records[0].Source != "expected-state" || records[0].Severity != "warning" {
		t.Fatalf("unexpected records: %#v", records)
	}
	device.Expectation.MaintenanceUntil = time.Now().UTC().Add(time.Hour)
	if records = expectationAlertRecords([]storage.Device{device}); len(records) != 0 {
		t.Fatalf("maintenance should suppress mismatch, got %#v", records)
	}
}

func TestClassifyDeviceLeavesWeakVendorEvidenceUnclassified(t *testing.T) {
	result := classifyDevice(storage.Device{Vendor: "Example Devices"}, nil)
	if result.Category != "Unclassified device" || result.Confidence != "Low" {
		t.Fatalf("classification = %q/%q, want Unclassified device/Low", result.Category, result.Confidence)
	}
}

func TestServiceNamesAreStable(t *testing.T) {
	got := serviceNames([]int{443, 22, 443, 9100})
	want := []string{"https", "jetdirect", "ssh"}
	if len(got) != len(want) {
		t.Fatalf("services = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("services = %#v, want %#v", got, want)
		}
	}
}

func TestMergeServicesPreservesDiscoveryEvidence(t *testing.T) {
	got := mergeServices(`["_ipp._tcp"]`, []string{"ipp", "https"})
	if got != `["_ipp._tcp","https","ipp"]` {
		t.Fatalf("merged services = %s", got)
	}
}

func TestUploadWiFiObservationsRequiresValidPayloadAndStoresRows(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Default()
	cfg.Site.ID = "site"
	a := &Agent{cfg: cfg, db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := []byte(`{"source":"android","observations":[{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"Office","band":"5 GHz","channel":36,"rssi_dbm":-55,"first_seen":"2026-07-21T20:00:00Z","last_seen":"2026-07-21T20:01:00Z"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wifi/observations", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	a.uploadWiFiObservations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rows, err := db.WiFiObservations("site", 10)
	if err != nil || len(rows) != 1 || rows[0].Channel != 36 {
		t.Fatalf("rows = %#v, err = %v", rows, err)
	}
}

func TestLatestManagedSwitchTopologyParsesPersistedSNMPResult(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "topology.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	details := `{"host":"192.0.2.2","neighbors":[{"host":"192.0.2.2","local_index":"7","remote_name":"ap-1","remote_port":"eth0"}],"mac_table":[{"mac":"00:11:22:33:44:55","vlan":"20","bridge_port":"7","if_index":"42","if_name":"Gi1/0/7"}]}`
	if err := db.SaveAdvanced(storage.AdvancedResult{Timestamp: now, SiteID: "site", CheckType: "snmp_topology", TargetName: "192.0.2.2", Target: "192.0.2.2", Success: true, Summary: "one neighbor", Details: details}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{db: db}
	rows := a.latestManagedSwitchTopology()
	if len(rows) != 1 || len(rows[0].MACTable) != 1 || rows[0].MACTable[0].IfName != "Gi1/0/7" || len(rows[0].Neighbors) != 1 {
		t.Fatalf("unexpected topology: %#v", rows)
	}
	devices := []storage.Device{{MAC: "00-11-22-33-44-55"}}
	a.attachManagedSwitchLocations(devices)
	if devices[0].SwitchHost != "192.0.2.2" || devices[0].SwitchIfName != "Gi1/0/7" || devices[0].VLAN != "20" {
		t.Fatalf("location not attached: %#v", devices[0])
	}
}

func TestDeviceExpectationAPIStoresLocationBaseline(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "expectation-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err = db.UpsertDevices([]storage.Device{{SiteID: "site", IP: "192.0.2.20", MAC: "00:11:22:33:44:66", FirstSeen: now, LastSeen: now, Source: "test"}}); err != nil {
		t.Fatal(err)
	}
	devices, err := db.Devices("site")
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices=%#v err=%v", devices, err)
	}
	cfg := config.Default()
	cfg.Site.ID = "site"
	cfg.Security.AdminToken = "admin"
	a, err := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"authorization":"authorized","expected_ip":"192.0.2.20","expected_switch":"192.0.2.2","expected_port":"Gi1/0/7","expected_vlan":"20"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/"+strconv.FormatInt(devices[0].ID, 10)+"/expectation", body)
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	expectation, err := db.DeviceExpectation("site", devices[0].ID)
	if err != nil || expectation.ExpectedSwitch != "192.0.2.2" || expectation.ExpectedPort != "Gi1/0/7" || expectation.ExpectedVLAN != "20" {
		t.Fatalf("expectation=%#v err=%v", expectation, err)
	}
}
