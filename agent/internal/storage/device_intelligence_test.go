package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceIntelligenceAndWiFiPersistence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	_, err = db.UpsertDevices([]Device{{SiteID: "site", IP: "192.0.2.10", MAC: "00:11:22:33:44:55", FirstSeen: now, LastSeen: now, Source: "arp"}})
	if err != nil {
		t.Fatal(err)
	}
	devices, err := db.Devices("site")
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices: %#v, %v", devices, err)
	}
	updated, err := db.UpdateDeviceIntelligence("site", devices[0].ID, "[22,445]", "[\"smb\",\"ssh\"]", "Server / NAS", "High", []string{"ports 445"}, []string{"SMB file sharing exposed (TCP 445)"}, "test-v1", now)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Category != "Server / NAS" || updated.OpenPorts != "[22,445]" || len(updated.RiskFlags) != 1 {
		t.Fatalf("updated device = %#v", updated)
	}
	expectation, err := db.UpsertDeviceExpectation(DeviceExpectation{DeviceID: devices[0].ID, SiteID: "site", Authorization: "authorized", ExpectedCategory: "Server / NAS", ExpectedIP: "192.0.2.10", ExpectedPorts: []int{22, 445}, ExpectedServices: []string{"ssh", "smb"}, ExpectedSwitch: "192.0.2.2", ExpectedPort: "Gi1/0/7", ExpectedVLAN: "20"})
	if err != nil || expectation.Authorization != "authorized" || len(expectation.ExpectedPorts) != 2 || expectation.ExpectedPort != "Gi1/0/7" {
		t.Fatalf("expectation = %#v, err = %v", expectation, err)
	}
	withExpectation, err := db.Device("site", devices[0].ID)
	if err != nil || withExpectation.Expectation == nil || withExpectation.Expectation.ExpectedIP != "192.0.2.10" {
		t.Fatalf("device expectation not attached: %#v, err = %v", withExpectation, err)
	}
	events, err := db.DeviceEvents("site", 10)
	if err != nil || len(events) != 1 || events[0].Type != "ports_changed" {
		t.Fatalf("events = %#v, %v", events, err)
	}
	stored, err := db.UpsertWiFiObservations("site", "android", []WiFiObservation{{BSSID: "AA:BB:CC:DD:EE:FF", SSID: "Office", Channel: 36, RSSIDBm: -55, FirstSeen: now, LastSeen: now}})
	if err != nil || stored != 1 {
		t.Fatalf("stored = %d, err = %v", stored, err)
	}
	wifi, err := db.WiFiObservations("site", 10)
	if err != nil || len(wifi) != 1 || wifi[0].BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("wifi = %#v, %v", wifi, err)
	}
}
