package runner

import (
	"testing"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func TestMergeDeviceCombinesSources(t *testing.T) {
	now := time.Now()
	devices := map[string]storage.Device{}
	mergeDevice(devices, storage.Device{SiteID: "site", IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:ff", Source: "arp", LastSeen: now})
	mergeDevice(devices, storage.Device{SiteID: "site", IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Example Vendor", Source: "arp-scan", LastSeen: now.Add(time.Second)})

	device := devices["aa:bb:cc:dd:ee:ff"]
	if device.Vendor != "Example Vendor" {
		t.Fatalf("vendor = %q", device.Vendor)
	}
	if device.Source != "arp,arp-scan" {
		t.Fatalf("source = %q", device.Source)
	}
	if !device.LastSeen.Equal(now.Add(time.Second)) {
		t.Fatalf("last seen = %v", device.LastSeen)
	}
}

func TestNormalizeMAC(t *testing.T) {
	if got := normalizeMAC("AA-BB-CC-DD-EE-FF"); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac = %q", got)
	}
	if got := normalizeMAC("<incomplete>"); got != "" {
		t.Fatalf("incomplete mac = %q", got)
	}
}
