package runner

import "testing"

func TestMergeTraceOutput(t *testing.T) {
	hops := map[int]*PathHop{}
	mergeTraceOutput(hops, " 1  192.168.1.1  1.25 ms\n 2  *\n 3  1.1.1.1  12.8 ms")
	if len(hops) != 3 || hops[1].Addresses[0] != "192.168.1.1" || hops[2].Timeouts != 1 || hops[3].RTTMS[0] != 12.8 {
		t.Fatalf("unexpected trace parse: %#v", hops)
	}
}

func TestExtractDHCPValues(t *testing.T) {
	raw := "| Server Identifier: 10.0.0.1\n| Router: 10.0.0.1\n| Domain Name Server: 10.0.0.2, 1.1.1.1"
	values := extractDHCPValues(raw, "Domain Name Server")
	if len(values) != 2 || values[0] != "1.1.1.1" || values[1] != "10.0.0.2" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestParseSNMPTable(t *testing.T) {
	raw := ".1.0.8802.1.1.2.1.4.1.1.9.0.5.1 = STRING: \"access-point-1\"\n"
	values := parseSNMPTable(raw, lldpRemoteNameOID)
	if values["0.5.1"] != "access-point-1" {
		t.Fatalf("unexpected table: %#v", values)
	}
}

func TestBuildSwitchPortLocations(t *testing.T) {
	locations := buildSwitchPortLocations(map[string]string{"10.0.17.34.51.68.85": "7"}, map[string]string{"7": "42"}, map[string]string{"42": "Gi1/0/7"})
	if len(locations) != 1 || locations[0].MAC != "00:11:22:33:44:55" || locations[0].VLAN != "10" || locations[0].IfName != "Gi1/0/7" {
		t.Fatalf("unexpected locations: %#v", locations)
	}
}
