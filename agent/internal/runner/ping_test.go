package runner

import "testing"

func TestParseLinuxPingOutput(t *testing.T) {
	output := `4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 10.123/12.500/20.000/3.100 ms`
	metrics, err := parsePingOutput(output)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if metrics.LossPercent != 0 {
		t.Fatalf("loss = %v", metrics.LossPercent)
	}
	if metrics.AvgMS != 12.5 {
		t.Fatalf("avg = %v", metrics.AvgMS)
	}
	if metrics.JitterMS != 3.1 {
		t.Fatalf("jitter = %v", metrics.JitterMS)
	}
}

func TestParseTotalLoss(t *testing.T) {
	output := `4 packets transmitted, 0 received, 100% packet loss, time 3000ms`
	metrics, err := parsePingOutput(output)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if metrics.LossPercent != 100 {
		t.Fatalf("loss = %v", metrics.LossPercent)
	}
}
