package runner

import (
	"context"
	"errors"
	"math"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type PingTarget struct {
	SiteID string
	Name   string
	Host   string
	Type   string
}

type PingRunner struct {
	Count int
}

func (r PingRunner) Run(ctx context.Context, target PingTarget) storage.PingResult {
	if r.Count <= 0 {
		r.Count = 4
	}
	result := storage.PingResult{
		Timestamp:  time.Now().UTC(),
		SiteID:     target.SiteID,
		TargetName: target.Name,
		TargetHost: target.Host,
		TargetType: target.Type,
	}

	if target.Host == "" || target.Host == "auto" {
		result.Error = "target host is not resolved"
		result.LossPercent = 100
		return result
	}

	args := pingArgs(target.Host, r.Count)
	cmd := exec.CommandContext(ctx, "ping", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	metrics, parseErr := parsePingOutput(output)
	if parseErr == nil {
		result.Up = metrics.LossPercent < 100
		result.LatencyMS = metrics.AvgMS
		result.LossPercent = metrics.LossPercent
		result.JitterMS = metrics.JitterMS
	}
	if err != nil {
		result.Error = strings.TrimSpace(err.Error())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.Error = "ping timed out"
		}
		if parseErr != nil {
			result.LossPercent = 100
		}
	}
	if parseErr != nil && result.Error == "" {
		result.Error = parseErr.Error()
		result.LossPercent = 100
	}
	return result
}

func pingArgs(host string, count int) []string {
	if runtime.GOOS == "windows" {
		return []string{"-n", strconv.Itoa(count), host}
	}
	return []string{"-c", strconv.Itoa(count), "-n", host}
}

type pingMetrics struct {
	LossPercent float64
	AvgMS       float64
	JitterMS    float64
}

var (
	packetLossRE = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)%\s*packet loss|Lost = \d+ \((\d+(?:\.\d+)?)% loss\)`)
	linuxRTTRE   = regexp.MustCompile(`(?:rtt|round-trip).*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)`)
	winAvgRE     = regexp.MustCompile(`(?i)Average = (\d+)ms`)
	winTimesRE   = regexp.MustCompile(`(?i)time[=<](\d+)ms`)
)

func parsePingOutput(output string) (pingMetrics, error) {
	var metrics pingMetrics
	lossMatch := packetLossRE.FindStringSubmatch(output)
	if len(lossMatch) == 0 {
		return metrics, errors.New("could not parse ping packet loss")
	}
	lossValue := lossMatch[1]
	if lossValue == "" {
		lossValue = lossMatch[2]
	}
	loss, err := strconv.ParseFloat(lossValue, 64)
	if err != nil {
		return metrics, err
	}
	metrics.LossPercent = loss

	if match := linuxRTTRE.FindStringSubmatch(output); len(match) == 5 {
		avg, _ := strconv.ParseFloat(match[2], 64)
		mdev, _ := strconv.ParseFloat(match[4], 64)
		metrics.AvgMS = avg
		metrics.JitterMS = mdev
		return metrics, nil
	}
	if match := winAvgRE.FindStringSubmatch(output); len(match) == 2 {
		avg, _ := strconv.ParseFloat(match[1], 64)
		metrics.AvgMS = avg
		metrics.JitterMS = estimateJitter(output)
		return metrics, nil
	}
	if loss >= 100 {
		return metrics, nil
	}
	return metrics, errors.New("could not parse ping latency")
}

func estimateJitter(output string) float64 {
	matches := winTimesRE.FindAllStringSubmatch(output, -1)
	if len(matches) < 2 {
		return 0
	}
	values := make([]float64, 0, len(matches))
	for _, match := range matches {
		value, err := strconv.ParseFloat(match[1], 64)
		if err == nil {
			values = append(values, value)
		}
	}
	if len(values) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(values); i++ {
		total += math.Abs(values[i] - values[i-1])
	}
	return total / float64(len(values)-1)
}

func ResolveGateway() string {
	candidates := []string{"ip", "route", "show", "default"}
	if _, err := exec.LookPath("ip"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, candidates[0], candidates[1:]...).Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) && net.ParseIP(fields[i+1]) != nil {
			return fields[i+1]
		}
	}
	return ""
}
