package runner

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type SpeedtestTarget struct {
	SiteID        string
	Name          string
	DownloadURL   string
	UploadURL     string
	DownloadBytes int64
	UploadBytes   int64
}

type SpeedtestRunner struct{}

func (r SpeedtestRunner) Run(ctx context.Context, target SpeedtestTarget) storage.SpeedtestResult {
	result := storage.SpeedtestResult{
		Timestamp:     time.Now().UTC(),
		SiteID:        target.SiteID,
		TargetName:    target.Name,
		DownloadURL:   target.DownloadURL,
		UploadURL:     target.UploadURL,
		DownloadBytes: target.DownloadBytes,
		UploadBytes:   target.UploadBytes,
	}
	result.DownloadMbps, result.DownloadDurationMS, result.DownloadBytes, result.DownloadError = measureDownload(ctx, target.DownloadURL, target.DownloadBytes)
	if target.UploadURL != "" && target.UploadBytes > 0 {
		result.UploadMbps, result.UploadDurationMS, result.UploadBytes, result.UploadError = measureUpload(ctx, target.UploadURL, target.UploadBytes)
	}
	result.Success = result.DownloadError == "" && result.UploadError == ""
	return result
}

func measureDownload(ctx context.Context, url string, limit int64) (float64, float64, int64, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, 0, err.Error()
	}
	req.Header.Set("User-Agent", "infracheck-agent/0.1")
	client := &http.Client{}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, float64(time.Since(start).Microseconds()) / 1000, 0, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, float64(time.Since(start).Microseconds()) / 1000, 0, resp.Status
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	duration := time.Since(start)
	if err != nil {
		return 0, float64(duration.Microseconds()) / 1000, n, err.Error()
	}
	return mbps(n, duration), float64(duration.Microseconds()) / 1000, n, ""
}

func measureUpload(ctx context.Context, url string, size int64) (float64, float64, int64, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, io.LimitReader(zeroReader{}, size))
	if err != nil {
		return 0, 0, 0, err.Error()
	}
	req.Header.Set("User-Agent", "infracheck-agent/0.1")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = size
	client := &http.Client{}
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return 0, float64(duration.Microseconds()) / 1000, 0, err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, float64(duration.Microseconds()) / 1000, size, resp.Status
	}
	return mbps(size, duration), float64(duration.Microseconds()) / 1000, size, ""
}

func mbps(bytes int64, duration time.Duration) float64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return (float64(bytes) * 8) / duration.Seconds() / 1_000_000
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
