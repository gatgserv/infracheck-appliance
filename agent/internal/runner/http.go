package runner

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

type HTTPTarget struct {
	SiteID         string
	Name           string
	URL            string
	ExpectedStatus int
	ExpectedText   string
}

type HTTPRunner struct{}

func (r HTTPRunner) Run(ctx context.Context, target HTTPTarget) storage.HTTPResult {
	result := storage.HTTPResult{
		Timestamp: time.Now().UTC(),
		SiteID:    target.SiteID,
		Name:      target.Name,
		URL:       target.URL,
		TLSValid:  true,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "infracheck-agent/0.1")

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer transport.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Do(req)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		result.Error = err.Error()
		result.TLSValid = !strings.Contains(strings.ToLower(err.Error()), "certificate")
		return result
	}
	defer resp.Body.Close()

	result.Up = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.StatusCode = resp.StatusCode
	if target.ExpectedStatus > 0 {
		result.Up = resp.StatusCode == target.ExpectedStatus
	}
	if target.ExpectedText != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			result.Up = false
			result.Error = err.Error()
		} else if !strings.Contains(string(body), target.ExpectedText) {
			result.Up = false
			result.Error = "expected text not found"
		}
	}
	if resp.TLS != nil {
		result.TLSValid = true
		result.TLSDaysUntilExpiry = daysUntilExpiry(resp.TLS)
	}
	if !result.Up {
		result.Error = resp.Status
	}
	return result
}

func daysUntilExpiry(state *tls.ConnectionState) int {
	if state == nil || len(state.PeerCertificates) == 0 {
		return 0
	}
	duration := time.Until(state.PeerCertificates[0].NotAfter)
	return int(duration.Hours() / 24)
}
