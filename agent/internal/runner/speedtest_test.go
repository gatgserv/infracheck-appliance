package runner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSpeedtestRunnerMeasuresDownloadAndUpload(t *testing.T) {
	var uploaded int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			_, _ = w.Write(make([]byte, 1024*64))
		case "/up":
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				t.Errorf("failed to read upload body: %v", err)
			}
			uploaded = n
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := SpeedtestRunner{}.Run(context.Background(), SpeedtestTarget{
		SiteID:        "site-1",
		Name:          "local",
		DownloadURL:   server.URL + "/down",
		UploadURL:     server.URL + "/up",
		DownloadBytes: 1024 * 64,
		UploadBytes:   1024 * 16,
	})

	if !result.Success {
		t.Fatalf("expected successful speedtest, got download=%q upload=%q", result.DownloadError, result.UploadError)
	}
	if result.DownloadBytes != 1024*64 {
		t.Fatalf("expected capped download bytes, got %d", result.DownloadBytes)
	}
	if uploaded != 1024*16 || result.UploadBytes != 1024*16 {
		t.Fatalf("expected upload bytes to be recorded, uploaded=%d result=%d", uploaded, result.UploadBytes)
	}
	if result.DownloadMbps <= 0 || result.UploadMbps <= 0 {
		t.Fatalf("expected positive throughput, download=%f upload=%f", result.DownloadMbps, result.UploadMbps)
	}
}

func TestSpeedtestRunnerRecordsDownloadFailure(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	result := SpeedtestRunner{}.Run(context.Background(), SpeedtestTarget{
		SiteID:        "site-1",
		Name:          "local",
		DownloadURL:   server.URL + "/missing",
		DownloadBytes: 1024,
	})

	if result.Success {
		t.Fatal("expected failed speedtest")
	}
	if result.DownloadError == "" {
		t.Fatal("expected download error")
	}
}
