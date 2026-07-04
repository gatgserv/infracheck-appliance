package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infracheck/infracheck/container/agent/internal/config"
)

func TestMaybeProtectReadAllowsPublicReads(t *testing.T) {
	a := &Agent{cfg: config.Default()}
	handler := a.maybeProtectRead(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected public read to pass, got %d", rec.Code)
	}
}

func TestMaybeProtectReadRequiresTokenWhenPrivate(t *testing.T) {
	cfg := config.Default()
	cfg.Security.AllowPublicReads = false
	cfg.Security.ReadToken = "read-token"
	a := &Agent{cfg: cfg}
	handler := a.maybeProtectRead(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing token to fail, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected read token to pass, got %d", rec.Code)
	}
}

func TestMaybeProtectMetricsIndependentOfPublicReads(t *testing.T) {
	cfg := config.Default()
	cfg.Security.AllowPublicReads = true
	cfg.Security.ProtectMetrics = true
	cfg.Security.AdminToken = "admin-token"
	a := &Agent{cfg: cfg}
	handler := a.maybeProtectMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected metrics without token to fail, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("X-Infracheck-Token", "admin-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected metrics with admin token to pass, got %d", rec.Code)
	}
}

func TestRequireAdminRejectsReadToken(t *testing.T) {
	cfg := config.Default()
	cfg.Security.ReadToken = "read-token"
	cfg.Security.AdminToken = "admin-token"
	a := &Agent{cfg: cfg}
	handler := a.requireAdmin(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tests/ping/run", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected read token to fail admin route, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/tests/ping/run", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected admin token to pass, got %d", rec.Code)
	}
}

func TestRouterSetsSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, req)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
		"Cache-Control":          "no-store",
	}
	for header, want := range expected {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("expected %s %q, got %q", header, want, got)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("expected content security policy header")
	}
}
