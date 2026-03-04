package budgettrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeTarpit(t *testing.T) {
	if testing.Short() {
		t.Skip("tarpit test involves real delays")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	status, trapType := applyTarpit(w, r, 1, seedRNG("test", "/test"))
	if status != http.StatusOK {
		t.Errorf("tarpit status: got %d, want 200", status)
	}
	if trapType != "tarpit" {
		t.Errorf("trap type: got %q, want tarpit", trapType)
	}
}

func TestServeInfinitePagination(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/users?page=1", nil)
	ServeInfinitePagination(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("pagination status: got %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("pagination content-type: got %q, want application/json", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "\"total\"") {
		t.Error("pagination response should contain total field")
	}
	if !strings.Contains(body, "\"next\"") {
		t.Error("pagination response should contain next link")
	}
	if !strings.Contains(body, "\"data\"") {
		t.Error("pagination response should contain data array")
	}
}

func TestServeExpandedContent(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/internal/reports/123", nil)
	ServeExpandedContent(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expansion status: got %d, want 200", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<a href=") {
		t.Error("expansion response should contain links")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("expansion response should be valid HTML")
	}
}

func TestServeStreamingBait(t *testing.T) {
	w := httptest.NewRecorder()
	// Use a short-lived context so the streaming bait cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest("GET", "/data/export", nil).WithContext(ctx)
	ServeStreamingBait(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("streaming bait status: got %d, want 200", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("streaming bait should return HTML")
	}
}

func TestGenerateNormalPage(t *testing.T) {
	rng := seedRNG("test", "/test")
	page := generateNormalPage(rng)

	if !strings.Contains(page, "<!DOCTYPE html>") {
		t.Error("normal page should start with DOCTYPE")
	}
	if !strings.Contains(page, "Acme Corp") {
		t.Error("normal page should use Acme Corp branding")
	}
}

func TestGenerateExpansionPage(t *testing.T) {
	rng := seedRNG("test", "/test")
	page := generateExpansionPage(rng)

	if !strings.Contains(page, "<!DOCTYPE html>") {
		t.Error("expansion page should start with DOCTYPE")
	}
	// Should contain many links
	linkCount := strings.Count(page, "<a href=")
	if linkCount < 20 {
		t.Errorf("expansion page should have many links, got %d", linkCount)
	}
}
