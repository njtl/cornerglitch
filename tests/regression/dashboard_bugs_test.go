// Package regression tests for dashboard bugs found on 2026-03-02.
//
// Bug 2: Traffic counters show "0 B" — apiMetrics() missing byte counter fields
// Bug 3: Audit log records "true→true" entries — no old!=new guard
// Bug 5: Method Distribution text overflow — no flex-wrap on legend container
//
// These tests verify the fixes remain in place.
package regression

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cornerglitch/internal/adaptive"
	"github.com/cornerglitch/internal/audit"
	"github.com/cornerglitch/internal/dashboard"
	"github.com/cornerglitch/internal/fingerprint"
	"github.com/cornerglitch/internal/metrics"
)

func init() {
	// Ensure audit logger is initialized for tests
	audit.Init(nil)
}

// ---------------------------------------------------------------------------
// Bug 2: Traffic counters show "0 B"
//
// Root cause: apiMetrics() in server.go did not include byte counter fields
// (total_request_bytes, total_response_bytes, session_request_bytes,
// session_response_bytes) in the JSON response, even though the collector
// tracked them.
//
// Fix: Added the four byte counter fields to the metrics API response.
//
// This test verifies the metrics API returns all byte counter fields.
// ---------------------------------------------------------------------------

func TestRegression_TrafficBytesInMetricsAPI(t *testing.T) {
	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	// Use the full server which registers /api/metrics on its own mux
	srv := dashboard.NewServer(collector, fp, adapt, 0)

	// Record some traffic to make counters non-zero
	collector.Record(metrics.RequestRecord{
		Method:        "GET",
		Path:          "/test",
		StatusCode:    200,
		RequestBytes:  1024,
		ResponseBytes: 4096,
		Latency:       time.Millisecond,
	})

	// Access the server's internal handler directly
	req := httptest.NewRequest("GET", "/api/metrics", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("GET /api/metrics returned %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal metrics: %v", err)
	}

	// These four fields MUST be present (this is what was missing)
	requiredFields := []string{
		"total_request_bytes",
		"total_response_bytes",
		"session_request_bytes",
		"session_response_bytes",
	}
	for _, field := range requiredFields {
		val, ok := resp[field]
		if !ok {
			t.Errorf("metrics response missing field %q", field)
			continue
		}
		// After recording 1 request, values should be > 0
		if f, ok := val.(float64); ok && f <= 0 {
			t.Errorf("metrics field %q = %v, expected > 0 after recording traffic", field, f)
		}
	}

	// Verify the specific values match what we recorded
	if v, ok := resp["total_request_bytes"].(float64); ok {
		if v != 1024 {
			t.Errorf("total_request_bytes = %v, want 1024", v)
		}
	}
	if v, ok := resp["total_response_bytes"].(float64); ok {
		if v != 4096 {
			t.Errorf("total_response_bytes = %v, want 4096", v)
		}
	}
}

// ---------------------------------------------------------------------------
// Bug 3: Audit log records "true→true" entries
//
// Root cause: admin_routes.go always called audit.Log() for feature toggles,
// even when the old value == new value (e.g., enabling an already-enabled
// feature during nightmare SetAll).
//
// Fix: Added `if old != req.Enabled` guard before the audit.Log call.
//
// This test verifies that toggling a feature to its current value does NOT
// generate an audit entry.
// ---------------------------------------------------------------------------

func TestRegression_AuditNoEntryOnSameValue(t *testing.T) {
	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	mux := http.NewServeMux()
	dashboard.RegisterAdminRoutes(mux, srv)

	audit.Init(nil) // fresh in-memory audit log

	// Ensure labyrinth is enabled (default)
	flags := dashboard.GetFeatureFlags()
	flags.Set("labyrinth", true)

	// Toggle labyrinth to true again (same value)
	body := `{"feature":"labyrinth","enabled":true}`
	req := httptest.NewRequest("POST", "/admin/api/features",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("POST /admin/api/features returned %d: %s", rec.Code, rec.Body.String())
	}

	// Check audit log — should NOT have an entry for this toggle
	time.Sleep(10 * time.Millisecond) // give audit a moment
	result := audit.Query(audit.QueryOpts{Limit: 100, Action: "feature.toggle"})
	for _, e := range result.Entries {
		if e.Resource == "feature_flags.labyrinth" {
			old, _ := json.Marshal(e.OldValue)
			nv, _ := json.Marshal(e.NewValue)
			if string(old) == "true" && string(nv) == "true" {
				t.Errorf("audit logged true→true toggle for labyrinth — should be suppressed")
			}
		}
	}

	// Now toggle to a DIFFERENT value — this SHOULD generate an entry
	body2 := `{"feature":"labyrinth","enabled":false}`
	req2 := httptest.NewRequest("POST", "/admin/api/features",
		strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	time.Sleep(10 * time.Millisecond)
	result2 := audit.Query(audit.QueryOpts{Limit: 100, Action: "feature.toggle"})
	found := false
	for _, e := range result2.Entries {
		if e.Resource == "feature_flags.labyrinth" {
			old, _ := json.Marshal(e.OldValue)
			nv, _ := json.Marshal(e.NewValue)
			if string(old) == "true" && string(nv) == "false" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("audit did NOT log true→false toggle for labyrinth — should have an entry")
	}

	// Reset
	flags.Set("labyrinth", true)
}

// ---------------------------------------------------------------------------
// Bug 2 supplementary: Verify ALL standard metrics fields are present
//
// This ensures we don't lose any metrics field in future refactors.
// ---------------------------------------------------------------------------

func TestRegression_MetricsAPIFieldCompleteness(t *testing.T) {
	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	srv := dashboard.NewServer(collector, fp, adapt, 0)

	req := httptest.NewRequest("GET", "/api/metrics", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	// All expected fields the dashboard JS reads
	expectedFields := []string{
		"uptime_seconds",
		"total_requests",
		"total_errors",
		"total_2xx",
		"total_4xx",
		"total_5xx",
		"total_delayed",
		"total_labyrinth",
		"active_connections",
		"unique_clients",
		"current_rps",
		"total_request_bytes",
		"total_response_bytes",
		"session_request_bytes",
		"session_response_bytes",
	}
	for _, field := range expectedFields {
		if _, ok := resp[field]; !ok {
			t.Errorf("metrics response missing expected field %q", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Bug 3 supplementary: Verify audit entries are generated for ACTUAL changes
//
// Makes sure the guard doesn't accidentally suppress real changes.
// ---------------------------------------------------------------------------

func TestRegression_AuditEntryOnActualChange(t *testing.T) {
	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	mux := http.NewServeMux()
	dashboard.RegisterAdminRoutes(mux, srv)

	audit.Init(nil)
	flags := dashboard.GetFeatureFlags()

	// Test toggling through all states: on→off→on
	testFeatures := []string{"honeypot", "captcha", "spider", "health", "privacy"}
	for _, feat := range testFeatures {
		flags.Set(feat, true) // ensure starting state

		// Toggle off
		post(t, mux, "/admin/api/features", map[string]interface{}{
			"feature": feat, "enabled": false,
		})

		// Toggle back on
		post(t, mux, "/admin/api/features", map[string]interface{}{
			"feature": feat, "enabled": true,
		})
	}

	time.Sleep(10 * time.Millisecond)
	result := audit.Query(audit.QueryOpts{Limit: 200, Action: "feature.toggle"})

	// Each feature should have exactly 2 entries (on→off, off→on)
	for _, feat := range testFeatures {
		count := 0
		for _, e := range result.Entries {
			if e.Resource == "feature_flags."+feat {
				count++
			}
		}
		if count != 2 {
			t.Errorf("feature %q: expected 2 audit entries, got %d", feat, count)
		}
	}
}

// post is a helper for sending JSON POST requests.
func post(t *testing.T, mux *http.ServeMux, path string, body interface{}) map[string]interface{} {
	t.Helper()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	resp := rec.Result()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	return result
}
