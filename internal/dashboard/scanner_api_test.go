package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltinScannerModules(t *testing.T) {
	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("GET", "/admin/api/scanner/builtin/modules", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("modules status: %d", rec.Code)
	}

	var modules []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &modules)
	if len(modules) < 3 {
		t.Errorf("expected at least 3 modules, got %d", len(modules))
	}

	// Verify known modules exist
	names := map[string]bool{}
	for _, m := range modules {
		if name, ok := m["name"].(string); ok {
			names[name] = true
		}
	}
	for _, expected := range []string{"owasp", "injection", "fuzzing", "protocol", "auth"} {
		if !names[expected] {
			t.Errorf("missing module: %s", expected)
		}
	}
}

func TestBuiltinScannerStatus_Idle(t *testing.T) {
	// Reset state
	builtinMu.Lock()
	builtinState = "idle"
	builtinEngine = nil
	builtinReport = nil
	builtinMu.Unlock()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("GET", "/admin/api/scanner/builtin/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status code: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["state"] != "idle" {
		t.Errorf("expected state=idle, got %v", resp["state"])
	}
}

func TestBuiltinScannerResults_NoResults(t *testing.T) {
	builtinMu.Lock()
	builtinReport = nil
	builtinMu.Unlock()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("GET", "/admin/api/scanner/builtin/results", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("results status: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != false {
		t.Errorf("expected ok=false when no results, got %v", resp["ok"])
	}
}

func TestBuiltinScannerHistory_Empty(t *testing.T) {
	builtinHistoryMu.Lock()
	builtinHistory = nil
	builtinHistoryMu.Unlock()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("GET", "/admin/api/scanner/builtin/history", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("history status: %d", rec.Code)
	}

	var resp []interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp) != 0 {
		t.Errorf("expected empty history, got %d entries", len(resp))
	}
}

func TestBuiltinScannerStop_NotRunning(t *testing.T) {
	builtinMu.Lock()
	builtinState = "idle"
	builtinEngine = nil
	builtinCancel = nil
	builtinMu.Unlock()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("POST", "/admin/api/scanner/builtin/stop", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("stop status: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("stop should return ok=true even when not running")
	}
}

func TestBuiltinScannerRun_BadJSON(t *testing.T) {
	builtinMu.Lock()
	builtinState = "idle"
	builtinMu.Unlock()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("POST", "/admin/api/scanner/builtin/run", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != false {
		t.Errorf("expected ok=false for bad JSON")
	}
}

func TestBuiltinScannerRun_DoubleRun(t *testing.T) {
	builtinMu.Lock()
	builtinState = "running"
	builtinMu.Unlock()
	defer func() {
		builtinMu.Lock()
		builtinState = "idle"
		builtinMu.Unlock()
	}()

	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	body := `{"profile":"compliance","target":"http://localhost:8765"}`
	req := httptest.NewRequest("POST", "/admin/api/scanner/builtin/run", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != false {
		t.Errorf("expected ok=false for double run")
	}
	if resp["error"] != "scan already running" {
		t.Errorf("expected 'scan already running', got %v", resp["error"])
	}
}

func TestBuiltinScannerRun_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	RegisterBuiltinScannerRoutes(mux)

	req := httptest.NewRequest("GET", "/admin/api/scanner/builtin/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}
