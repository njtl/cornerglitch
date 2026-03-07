package atomic

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cornerglitch/internal/audit"
)

// ---------------------------------------------------------------------------
// Audit log integration tests — verify the audit API endpoint returns correct
// data for actions performed through the admin API, including filtering and
// pagination.
// ---------------------------------------------------------------------------

// initAudit sets up a fresh audit logger for testing.
func initAudit(t *testing.T) {
	t.Helper()
	audit.Init(nil) // in-memory only, no DB
}

func TestAudit_FeatureToggleGeneratesEntry(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)
	resetAll(t)

	// Toggle a feature off
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "labyrinth",
		"enabled": false,
	})

	// Query audit log via API
	resp := apiGet(t, mux, "/admin/api/audit?limit=10&action=feature")
	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatalf("expected entries array, got %T", resp["entries"])
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 audit entry for feature toggle")
	}

	// Verify the entry has correct fields
	entry := entries[0].(map[string]interface{})
	if entry["action"] != "feature.toggle" {
		t.Errorf("action = %q, want %q", entry["action"], "feature.toggle")
	}
	if entry["actor"] != "admin" {
		t.Errorf("actor = %q, want %q", entry["actor"], "admin")
	}
}

func TestAudit_ConfigChangeGeneratesEntry(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)
	resetAll(t)

	// Change a config value
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "error_rate_multiplier",
		"value": 3.5,
	})

	// Query audit log via API
	resp := apiGet(t, mux, "/admin/api/audit?limit=10&action=config")
	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatalf("expected entries array, got %T", resp["entries"])
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 audit entry for config change")
	}

	entry := entries[0].(map[string]interface{})
	if entry["action"] != "config.change" {
		t.Errorf("action = %q, want %q", entry["action"], "config.change")
	}
}

func TestAudit_VulnGroupToggleGeneratesEntry(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)
	resetAll(t)

	// Toggle a vuln group off
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": false,
	})

	// Query audit log via API
	resp := apiGet(t, mux, "/admin/api/audit?limit=10&action=vuln")
	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatalf("expected entries array, got %T", resp["entries"])
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 audit entry for vuln toggle")
	}

	// Check that at least one entry has vuln.group_toggle action
	found := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] == "vuln.group_toggle" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one vuln.group_toggle entry")
	}
}

func TestAudit_APIEndpointReturnsEntries(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	// Create some entries
	audit.Log("admin", "config.change", "admin_config.error_rate", 1.0, 2.0, nil)
	audit.LogSystem("system.test", "system.lifecycle", nil)
	audit.LogEntry(audit.Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		Status:   "error",
		ClientIP: "10.0.0.1",
	})

	// GET /admin/api/audit
	resp := apiGet(t, mux, "/admin/api/audit?limit=50")

	// Verify structure
	total, ok := resp["total"].(float64)
	if !ok {
		t.Fatalf("expected total as number, got %T", resp["total"])
	}
	if total < 3 {
		t.Errorf("expected total >= 3, got %v", total)
	}

	entries := resp["entries"].([]interface{})
	if len(entries) < 3 {
		t.Errorf("expected >= 3 entries, got %d", len(entries))
	}

	// Verify filters are populated
	filters, ok := resp["filters"].(map[string]interface{})
	if !ok {
		t.Fatal("expected filters object")
	}
	actors := filters["actors"].([]interface{})
	if len(actors) < 2 {
		t.Errorf("expected at least 2 distinct actors, got %d", len(actors))
	}
}

func TestAudit_FilterByActor(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	audit.Log("admin", "test.action1", "res1", nil, nil, nil)
	audit.LogSystem("test.action2", "res2", nil)

	resp := apiGet(t, mux, "/admin/api/audit?actor=system&limit=50")
	entries := resp["entries"].([]interface{})
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["actor"] != "system" {
			t.Errorf("expected actor=system, got %q", entry["actor"])
		}
	}
}

func TestAudit_FilterByAction(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	audit.Log("admin", "config.change", "res1", nil, nil, nil)
	audit.Log("admin", "config.import", "res2", nil, nil, nil)
	audit.Log("admin", "feature.toggle", "res3", nil, nil, nil)

	// Prefix match on "config"
	resp := apiGet(t, mux, "/admin/api/audit?action=config&limit=50")
	total := resp["total"].(float64)
	if total != 2 {
		t.Errorf("expected 2 entries for action prefix 'config', got %v", total)
	}
}

func TestAudit_FilterByStatus(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	audit.Log("admin", "test.action", "res", nil, nil, nil) // success
	audit.LogEntry(audit.Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		Status:   "error",
	})

	resp := apiGet(t, mux, "/admin/api/audit?status=error&limit=50")
	total := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected 1 error entry, got %v", total)
	}
}

func TestAudit_Pagination(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	// Create 10 entries
	for i := 0; i < 10; i++ {
		audit.Log("admin", "page.test", "resource", nil, nil, nil)
	}

	// Page 1
	r1 := apiGet(t, mux, "/admin/api/audit?limit=3&offset=0")
	entries1 := r1["entries"].([]interface{})
	if len(entries1) != 3 {
		t.Fatalf("expected 3 entries on page 1, got %d", len(entries1))
	}
	total := r1["total"].(float64)
	if total != 10 {
		t.Errorf("expected total=10, got %v", total)
	}

	// Page 2
	r2 := apiGet(t, mux, "/admin/api/audit?limit=3&offset=3")
	entries2 := r2["entries"].([]interface{})
	if len(entries2) != 3 {
		t.Fatalf("expected 3 entries on page 2, got %d", len(entries2))
	}

	// Verify different entries
	id1 := entries1[0].(map[string]interface{})["id"]
	id2 := entries2[0].(map[string]interface{})["id"]
	if id1 == id2 {
		t.Error("expected different entries on different pages")
	}
}

func TestAudit_FilterByTimeRange(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	audit.Log("admin", "old.action", "resource", nil, nil, nil)
	time.Sleep(10 * time.Millisecond)
	cutoff := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	audit.Log("admin", "new.action", "resource", nil, nil, nil)

	// Only entries after cutoff
	resp := apiGet(t, mux, "/admin/api/audit?from="+cutoff.Format(time.RFC3339Nano)+"&limit=50")
	entries := resp["entries"].([]interface{})
	total := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected 1 entry after cutoff, got %v", total)
	}
	if len(entries) > 0 {
		entry := entries[0].(map[string]interface{})
		if entry["action"] != "new.action" {
			t.Errorf("expected new.action, got %q", entry["action"])
		}
	}
}

func TestAudit_JSONFieldNames(t *testing.T) {
	// Verify Entry JSON tags use snake_case
	e := audit.Entry{
		ID:        1,
		Timestamp: time.Now(),
		Actor:     "admin",
		Action:    "test",
		Resource:  "res",
		OldValue:  "old",
		NewValue:  "new",
		Details:   map[string]interface{}{"k": "v"},
		ClientIP:  "10.0.0.1",
		Status:    "success",
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	requiredFields := []string{"id", "timestamp", "actor", "action", "resource", "old_value", "new_value", "details", "client_ip", "status"}
	for _, f := range requiredFields {
		if _, ok := raw[f]; !ok {
			t.Errorf("missing snake_case JSON field %q", f)
		}
	}
}

func TestAudit_APIResponseStructure(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)

	audit.Log("admin", "test", "resource", nil, nil, nil)

	resp := apiGet(t, mux, "/admin/api/audit?limit=10")

	// Verify required response fields
	for _, field := range []string{"entries", "total", "limit", "offset", "filters"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("missing response field %q", field)
		}
	}

	// Verify filters sub-structure
	filters := resp["filters"].(map[string]interface{})
	for _, field := range []string{"actors", "actions", "statuses"} {
		if _, ok := filters[field]; !ok {
			t.Errorf("missing filters field %q", field)
		}
	}
}

func TestAudit_NightmareToggleGeneratesEntry(t *testing.T) {
	mux := setupTestEnv(t)
	initAudit(t)
	resetAll(t)

	// Enable nightmare for server
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": true,
	})

	resp := apiGet(t, mux, "/admin/api/audit?limit=10&action=nightmare")
	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatalf("expected entries array, got %T", resp["entries"])
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 audit entry for nightmare toggle")
	}

	// Check any entry has a nightmare action
	found := false
	for _, e := range entries {
		entry := e.(map[string]interface{})
		action, _ := entry["action"].(string)
		if len(action) >= 9 && action[:9] == "nightmare" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one nightmare.* audit entry")
	}

	// Clean up
	resetNightmareState(t)
}
