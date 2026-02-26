package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// testDSN returns a PostgreSQL DSN for testing.
func testDSN() string {
	if dsn := os.Getenv("GLITCH_TEST_DB_URL"); dsn != "" {
		return dsn
	}
	return DefaultDSN
}

var (
	sharedDB   *sql.DB
	sharedOnce sync.Once
	sharedErr  error
)

// testStore creates a Store for testing, cleaning tables between tests.
// Uses a shared DB connection and ensures migrations are applied once.
// Skips the test if no database is available.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := testDSN()

	sharedOnce.Do(func() {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			sharedErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			sharedErr = fmt.Errorf("ping: %w", err)
			return
		}
		if err := Migrate(ctx, db); err != nil {
			db.Close()
			sharedErr = fmt.Errorf("migrate: %w", err)
			return
		}
		sharedDB = db
	})
	if sharedErr != nil {
		t.Skipf("cannot connect to postgres: %v", sharedErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Clean all data tables (but not schema_migrations)
	for _, tbl := range []string{"request_log", "client_profiles", "metrics_snapshots", "scan_history", "config_versions"} {
		if _, err := sharedDB.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", tbl)); err != nil {
			t.Fatalf("clean table %s: %v", tbl, err)
		}
	}

	return &Store{db: sharedDB, dsn: dsn}
}

// ---------------------------------------------------------------------------
// Migration tests
// ---------------------------------------------------------------------------

func TestMigrate_Idempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Running migrations again should be a no-op
	if err := Migrate(ctx, s.db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// And a third time
	if err := Migrate(ctx, s.db); err != nil {
		t.Fatalf("third migrate: %v", err)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		filename string
		want     int
		wantErr  bool
	}{
		{"001_initial.sql", 1, false},
		{"002_add_indexes.sql", 2, false},
		{"100_big_migration.sql", 100, false},
		{"bad.sql", 0, true},
		{"notanumber_desc.sql", 0, true},
	}
	for _, tt := range tests {
		v, err := parseVersion(tt.filename)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseVersion(%q) error = %v, wantErr %v", tt.filename, err, tt.wantErr)
			continue
		}
		if v != tt.want {
			t.Errorf("parseVersion(%q) = %d, want %d", tt.filename, v, tt.want)
		}
	}
}

func TestStripTransactionStatements(t *testing.T) {
	input := "BEGIN;\nCREATE TABLE foo (id INT);\nCOMMIT;\n"
	result := stripTransactionStatements(input)
	if result == input {
		t.Error("expected BEGIN/COMMIT to be stripped")
	}
	if contains(result, "BEGIN;") || contains(result, "COMMIT;") {
		t.Errorf("result still contains transaction statements: %q", result)
	}
	if !contains(result, "CREATE TABLE foo") {
		t.Errorf("result missing body: %q", result)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Config versioning tests
// ---------------------------------------------------------------------------

func TestSaveAndLoadConfig(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save config
	data := map[string]interface{}{"key1": "value1", "key2": float64(42)}
	if err := s.SaveConfig(ctx, "test_entity", data); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// Load config
	var loaded map[string]interface{}
	found, err := s.LoadConfig(ctx, "test_entity", &loaded)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !found {
		t.Fatal("LoadConfig: not found")
	}
	if loaded["key1"] != "value1" {
		t.Errorf("key1 = %v, want value1", loaded["key1"])
	}
	if loaded["key2"] != float64(42) {
		t.Errorf("key2 = %v, want 42", loaded["key2"])
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	var loaded map[string]interface{}
	found, err := s.LoadConfig(ctx, "nonexistent", &loaded)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if found {
		t.Error("expected not found for nonexistent entity")
	}
}

func TestConfigVersioning(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save three versions
	for i := 1; i <= 3; i++ {
		data := map[string]int{"version_data": i}
		if err := s.SaveConfig(ctx, "versioned_entity", data); err != nil {
			t.Fatalf("SaveConfig v%d: %v", i, err)
		}
	}

	// Latest should be version 3
	ver, err := s.ConfigVersion(ctx, "versioned_entity")
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver != 3 {
		t.Errorf("ConfigVersion = %d, want 3", ver)
	}

	// LoadConfig should return latest (v3)
	var latest map[string]int
	found, err := s.LoadConfig(ctx, "versioned_entity", &latest)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !found || latest["version_data"] != 3 {
		t.Errorf("LoadConfig latest = %v, want {version_data:3}", latest)
	}

	// LoadConfigVersion should return specific versions
	for i := 1; i <= 3; i++ {
		var specific map[string]int
		found, err := s.LoadConfigVersion(ctx, "versioned_entity", i, &specific)
		if err != nil {
			t.Fatalf("LoadConfigVersion v%d: %v", i, err)
		}
		if !found {
			t.Fatalf("LoadConfigVersion v%d: not found", i)
		}
		if specific["version_data"] != i {
			t.Errorf("LoadConfigVersion v%d = %v, want %d", i, specific["version_data"], i)
		}
	}
}

func TestConfigHistory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save 5 versions
	for i := 1; i <= 5; i++ {
		if err := s.SaveConfig(ctx, "history_entity", map[string]int{"v": i}); err != nil {
			t.Fatalf("SaveConfig v%d: %v", i, err)
		}
	}

	// List history (latest first)
	history, err := s.ListConfigHistory(ctx, "history_entity", 10)
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(history) != 5 {
		t.Fatalf("history length = %d, want 5", len(history))
	}
	// Should be in descending version order
	if history[0].Version != 5 || history[4].Version != 1 {
		t.Errorf("history order wrong: first=%d, last=%d", history[0].Version, history[4].Version)
	}

	// Limit works
	limited, err := s.ListConfigHistory(ctx, "history_entity", 2)
	if err != nil {
		t.Fatalf("ListConfigHistory limit: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limited length = %d, want 2", len(limited))
	}
}

func TestConfigVersion_NoVersions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	ver, err := s.ConfigVersion(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver != 0 {
		t.Errorf("ConfigVersion = %d, want 0 for nonexistent entity", ver)
	}
}

// ---------------------------------------------------------------------------
// Full config export/import tests
// ---------------------------------------------------------------------------

func TestSaveAndLoadFullConfig(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	export := &FullConfigExport{
		Features: map[string]bool{
			"labyrinth": true,
			"honeypot":  false,
		},
		Config: map[string]interface{}{
			"error_rate_multiplier": float64(1.5),
			"content_theme":         "corporate",
		},
		VulnConfig: map[string]interface{}{
			"groups": map[string]interface{}{
				"owasp": true,
			},
		},
		ErrorWeights: map[string]float64{
			"404": 0.3,
			"500": 0.7,
		},
		PageTypeWeights: map[string]float64{
			"html": 0.6,
			"json": 0.4,
		},
	}

	if err := s.SaveFullConfig(ctx, export); err != nil {
		t.Fatalf("SaveFullConfig: %v", err)
	}

	loaded, err := s.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadFullConfig: nil result")
	}

	// Verify features
	if loaded.Features["labyrinth"] != true {
		t.Errorf("labyrinth = %v, want true", loaded.Features["labyrinth"])
	}
	if loaded.Features["honeypot"] != false {
		t.Errorf("honeypot = %v, want false", loaded.Features["honeypot"])
	}

	// Verify config
	if loaded.Config["error_rate_multiplier"] != float64(1.5) {
		t.Errorf("error_rate_multiplier = %v, want 1.5", loaded.Config["error_rate_multiplier"])
	}

	// Verify error weights
	if loaded.ErrorWeights["404"] != 0.3 {
		t.Errorf("error weight 404 = %v, want 0.3", loaded.ErrorWeights["404"])
	}

	// Verify page type weights
	if loaded.PageTypeWeights["html"] != 0.6 {
		t.Errorf("page type weight html = %v, want 0.6", loaded.PageTypeWeights["html"])
	}
}

func TestLoadFullConfig_Empty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	loaded, err := s.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected nil for empty config, got %+v", loaded)
	}
}

func TestSaveFullConfig_WithBlocking(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	export := &FullConfigExport{
		Features: map[string]bool{"test": true},
		Config:   map[string]interface{}{"k": "v"},
		Blocking: map[string]interface{}{
			"enabled": true,
			"rules":   []interface{}{"rule1"},
		},
	}

	if err := s.SaveFullConfig(ctx, export); err != nil {
		t.Fatalf("SaveFullConfig: %v", err)
	}

	loaded, err := s.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded.Blocking == nil {
		t.Fatal("Blocking is nil")
	}
	if loaded.Blocking["enabled"] != true {
		t.Errorf("Blocking.enabled = %v, want true", loaded.Blocking["enabled"])
	}
}

func TestFullConfig_VersionIncrement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save twice
	export1 := &FullConfigExport{
		Features: map[string]bool{"test": true},
		Config:   map[string]interface{}{"v": float64(1)},
	}
	export2 := &FullConfigExport{
		Features: map[string]bool{"test": false},
		Config:   map[string]interface{}{"v": float64(2)},
	}

	if err := s.SaveFullConfig(ctx, export1); err != nil {
		t.Fatalf("SaveFullConfig #1: %v", err)
	}
	if err := s.SaveFullConfig(ctx, export2); err != nil {
		t.Fatalf("SaveFullConfig #2: %v", err)
	}

	// feature_flags should be at version 2
	ver, err := s.ConfigVersion(ctx, "feature_flags")
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver != 2 {
		t.Errorf("feature_flags version = %d, want 2", ver)
	}

	// Latest should have v=2
	loaded, err := s.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded.Features["test"] != false {
		t.Errorf("Features.test = %v, want false", loaded.Features["test"])
	}
}

// ---------------------------------------------------------------------------
// Scan history tests
// ---------------------------------------------------------------------------

func TestSaveScan(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	report := map[string]interface{}{"finding": "test"}
	reportJSON, _ := json.Marshal(report)

	rec := &ScanRecord{
		ScannerName:   "nuclei",
		Status:        "completed",
		Grade:         "B+",
		DetectionRate: 0.85,
		Report:        reportJSON,
	}

	id, err := s.SaveScan(ctx, rec)
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	// Retrieve it
	got, err := s.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got == nil {
		t.Fatal("GetScan: nil")
	}
	if got.ScannerName != "nuclei" {
		t.Errorf("ScannerName = %q, want nuclei", got.ScannerName)
	}
	if got.Grade != "B+" {
		t.Errorf("Grade = %q, want B+", got.Grade)
	}
	if got.DetectionRate != 0.85 {
		t.Errorf("DetectionRate = %v, want 0.85", got.DetectionRate)
	}
}

func TestSaveScanFromReport(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	report := struct {
		Findings int    `json:"findings"`
		Tool     string `json:"tool"`
	}{Findings: 42, Tool: "httpx"}

	id, err := s.SaveScanFromReport(ctx, "httpx", "done", "A", 0.95, report)
	if err != nil {
		t.Fatalf("SaveScanFromReport: %v", err)
	}

	got, err := s.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.ScannerName != "httpx" {
		t.Errorf("ScannerName = %q, want httpx", got.ScannerName)
	}
}

func TestListScans(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert 3 scans
	for i := 0; i < 3; i++ {
		_, err := s.SaveScanFromReport(ctx, fmt.Sprintf("scanner-%d", i), "ok", "", float64(i)*0.3, nil)
		if err != nil {
			t.Fatalf("SaveScanFromReport %d: %v", i, err)
		}
	}

	scans, err := s.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("ListScans count = %d, want 3", len(scans))
	}

	// Limit
	limited, err := s.ListScans(ctx, 2)
	if err != nil {
		t.Fatalf("ListScans limited: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limited count = %d, want 2", len(limited))
	}
}

func TestCountScans(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	count, err := s.CountScans(ctx)
	if err != nil {
		t.Fatalf("CountScans: %v", err)
	}
	if count != 0 {
		t.Errorf("initial count = %d, want 0", count)
	}

	s.SaveScanFromReport(ctx, "test", "ok", "", 0.5, nil)
	count, err = s.CountScans(ctx)
	if err != nil {
		t.Fatalf("CountScans: %v", err)
	}
	if count != 1 {
		t.Errorf("count after insert = %d, want 1", count)
	}
}

func TestGetScan_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	got, err := s.GetScan(ctx, 999999)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for nonexistent scan, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Metrics snapshot tests
// ---------------------------------------------------------------------------

func TestSaveMetricsSnapshot(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	snap := &MetricsSnapshot{
		TotalRequests:     1000,
		TotalErrors:       50,
		Total2xx:          800,
		Total4xx:          100,
		Total5xx:          50,
		ActiveConnections: 25,
		UniqueClients:     10,
		SnapshotData:      json.RawMessage(`{"top_paths":["/api","/health"]}`),
	}

	id, err := s.SaveMetricsSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("SaveMetricsSnapshot: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	// List and verify
	snapshots, err := s.ListMetricsSnapshots(ctx, 10)
	if err != nil {
		t.Fatalf("ListMetricsSnapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshot count = %d, want 1", len(snapshots))
	}
	if snapshots[0].TotalRequests != 1000 {
		t.Errorf("TotalRequests = %d, want 1000", snapshots[0].TotalRequests)
	}
	if snapshots[0].UniqueClients != 10 {
		t.Errorf("UniqueClients = %d, want 10", snapshots[0].UniqueClients)
	}
}

func TestMetricsInRange(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save a snapshot
	snap := &MetricsSnapshot{TotalRequests: 100, Total2xx: 90}
	_, err := s.SaveMetricsSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("SaveMetricsSnapshot: %v", err)
	}

	// Query with wide range (should find it)
	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	results, err := s.GetMetricsInRange(ctx, from, to, 10)
	if err != nil {
		t.Fatalf("GetMetricsInRange: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("results count = %d, want 1", len(results))
	}

	// Query with past range (should not find it)
	from2 := time.Now().Add(-2 * time.Hour)
	to2 := time.Now().Add(-1 * time.Hour)
	results2, err := s.GetMetricsInRange(ctx, from2, to2, 10)
	if err != nil {
		t.Fatalf("GetMetricsInRange past: %v", err)
	}
	if len(results2) != 0 {
		t.Errorf("past range count = %d, want 0", len(results2))
	}
}

// ---------------------------------------------------------------------------
// Client profile tests
// ---------------------------------------------------------------------------

func TestSaveAndLoadClientProfile(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	profileData, _ := json.Marshal(map[string]interface{}{
		"paths_visited": 42,
		"attack_score":  0.7,
	})

	rec := &ClientProfileRecord{
		ClientID:      "client-abc-123",
		TotalRequests: 500,
		BotScore:      75,
		AdaptiveMode:  "aggressive",
		ProfileData:   profileData,
	}

	if err := s.SaveClientProfile(ctx, rec); err != nil {
		t.Fatalf("SaveClientProfile: %v", err)
	}

	// Load it
	loaded, err := s.LoadClientProfile(ctx, "client-abc-123")
	if err != nil {
		t.Fatalf("LoadClientProfile: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadClientProfile: nil")
	}
	if loaded.ClientID != "client-abc-123" {
		t.Errorf("ClientID = %q, want client-abc-123", loaded.ClientID)
	}
	if loaded.BotScore != 75 {
		t.Errorf("BotScore = %d, want 75", loaded.BotScore)
	}
	if loaded.Version != 1 {
		t.Errorf("Version = %d, want 1", loaded.Version)
	}
}

func TestClientProfile_Versioning(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Save 3 versions for the same client
	for i := 1; i <= 3; i++ {
		rec := &ClientProfileRecord{
			ClientID:      "versioned-client",
			TotalRequests: int64(i * 100),
			BotScore:      i * 10,
			AdaptiveMode:  fmt.Sprintf("mode-%d", i),
			ProfileData:   json.RawMessage(`{}`),
		}
		if err := s.SaveClientProfile(ctx, rec); err != nil {
			t.Fatalf("SaveClientProfile v%d: %v", i, err)
		}
	}

	// Latest version should be #3
	loaded, err := s.LoadClientProfile(ctx, "versioned-client")
	if err != nil {
		t.Fatalf("LoadClientProfile: %v", err)
	}
	if loaded.Version != 3 {
		t.Errorf("Version = %d, want 3", loaded.Version)
	}
	if loaded.BotScore != 30 {
		t.Errorf("BotScore = %d, want 30", loaded.BotScore)
	}
	if loaded.AdaptiveMode != "mode-3" {
		t.Errorf("AdaptiveMode = %q, want mode-3", loaded.AdaptiveMode)
	}
}

func TestLoadClientProfile_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	loaded, err := s.LoadClientProfile(ctx, "nonexistent-client")
	if err != nil {
		t.Fatalf("LoadClientProfile: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected nil for nonexistent client, got %+v", loaded)
	}
}

func TestListClientProfiles(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create 3 different clients
	for i := 0; i < 3; i++ {
		rec := &ClientProfileRecord{
			ClientID:      fmt.Sprintf("client-%d", i),
			TotalRequests: int64((3 - i) * 100), // descending order
			BotScore:      50,
			AdaptiveMode:  "normal",
			ProfileData:   json.RawMessage(`{}`),
		}
		if err := s.SaveClientProfile(ctx, rec); err != nil {
			t.Fatalf("SaveClientProfile %d: %v", i, err)
		}
	}

	profiles, err := s.ListClientProfiles(ctx, 10)
	if err != nil {
		t.Fatalf("ListClientProfiles: %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("profiles count = %d, want 3", len(profiles))
	}
	// Should be sorted by total_requests DESC
	if profiles[0].TotalRequests < profiles[2].TotalRequests {
		t.Errorf("expected descending order by total_requests")
	}
}

// ---------------------------------------------------------------------------
// Request log tests
// ---------------------------------------------------------------------------

func TestSaveAndListRequests(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entry := &RequestLogEntry{
		ClientID:     "client-1",
		Method:       "GET",
		Path:         "/api/v1/users",
		StatusCode:   200,
		LatencyMs:    12.5,
		ResponseType: "json",
		UserAgent:    "Mozilla/5.0",
	}

	if err := s.SaveRequest(ctx, entry); err != nil {
		t.Fatalf("SaveRequest: %v", err)
	}

	entries, err := s.ListRequests(ctx, 10)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries count = %d, want 1", len(entries))
	}
	if entries[0].Method != "GET" {
		t.Errorf("Method = %q, want GET", entries[0].Method)
	}
	if entries[0].Path != "/api/v1/users" {
		t.Errorf("Path = %q, want /api/v1/users", entries[0].Path)
	}
	if entries[0].StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", entries[0].StatusCode)
	}
}

func TestSaveRequestBatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entries := []RequestLogEntry{
		{Method: "GET", Path: "/page1", StatusCode: 200, LatencyMs: 10},
		{Method: "POST", Path: "/api/submit", StatusCode: 201, LatencyMs: 50},
		{Method: "GET", Path: "/page2", StatusCode: 404, LatencyMs: 5},
	}

	if err := s.SaveRequestBatch(ctx, entries); err != nil {
		t.Fatalf("SaveRequestBatch: %v", err)
	}

	count, err := s.CountRequests(ctx)
	if err != nil {
		t.Fatalf("CountRequests: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestSaveRequestBatch_Empty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Empty batch should be a no-op
	if err := s.SaveRequestBatch(ctx, nil); err != nil {
		t.Fatalf("SaveRequestBatch empty: %v", err)
	}
}

func TestListRequestsByClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert requests for two clients
	entries := []RequestLogEntry{
		{ClientID: "alpha", Method: "GET", Path: "/a", StatusCode: 200, LatencyMs: 1},
		{ClientID: "alpha", Method: "GET", Path: "/b", StatusCode: 200, LatencyMs: 2},
		{ClientID: "beta", Method: "GET", Path: "/c", StatusCode: 200, LatencyMs: 3},
	}
	if err := s.SaveRequestBatch(ctx, entries); err != nil {
		t.Fatalf("SaveRequestBatch: %v", err)
	}

	// Query alpha
	alphaEntries, err := s.ListRequestsByClient(ctx, "alpha", 10)
	if err != nil {
		t.Fatalf("ListRequestsByClient alpha: %v", err)
	}
	if len(alphaEntries) != 2 {
		t.Errorf("alpha entries = %d, want 2", len(alphaEntries))
	}

	// Query beta
	betaEntries, err := s.ListRequestsByClient(ctx, "beta", 10)
	if err != nil {
		t.Fatalf("ListRequestsByClient beta: %v", err)
	}
	if len(betaEntries) != 1 {
		t.Errorf("beta entries = %d, want 1", len(betaEntries))
	}
}

func TestGetRequestsInRange(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entry := &RequestLogEntry{
		Method: "GET", Path: "/test", StatusCode: 200, LatencyMs: 5,
	}
	if err := s.SaveRequest(ctx, entry); err != nil {
		t.Fatalf("SaveRequest: %v", err)
	}

	// Wide range
	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	results, err := s.GetRequestsInRange(ctx, from, to, 10)
	if err != nil {
		t.Fatalf("GetRequestsInRange: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("results = %d, want 1", len(results))
	}
}

func TestGetRequestStats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entries := []RequestLogEntry{
		{Method: "GET", Path: "/a", StatusCode: 200, LatencyMs: 10},
		{Method: "GET", Path: "/b", StatusCode: 200, LatencyMs: 20},
		{Method: "POST", Path: "/c", StatusCode: 201, LatencyMs: 30},
		{Method: "GET", Path: "/d", StatusCode: 404, LatencyMs: 5},
	}
	if err := s.SaveRequestBatch(ctx, entries); err != nil {
		t.Fatalf("SaveRequestBatch: %v", err)
	}

	stats, err := s.GetRequestStats(ctx)
	if err != nil {
		t.Fatalf("GetRequestStats: %v", err)
	}
	if stats.TotalRequests != 4 {
		t.Errorf("TotalRequests = %d, want 4", stats.TotalRequests)
	}
	if stats.ByMethod["GET"] != 3 {
		t.Errorf("GET count = %d, want 3", stats.ByMethod["GET"])
	}
	if stats.ByMethod["POST"] != 1 {
		t.Errorf("POST count = %d, want 1", stats.ByMethod["POST"])
	}
	if stats.ByStatus[200] != 2 {
		t.Errorf("200 count = %d, want 2", stats.ByStatus[200])
	}
	if stats.ByStatus[404] != 1 {
		t.Errorf("404 count = %d, want 1", stats.ByStatus[404])
	}
	// Avg latency should be (10+20+30+5)/4 = 16.25
	if stats.AvgLatencyMs < 16 || stats.AvgLatencyMs > 17 {
		t.Errorf("AvgLatencyMs = %v, want ~16.25", stats.AvgLatencyMs)
	}
}

func TestGetPathsInTimeWindow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entries := []RequestLogEntry{
		{Method: "GET", Path: "/api/users", StatusCode: 200, LatencyMs: 1},
		{Method: "GET", Path: "/api/products", StatusCode: 200, LatencyMs: 1},
		{Method: "GET", Path: "/api/users", StatusCode: 200, LatencyMs: 1}, // duplicate
	}
	if err := s.SaveRequestBatch(ctx, entries); err != nil {
		t.Fatalf("SaveRequestBatch: %v", err)
	}

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	paths, err := s.GetPathsInTimeWindow(ctx, from, to)
	if err != nil {
		t.Fatalf("GetPathsInTimeWindow: %v", err)
	}
	// Should have 2 distinct paths
	if len(paths) != 2 {
		t.Errorf("paths count = %d, want 2", len(paths))
	}
}

func TestCountRequests(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	count, err := s.CountRequests(ctx)
	if err != nil {
		t.Fatalf("CountRequests: %v", err)
	}
	if count != 0 {
		t.Errorf("initial count = %d, want 0", count)
	}
}

// ---------------------------------------------------------------------------
// Store lifecycle tests
// ---------------------------------------------------------------------------

func TestPing(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestDB(t *testing.T) {
	s := testStore(t)
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}
}

// ---------------------------------------------------------------------------
// Null handling tests
// ---------------------------------------------------------------------------

func TestNullString(t *testing.T) {
	ns := nullString("")
	if ns.Valid {
		t.Error("empty string should be invalid")
	}

	ns2 := nullString("hello")
	if !ns2.Valid || ns2.String != "hello" {
		t.Errorf("expected valid 'hello', got %+v", ns2)
	}
}

func TestNullJSON(t *testing.T) {
	if nullJSON(nil) != nil {
		t.Error("nil should return nil")
	}
	if nullJSON(json.RawMessage{}) != nil {
		t.Error("empty should return nil")
	}
	data := json.RawMessage(`{"key":"value"}`)
	if nullJSON(data) == nil {
		t.Error("non-empty should not return nil")
	}
}

// ---------------------------------------------------------------------------
// SaveScan with nil report
// ---------------------------------------------------------------------------

func TestSaveScan_NilReport(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	rec := &ScanRecord{
		ScannerName:   "test-scanner",
		Status:        "ok",
		DetectionRate: 0.5,
		Report:        nil, // nil should default to {}
	}

	id, err := s.SaveScan(ctx, rec)
	if err != nil {
		t.Fatalf("SaveScan nil report: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}
}

// ---------------------------------------------------------------------------
// Default limit tests
// ---------------------------------------------------------------------------

func TestDefaultLimits(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// These should not error with 0 or negative limits (they use defaults)
	if _, err := s.ListScans(ctx, 0); err != nil {
		t.Errorf("ListScans limit 0: %v", err)
	}
	if _, err := s.ListScans(ctx, -1); err != nil {
		t.Errorf("ListScans limit -1: %v", err)
	}
	if _, err := s.ListMetricsSnapshots(ctx, 0); err != nil {
		t.Errorf("ListMetricsSnapshots limit 0: %v", err)
	}
	if _, err := s.ListRequests(ctx, 0); err != nil {
		t.Errorf("ListRequests limit 0: %v", err)
	}
	if _, err := s.ListClientProfiles(ctx, 0); err != nil {
		t.Errorf("ListClientProfiles limit 0: %v", err)
	}
	if _, err := s.ListConfigHistory(ctx, "any", 0); err != nil {
		t.Errorf("ListConfigHistory limit 0: %v", err)
	}
}
