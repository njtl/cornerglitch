package storage

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSmoke_PostgreSQL(t *testing.T) {
	dsn := os.Getenv("GLITCH_DB_URL")
	if dsn == "" {
		dsn = "postgres://glitch:glitch@localhost:5432/glitch?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := NewWithDSN(ctx, dsn)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer store.Close()

	// Test SaveConfig + LoadConfig
	testData := map[string]bool{"labyrinth": true, "vuln": false}
	if err := store.SaveConfig(ctx, "test_entity", testData); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var loaded map[string]bool
	found, err := store.LoadConfig(ctx, "test_entity", &loaded)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !found {
		t.Fatal("LoadConfig: expected found=true")
	}
	if loaded["labyrinth"] != true || loaded["vuln"] != false {
		t.Fatalf("LoadConfig: unexpected data %v", loaded)
	}

	// Test version incrementing
	if err := store.SaveConfig(ctx, "test_entity", map[string]bool{"updated": true}); err != nil {
		t.Fatalf("SaveConfig v2: %v", err)
	}
	ver, err := store.ConfigVersion(ctx, "test_entity")
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver < 2 {
		t.Fatalf("ConfigVersion: expected >= 2, got %d", ver)
	}

	// Test SaveFullConfig + LoadFullConfig
	export := &FullConfigExport{
		Features:     map[string]bool{"labyrinth": true, "error_inject": true},
		Config:       map[string]interface{}{"max_labyrinth_depth": 50.0},
		ErrorWeights: map[string]float64{"500": 0.5, "503": 0.3},
	}
	if err := store.SaveFullConfig(ctx, export); err != nil {
		t.Fatalf("SaveFullConfig: %v", err)
	}

	loaded2, err := store.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded2 == nil {
		t.Fatal("LoadFullConfig: nil")
	}
	if !loaded2.Features["labyrinth"] {
		t.Fatal("LoadFullConfig: labyrinth should be true")
	}

	// Test MetricsSnapshot
	snapData, _ := json.Marshal(map[string]string{"test": "data"})
	snap := &MetricsSnapshot{
		TotalRequests:     100,
		TotalErrors:       5,
		Total2xx:          80,
		Total4xx:          10,
		Total5xx:          5,
		ActiveConnections: 3,
		UniqueClients:     2,
		SnapshotData:      snapData,
	}
	id, err := store.SaveMetricsSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("SaveMetricsSnapshot: %v", err)
	}
	if id == 0 {
		t.Fatal("SaveMetricsSnapshot: expected non-zero id")
	}

	snapshots, err := store.ListMetricsSnapshots(ctx, 1)
	if err != nil {
		t.Fatalf("ListMetricsSnapshots: %v", err)
	}
	if len(snapshots) == 0 {
		t.Fatal("ListMetricsSnapshots: expected at least 1")
	}

	// Test ScanRecord
	reportData, _ := json.Marshal(map[string]string{"scanner": "test"})
	scanID, err := store.SaveScan(ctx, &ScanRecord{
		ScannerName:   "test-scanner",
		Status:        "completed",
		Grade:         "A",
		DetectionRate: 0.95,
		Report:        reportData,
	})
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if scanID == 0 {
		t.Fatal("SaveScan: expected non-zero id")
	}

	scans, err := store.ListScans(ctx, 1)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("ListScans: expected at least 1")
	}

	// Test RequestLog
	if err := store.SaveRequest(ctx, &RequestLogEntry{
		ClientID:   "test-client",
		Method:     "GET",
		Path:       "/test",
		StatusCode: 200,
		LatencyMs:  1.5,
	}); err != nil {
		t.Fatalf("SaveRequest: %v", err)
	}

	requests, err := store.ListRequests(ctx, 1)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(requests) == 0 {
		t.Fatal("ListRequests: expected at least 1")
	}

	// Test ClientProfile
	profileData, _ := json.Marshal(map[string]string{"ua": "test"})
	if err := store.SaveClientProfile(ctx, &ClientProfileRecord{
		ClientID:      "smoke-test-client",
		TotalRequests: 42,
		BotScore:      15,
		AdaptiveMode:  "normal",
		ProfileData:   profileData,
	}); err != nil {
		t.Fatalf("SaveClientProfile: %v", err)
	}

	profile, err := store.LoadClientProfile(ctx, "smoke-test-client")
	if err != nil {
		t.Fatalf("LoadClientProfile: %v", err)
	}
	if profile == nil {
		t.Fatal("LoadClientProfile: nil")
	}
	if profile.TotalRequests != 42 {
		t.Fatalf("LoadClientProfile: expected 42 requests, got %d", profile.TotalRequests)
	}

	t.Log("All storage smoke tests passed")
}
