package atomic

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Server Blocking Config — Atomic Tests
//
// Tests the blocking API: enable/disable, chance, duration, and round-trip.
// ---------------------------------------------------------------------------

// TestServer_Blocking_DefaultState verifies default blocking config via API.
func TestServer_Blocking_DefaultState(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/blocking")
	if resp["enabled"] != true {
		t.Errorf("default blocking enabled = %v, want true", resp["enabled"])
	}

	chance, _ := toFloat64(resp["chance"])
	if chance != 0.02 {
		t.Errorf("default chance = %v, want 0.02", chance)
	}

	dur, _ := toFloat64(resp["duration_sec"])
	if dur != 30 {
		t.Errorf("default duration_sec = %v, want 30", dur)
	}
}

// TestServer_Blocking_SetChance tests setting the block chance.
func TestServer_Blocking_SetChance(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	testVals := []float64{0, 0.05, 0.1, 0.5, 1.0}
	for _, val := range testVals {
		t.Run(fmtFloat(val), func(t *testing.T) {
			resp := apiPost(t, mux, "/admin/api/blocking", map[string]interface{}{
				"chance": val,
			})
			if resp["ok"] != true {
				t.Fatalf("POST blocking returned ok=%v", resp["ok"])
			}

			got, _ := toFloat64(resp["chance"])
			if got != val {
				t.Errorf("response chance = %v, want %v", got, val)
			}

			// Verify via GET
			getResp := apiGet(t, mux, "/admin/api/blocking")
			getCh, _ := toFloat64(getResp["chance"])
			if getCh != val {
				t.Errorf("[GET] chance = %v, want %v", getCh, val)
			}
		})
	}
}

// TestServer_Blocking_SetDuration tests setting the block duration.
func TestServer_Blocking_SetDuration(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	testVals := []int{1, 10, 30, 300, 3600}
	for _, val := range testVals {
		t.Run(fmtFloat(float64(val)), func(t *testing.T) {
			resp := apiPost(t, mux, "/admin/api/blocking", map[string]interface{}{
				"duration_sec": val,
			})
			if resp["ok"] != true {
				t.Fatalf("POST blocking returned ok=%v", resp["ok"])
			}

			got, _ := toFloat64(resp["duration_sec"])
			if got != float64(val) {
				t.Errorf("response duration_sec = %v, want %v", got, val)
			}
		})
	}
}

// TestServer_Blocking_ToggleEnabled tests enabling/disabling blocking.
func TestServer_Blocking_ToggleEnabled(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable
	resp := apiPost(t, mux, "/admin/api/blocking", map[string]interface{}{
		"enabled": false,
	})
	if resp["ok"] != true {
		t.Fatal("disable blocking failed")
	}
	if resp["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", resp["enabled"])
	}

	// Verify via GET
	getResp := apiGet(t, mux, "/admin/api/blocking")
	if getResp["enabled"] != false {
		t.Error("[GET] blocking should be disabled")
	}

	// Re-enable
	resp = apiPost(t, mux, "/admin/api/blocking", map[string]interface{}{
		"enabled": true,
	})
	if resp["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", resp["enabled"])
	}
}

// TestServer_Blocking_MultiFieldUpdate tests updating multiple fields at once.
func TestServer_Blocking_MultiFieldUpdate(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiPost(t, mux, "/admin/api/blocking", map[string]interface{}{
		"enabled":      false,
		"chance":       0.25,
		"duration_sec": 120,
	})
	if resp["ok"] != true {
		t.Fatal("multi-field update failed")
	}
	if resp["enabled"] != false {
		t.Error("enabled should be false")
	}
	ch, _ := toFloat64(resp["chance"])
	if ch != 0.25 {
		t.Errorf("chance = %v, want 0.25", ch)
	}
	dur, _ := toFloat64(resp["duration_sec"])
	if dur != 120 {
		t.Errorf("duration_sec = %v, want 120", dur)
	}
}
