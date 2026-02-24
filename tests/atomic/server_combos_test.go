package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Combination Tests — Atomic Tests
//
// Tests interactions between multiple settings: all features on/off,
// config export/import round-trip, nightmare with features, etc.
// ---------------------------------------------------------------------------

// TestCombo_AllFeaturesOff verifies disabling all features simultaneously.
func TestCombo_AllFeaturesOff(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable all features via SetAll
	dashboard.GetFeatureFlags().SetAll(false)

	snap := dashboard.GetFeatureFlags().Snapshot()
	for _, flag := range allFeatureFlags {
		if flag == "recorder" {
			continue // recorder excluded from SetAll
		}
		if snap[flag] {
			t.Errorf("flag %q should be disabled after SetAll(false)", flag)
		}
	}

	// Re-enable all
	dashboard.GetFeatureFlags().SetAll(true)

	snap = dashboard.GetFeatureFlags().Snapshot()
	for _, flag := range allFeatureFlags {
		if flag == "recorder" {
			continue
		}
		if !snap[flag] {
			t.Errorf("flag %q should be enabled after SetAll(true)", flag)
		}
	}

	// Verify via API
	resp := apiGet(t, mux, "/admin/api/features")
	for _, flag := range allFeatureFlags {
		if flag == "recorder" {
			continue
		}
		if resp[flag] != true {
			t.Errorf("[API] flag %q = %v, want true", flag, resp[flag])
		}
	}
}

// TestCombo_AllVulnGroupsOff verifies disabling all vuln groups simultaneously.
func TestCombo_AllVulnGroupsOff(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable all groups
	for _, group := range allVulnGroups {
		apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
			"group":   group,
			"enabled": false,
		})
	}

	// Verify all disabled
	for _, group := range allVulnGroups {
		verifyVulnGroup(t, mux, group, false)
	}

	// Re-enable all
	for _, group := range allVulnGroups {
		apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
			"group":   group,
			"enabled": true,
		})
	}

	// Verify all re-enabled
	for _, group := range allVulnGroups {
		verifyVulnGroup(t, mux, group, true)
	}
}

// TestCombo_ConfigExportImportRoundTrip tests that exported config can be reimported.
func TestCombo_ConfigExportImportRoundTrip(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Modify some settings
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "max_labyrinth_depth",
		"value": 75,
	})
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "captcha",
		"enabled": false,
	})

	// Export config
	exportResp := apiGet(t, mux, "/admin/api/config/export")
	if len(exportResp) == 0 {
		t.Fatal("config export returned empty response")
	}

	// Reset everything to defaults
	resetAll(t)

	// Verify reset worked
	verifyConfigValue(t, mux, "max_labyrinth_depth", float64(50))
	verifyFeatureFlag(t, mux, "captcha", true)

	// Import the exported config
	apiPost(t, mux, "/admin/api/config/import", exportResp)

	// Verify settings were restored
	verifyConfigValue(t, mux, "max_labyrinth_depth", float64(75))
	verifyFeatureFlag(t, mux, "captcha", false)
}

// TestCombo_NightmarePreservesRecorder verifies nightmare + recorder interaction.
func TestCombo_NightmarePreservesRecorder(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable recorder
	dashboard.GetFeatureFlags().Set("recorder", false)
	if dashboard.GetFeatureFlags().Snapshot()["recorder"] {
		t.Fatal("recorder should be disabled")
	}

	// Activate nightmare (which calls SetAll(true) for features)
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": true,
	})

	// Recorder should still be disabled
	if dashboard.GetFeatureFlags().Snapshot()["recorder"] {
		t.Error("nightmare should not change recorder flag")
	}

	// Deactivate
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": false,
	})

	// Recorder should still be disabled (restored to pre-nightmare state)
	if dashboard.GetFeatureFlags().Snapshot()["recorder"] {
		t.Error("post-nightmare restore should keep recorder disabled")
	}
}

// TestCombo_FeaturesAndConfigIndependent verifies features and config are separate.
func TestCombo_FeaturesAndConfigIndependent(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Change a config value
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "error_rate_multiplier",
		"value": 3.5,
	})

	// Toggle a feature
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "labyrinth",
		"enabled": false,
	})

	// Verify config wasn't affected by feature toggle
	verifyConfigValue(t, mux, "error_rate_multiplier", 3.5)

	// Verify feature wasn't affected by config change
	verifyFeatureFlag(t, mux, "labyrinth", false)

	// Verify other features still enabled
	verifyFeatureFlag(t, mux, "captcha", true)
	verifyFeatureFlag(t, mux, "honeypot", true)
}

// TestCombo_VulnGroupAndFeaturesIndependent verifies vuln and features are separate.
func TestCombo_VulnGroupAndFeaturesIndependent(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable a vuln group
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": false,
	})

	// Disable a feature
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "vuln",
		"enabled": false,
	})

	// Verify both changes are independent
	verifyVulnGroup(t, mux, "owasp", false)
	verifyVulnGroup(t, mux, "api_security", true) // other groups unaffected
	verifyFeatureFlag(t, mux, "vuln", false)
	verifyFeatureFlag(t, mux, "labyrinth", true) // other features unaffected
}

// TestCombo_ResetAllRestoresBaseline verifies full reset restores everything.
func TestCombo_ResetAllRestoresBaseline(t *testing.T) {
	mux := setupTestEnv(t)

	// Make various changes
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 4.0)
	dashboard.GetVulnConfig().SetGroup("owasp", false)

	// Reset everything
	resetAll(t)

	// Verify all restored to defaults
	verifyFeatureFlag(t, mux, "labyrinth", true)
	verifyConfigValue(t, mux, "error_rate_multiplier", 1.0)
	verifyVulnGroup(t, mux, "owasp", true)
}
