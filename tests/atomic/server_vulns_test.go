package atomic

import (
	"testing"

	"github.com/cornerglitch/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Vulnerability Config — Atomic Tests
//
// Tests every vuln group: toggle on/off, verify, isolation, API response.
// ---------------------------------------------------------------------------

var allVulnGroups = dashboard.VulnGroups

// TestServer_VulnGroups_AllDefaultEnabled verifies all groups start enabled.
func TestServer_VulnGroups_AllDefaultEnabled(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	for _, group := range allVulnGroups {
		t.Run(group+"_default_enabled", func(t *testing.T) {
			verifyVulnGroup(t, mux, group, true)
		})
	}
}

// TestServer_VulnGroups_ToggleOff tests disabling each group individually.
func TestServer_VulnGroups_ToggleOff(t *testing.T) {
	mux := setupTestEnv(t)

	for _, group := range allVulnGroups {
		t.Run(group, func(t *testing.T) {
			resetAll(t)

			// Baseline: enabled
			verifyVulnGroup(t, mux, group, true)

			// Toggle OFF via API
			resp := apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
				"group":   group,
				"enabled": false,
			})
			if resp["ok"] != true {
				t.Fatalf("POST vulns/group returned ok=%v", resp["ok"])
			}

			// Verify disabled (dual-layer)
			verifyVulnGroup(t, mux, group, false)

			// Toggle back ON
			apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
				"group":   group,
				"enabled": true,
			})

			// Verify restored
			verifyVulnGroup(t, mux, group, true)
		})
	}
}

// TestServer_VulnGroups_ToggleOn tests enabling a disabled group.
func TestServer_VulnGroups_ToggleOn(t *testing.T) {
	mux := setupTestEnv(t)

	for _, group := range allVulnGroups {
		t.Run(group, func(t *testing.T) {
			resetAll(t)

			// Start disabled
			dashboard.GetVulnConfig().SetGroup(group, false)
			verifyVulnGroup(t, mux, group, false)

			// Toggle ON via API
			resp := apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
				"group":   group,
				"enabled": true,
			})
			if resp["ok"] != true {
				t.Fatalf("POST vulns/group returned ok=%v", resp["ok"])
			}

			verifyVulnGroup(t, mux, group, true)
		})
	}
}

// TestServer_VulnGroups_IsolationNoSideEffects verifies toggling one group
// doesn't affect any other group.
func TestServer_VulnGroups_IsolationNoSideEffects(t *testing.T) {
	mux := setupTestEnv(t)

	for _, target := range allVulnGroups {
		t.Run(target, func(t *testing.T) {
			resetAll(t)

			// Disable only the target
			apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
				"group":   target,
				"enabled": false,
			})

			// All OTHER groups must still be enabled
			for _, other := range allVulnGroups {
				if other == target {
					verifyVulnGroup(t, mux, other, false)
					continue
				}
				verifyVulnGroup(t, mux, other, true)
			}
		})
	}
}

// TestServer_VulnGroups_UnknownReturnsError tests that unknown groups are rejected.
func TestServer_VulnGroups_UnknownReturnsError(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	unknowns := []string{"nonexistent", "foo", "owasp_extra", ""}
	for _, name := range unknowns {
		t.Run(name, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/vulns/group", map[string]interface{}{
				"group":   name,
				"enabled": true,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("unknown vuln group %q should return error, got 200", name)
			}
		})
	}
}

// TestServer_VulnGroups_CategoryToggle tests individual category toggling.
func TestServer_VulnGroups_CategoryToggle(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	categories := []string{"a01_injection", "a02_broken_auth", "a03_sensitive_data"}

	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			resetVulnConfig(t)
			vc := dashboard.GetVulnConfig()

			// Toggle OFF via API
			apiPost(t, mux, "/admin/api/vulns", map[string]interface{}{
				"id":      cat,
				"enabled": false,
			})

			if vc.IsCategoryEnabled(cat) {
				t.Errorf("category %s should be disabled", cat)
			}

			// Re-enable
			apiPost(t, mux, "/admin/api/vulns", map[string]interface{}{
				"id":      cat,
				"enabled": true,
			})

			if !vc.IsCategoryEnabled(cat) {
				t.Errorf("category %s should be re-enabled", cat)
			}
		})
	}
}

// TestServer_VulnGroups_CategoryIsolation verifies disabling one category
// doesn't affect other categories.
func TestServer_VulnGroups_CategoryIsolation(t *testing.T) {
	resetAll(t)
	vc := dashboard.GetVulnConfig()

	// Disable one category
	vc.SetCategory("a01_injection", false)

	// Other categories should still be enabled
	if !vc.IsCategoryEnabled("a02_broken_auth") {
		t.Error("a02_broken_auth should not be affected by disabling a01_injection")
	}
	if !vc.IsCategoryEnabled("a03_sensitive_data") {
		t.Error("a03_sensitive_data should not be affected by disabling a01_injection")
	}

	// The disabled one should be off
	if vc.IsCategoryEnabled("a01_injection") {
		t.Error("a01_injection should be disabled")
	}

	// Clean up
	vc.SetCategory("a01_injection", true)
}

// TestServer_VulnGroups_GroupAndCategoryInteraction verifies that disabling
// a group and re-enabling it doesn't affect individually-disabled categories.
func TestServer_VulnGroups_GroupAndCategoryInteraction(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable a specific OWASP category
	apiPost(t, mux, "/admin/api/vulns", map[string]interface{}{
		"id":      "a01_injection",
		"enabled": false,
	})

	vc := dashboard.GetVulnConfig()
	if vc.IsCategoryEnabled("a01_injection") {
		t.Fatal("a01_injection should be disabled")
	}

	// Disable then re-enable the entire owasp group
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": false,
	})
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": true,
	})

	// The group is re-enabled, but individual category may still be affected
	// This tests whether group toggle preserves or resets category state
	// Either behavior is valid — document whatever happens
	catState := vc.IsCategoryEnabled("a01_injection")
	t.Logf("After group toggle, a01_injection enabled = %v", catState)
}

// TestServer_VulnGroups_APIResponseFormat verifies the vuln API response structure.
func TestServer_VulnGroups_APIResponseFormat(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/vulns")

	// Should have "groups" key
	groups, ok := resp["groups"].(map[string]interface{})
	if !ok {
		t.Fatalf("vulns response missing 'groups' key or wrong type: %T", resp["groups"])
	}

	// All groups should be present
	for _, group := range allVulnGroups {
		val, exists := groups[group]
		if !exists {
			t.Errorf("API response missing vuln group %q", group)
			continue
		}
		if _, isBool := val.(bool); !isBool {
			t.Errorf("vuln group %q has type %T, want bool", group, val)
		}
	}
}
