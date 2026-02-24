package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
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

	// Toggle a specific category
	apiPost(t, mux, "/admin/api/vulns", map[string]interface{}{
		"id":      "a01_injection",
		"enabled": false,
	})

	vc := dashboard.GetVulnConfig()
	if vc.IsCategoryEnabled("a01_injection") {
		t.Error("category a01_injection should be disabled")
	}

	// Re-enable
	apiPost(t, mux, "/admin/api/vulns", map[string]interface{}{
		"id":      "a01_injection",
		"enabled": true,
	})

	if !vc.IsCategoryEnabled("a01_injection") {
		t.Error("category a01_injection should be re-enabled")
	}
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
