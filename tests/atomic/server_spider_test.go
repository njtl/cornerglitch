package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Spider Config — Atomic Tests
//
// Tests every spider configuration parameter: defaults, set/verify,
// clamping, unknown keys.
// ---------------------------------------------------------------------------

type spiderNumericSpec struct {
	Key     string
	Default float64
	Min     float64
	Max     float64
}

var spiderNumericConfigs = []spiderNumericSpec{
	{"sitemap_error_rate", 0.15, 0, 1},
	{"sitemap_gzip_error_rate", 0.10, 0, 1},
	{"favicon_error_rate", 0.20, 0, 1},
	{"robots_error_rate", 0.10, 0, 1},
	{"meta_error_rate", 0.10, 0, 1},
}

type spiderBoolSpec struct {
	Key     string
	Default bool
}

var spiderBoolConfigs = []spiderBoolSpec{
	{"enable_sitemap_index", true},
	{"enable_gzip_sitemap", true},
}

// TestServer_Spider_NumericDefaults verifies all spider numeric defaults.
func TestServer_Spider_NumericDefaults(t *testing.T) {
	mux := setupTestEnv(t)
	resetSpiderConfig(t)

	resp := apiGet(t, mux, "/admin/api/spider")
	for _, spec := range spiderNumericConfigs {
		t.Run(spec.Key+"_default", func(t *testing.T) {
			apiVal, ok := toFloat64(resp[spec.Key])
			if !ok {
				t.Fatalf("spider config %q not found or wrong type in API", spec.Key)
			}
			if apiVal != spec.Default {
				t.Errorf("spider %q default = %v, want %v", spec.Key, apiVal, spec.Default)
			}
		})
	}
}

// TestServer_Spider_BoolDefaults verifies all spider bool defaults.
func TestServer_Spider_BoolDefaults(t *testing.T) {
	mux := setupTestEnv(t)
	resetSpiderConfig(t)

	resp := apiGet(t, mux, "/admin/api/spider")
	for _, spec := range spiderBoolConfigs {
		t.Run(spec.Key+"_default", func(t *testing.T) {
			apiVal, ok := resp[spec.Key].(bool)
			if !ok {
				t.Fatalf("spider config %q not found or wrong type", spec.Key)
			}
			if apiVal != spec.Default {
				t.Errorf("spider %q default = %v, want %v", spec.Key, apiVal, spec.Default)
			}
		})
	}
}

// TestServer_Spider_NumericSetAndVerify tests setting each spider numeric value.
func TestServer_Spider_NumericSetAndVerify(t *testing.T) {
	mux := setupTestEnv(t)

	for _, spec := range spiderNumericConfigs {
		t.Run(spec.Key, func(t *testing.T) {
			testVals := []float64{0, 0.25, 0.5, 0.75, 1.0}
			for _, val := range testVals {
				t.Run(fmtFloat(val), func(t *testing.T) {
					resetSpiderConfig(t)

					resp := apiPost(t, mux, "/admin/api/spider", map[string]interface{}{
						"key":   spec.Key,
						"value": val,
					})
					if resp["ok"] != true {
						t.Fatalf("POST spider returned ok=%v", resp["ok"])
					}

					// Verify via API
					got := apiGet(t, mux, "/admin/api/spider")
					apiVal, _ := toFloat64(got[spec.Key])
					if apiVal != val {
						t.Errorf("[API] spider %q = %v, want %v", spec.Key, apiVal, val)
					}

					// Verify internal
					internal := dashboard.GetSpiderConfig().Get(spec.Key)
					internalVal, _ := toFloat64(internal)
					if internalVal != val {
						t.Errorf("[Internal] spider %q = %v, want %v", spec.Key, internalVal, val)
					}
				})
			}
		})
	}
}

// TestServer_Spider_BoolSetAndVerify tests toggling spider bool configs.
func TestServer_Spider_BoolSetAndVerify(t *testing.T) {
	mux := setupTestEnv(t)

	for _, spec := range spiderBoolConfigs {
		t.Run(spec.Key, func(t *testing.T) {
			for _, val := range []bool{false, true} {
				resetSpiderConfig(t)

				apiPost(t, mux, "/admin/api/spider", map[string]interface{}{
					"key":   spec.Key,
					"value": val,
				})

				got := apiGet(t, mux, "/admin/api/spider")
				apiVal, ok := got[spec.Key].(bool)
				if !ok {
					t.Fatalf("spider %q not bool in response", spec.Key)
				}
				if apiVal != val {
					t.Errorf("[API] spider %q = %v, want %v", spec.Key, apiVal, val)
				}

				internal := dashboard.GetSpiderConfig().Get(spec.Key)
				if internal.(bool) != val {
					t.Errorf("[Internal] spider %q = %v, want %v", spec.Key, internal, val)
				}
			}
		})
	}
}

// TestServer_Spider_NumericClamping tests boundary clamping for spider rates.
func TestServer_Spider_NumericClamping(t *testing.T) {
	mux := setupTestEnv(t)

	for _, spec := range spiderNumericConfigs {
		t.Run(spec.Key+"_below_min", func(t *testing.T) {
			resetSpiderConfig(t)
			apiPost(t, mux, "/admin/api/spider", map[string]interface{}{
				"key":   spec.Key,
				"value": -0.5,
			})
			internal := dashboard.GetSpiderConfig().Get(spec.Key)
			v, _ := toFloat64(internal)
			if v != spec.Min {
				t.Errorf("spider %q below min: got %v, want %v", spec.Key, v, spec.Min)
			}
		})
		t.Run(spec.Key+"_above_max", func(t *testing.T) {
			resetSpiderConfig(t)
			apiPost(t, mux, "/admin/api/spider", map[string]interface{}{
				"key":   spec.Key,
				"value": 1.5,
			})
			internal := dashboard.GetSpiderConfig().Get(spec.Key)
			v, _ := toFloat64(internal)
			if v != spec.Max {
				t.Errorf("spider %q above max: got %v, want %v", spec.Key, v, spec.Max)
			}
		})
	}
}

// TestServer_Spider_UnknownKeyReturnsError tests that unknown keys are rejected.
func TestServer_Spider_UnknownKeyReturnsError(t *testing.T) {
	mux := setupTestEnv(t)

	unknowns := []string{"nonexistent", "foo", "sitemap_count", ""}
	for _, key := range unknowns {
		t.Run(key, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/spider", map[string]interface{}{
				"key":   key,
				"value": 0.5,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("unknown spider key %q should return error, got 200", key)
			}
		})
	}
}

// TestServer_Spider_SitemapEntryCountDefaults tests integer config defaults.
func TestServer_Spider_SitemapEntryCountDefaults(t *testing.T) {
	mux := setupTestEnv(t)
	resetSpiderConfig(t)

	resp := apiGet(t, mux, "/admin/api/spider")
	val, ok := toFloat64(resp["sitemap_entry_count"])
	if !ok {
		t.Fatal("sitemap_entry_count not found in API")
	}
	if val != 50 {
		t.Errorf("sitemap_entry_count default = %v, want 50", val)
	}
}

// TestServer_Spider_RobotsCrawlDelayDefault tests robots_crawl_delay default.
func TestServer_Spider_RobotsCrawlDelayDefault(t *testing.T) {
	mux := setupTestEnv(t)
	resetSpiderConfig(t)

	resp := apiGet(t, mux, "/admin/api/spider")
	val, ok := toFloat64(resp["robots_crawl_delay"])
	if !ok {
		t.Fatal("robots_crawl_delay not found in API")
	}
	if val != 2 {
		t.Errorf("robots_crawl_delay default = %v, want 2", val)
	}
}

// resetSpiderConfig is defined in helpers_test.go
