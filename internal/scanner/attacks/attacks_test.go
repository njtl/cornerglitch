package attacks

import (
	"testing"

	"github.com/glitchWebServer/internal/scanner"
)

// ---------------------------------------------------------------------------
// TestOWASPModule_GenerateRequests
// ---------------------------------------------------------------------------

func TestOWASPModule_GenerateRequests(t *testing.T) {
	mod := &OWASPModule{}

	if mod.Name() != "owasp" {
		t.Errorf("expected name 'owasp', got %q", mod.Name())
	}
	if mod.Category() != "vulnerability" {
		t.Errorf("expected category 'vulnerability', got %q", mod.Category())
	}

	reqs := mod.GenerateRequests("http://localhost:8765")

	if len(reqs) == 0 {
		t.Fatal("OWASPModule generated zero requests")
	}

	t.Logf("OWASPModule generated %d requests", len(reqs))

	// Verify requests cover multiple OWASP categories.
	categories := make(map[string]int)
	for _, r := range reqs {
		categories[r.Category]++
	}

	expectedCategories := []string{
		"OWASP-A01", "OWASP-A02", "OWASP-A03", "OWASP-A04", "OWASP-A05",
		"OWASP-A06", "OWASP-A07", "OWASP-A08", "OWASP-A09", "OWASP-A10",
		"API-Security-API1", "LLM-Top-10",
	}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("expected at least one request in category %q, found none", cat)
		}
	}

	// Verify basic structure of all requests.
	for i, r := range reqs {
		if r.Method == "" {
			t.Errorf("request %d has empty Method", i)
		}
		if r.Path == "" {
			t.Errorf("request %d has empty Path", i)
		}
		if r.Category == "" {
			t.Errorf("request %d has empty Category", i)
		}
		if r.Description == "" {
			t.Errorf("request %d has empty Description", i)
		}
	}

	// Verify both GET and POST methods are present.
	methods := make(map[string]int)
	for _, r := range reqs {
		methods[r.Method]++
	}
	if methods["GET"] == 0 {
		t.Error("expected GET requests from OWASP module")
	}
	if methods["POST"] == 0 {
		t.Error("expected POST requests from OWASP module")
	}
}

// ---------------------------------------------------------------------------
// TestInjectionModule_GenerateRequests
// ---------------------------------------------------------------------------

func TestInjectionModule_GenerateRequests(t *testing.T) {
	mod := &InjectionModule{}

	if mod.Name() != "injection" {
		t.Errorf("expected name 'injection', got %q", mod.Name())
	}
	if mod.Category() != "injection" {
		t.Errorf("expected category 'injection', got %q", mod.Category())
	}

	reqs := mod.GenerateRequests("http://localhost:8765")

	if len(reqs) == 0 {
		t.Fatal("InjectionModule generated zero requests")
	}

	t.Logf("InjectionModule generated %d requests", len(reqs))

	// Verify injection categories are covered.
	categories := make(map[string]int)
	for _, r := range reqs {
		categories[r.Category]++
	}

	expectedCategories := []string{
		"SQL-Injection", "XSS", "SSRF", "SSTI",
		"Command-Injection", "LDAP-Injection", "XML-Injection",
	}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("expected at least one request in category %q, found none", cat)
		}
	}

	// Verify sub-categories exist for SQL injection.
	subCats := make(map[string]int)
	for _, r := range reqs {
		if r.Category == "SQL-Injection" {
			subCats[r.SubCategory]++
		}
	}
	sqlSubCats := []string{"union-based", "auth-bypass", "time-based-blind", "boolean-blind", "stacked-query"}
	for _, sc := range sqlSubCats {
		if subCats[sc] == 0 {
			t.Errorf("expected SQL injection sub-category %q, found none", sc)
		}
	}

	// Verify XML/XXE requests use POST and application/xml.
	for _, r := range reqs {
		if r.Category == "XML-Injection" {
			if r.Method != "POST" {
				t.Errorf("XML injection request should be POST, got %s", r.Method)
				break
			}
			if r.BodyType != "application/xml" {
				t.Errorf("XML injection request should have BodyType application/xml, got %s", r.BodyType)
				break
			}
			if r.Body == "" {
				t.Error("XML injection request should have a non-empty body")
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestFuzzingModule_GenerateRequests
// ---------------------------------------------------------------------------

func TestFuzzingModule_GenerateRequests(t *testing.T) {
	mod := &FuzzingModule{}

	if mod.Name() != "fuzzing" {
		t.Errorf("expected name 'fuzzing', got %q", mod.Name())
	}
	if mod.Category() != "fuzzing" {
		t.Errorf("expected category 'fuzzing', got %q", mod.Category())
	}

	reqs := mod.GenerateRequests("http://localhost:8765")

	if len(reqs) == 0 {
		t.Fatal("FuzzingModule generated zero requests")
	}

	t.Logf("FuzzingModule generated %d requests", len(reqs))

	// Verify fuzzing sub-categories are covered.
	subCats := make(map[string]int)
	for _, r := range reqs {
		subCats[r.SubCategory]++
	}

	expectedSubCats := []string{
		"path-admin", "path-backup", "path-config", "path-dotfile", "path-api",
		"param-numeric", "param-string",
		"method-fuzzing",
		"header-oversize", "header-null", "header-crlf", "header-special",
		"content-type",
	}
	for _, sc := range expectedSubCats {
		if subCats[sc] == 0 {
			t.Errorf("expected fuzzing sub-category %q, found none", sc)
		}
	}

	// Verify method fuzzing includes unusual methods.
	methods := make(map[string]bool)
	for _, r := range reqs {
		if r.SubCategory == "method-fuzzing" {
			methods[r.Method] = true
		}
	}

	unusualMethods := []string{"OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PURGE"}
	for _, m := range unusualMethods {
		if !methods[m] {
			t.Errorf("expected method fuzzing to include %s", m)
		}
	}

	// Verify header fuzzing includes oversized headers.
	for _, r := range reqs {
		if r.SubCategory == "header-oversize" {
			found := false
			for _, v := range r.Headers {
				if len(v) >= 8192 {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected at least one oversized header value (>= 8KB)")
			}
			break
		}
	}
}

// ---------------------------------------------------------------------------
// TestAllModules — all modules generate non-empty request lists
// ---------------------------------------------------------------------------

func TestAllModules(t *testing.T) {
	modules := AllModules()

	if len(modules) == 0 {
		t.Fatal("AllModules returned no modules")
	}

	for _, mod := range modules {
		t.Run(mod.Name(), func(t *testing.T) {
			if mod.Name() == "" {
				t.Error("module has empty name")
			}
			if mod.Category() == "" {
				t.Error("module has empty category")
			}

			reqs := mod.GenerateRequests("http://localhost:8765")
			if len(reqs) == 0 {
				t.Errorf("module %q generated 0 requests", mod.Name())
			}

			// Verify all requests have required fields.
			for i, r := range reqs {
				if r.Method == "" {
					t.Errorf("module %q request %d has empty Method", mod.Name(), i)
				}
				if r.Path == "" {
					t.Errorf("module %q request %d has empty Path", mod.Name(), i)
				}
				if r.Category == "" {
					t.Errorf("module %q request %d has empty Category", mod.Name(), i)
				}
			}

			t.Logf("module %q generated %d requests", mod.Name(), len(reqs))
		})
	}
}

// ---------------------------------------------------------------------------
// TestModuleRegistry
// ---------------------------------------------------------------------------

func TestModuleRegistry(t *testing.T) {
	t.Run("AllModules_returns_modules", func(t *testing.T) {
		modules := AllModules()
		if len(modules) < 2 {
			t.Errorf("expected at least 2 modules, got %d", len(modules))
		}

		// Verify it returns AttackModule interface implementations.
		for _, m := range modules {
			var _ scanner.AttackModule = m
		}
	})

	t.Run("ListModuleNames", func(t *testing.T) {
		names := ListModuleNames()
		if len(names) == 0 {
			t.Fatal("ListModuleNames returned no names")
		}

		// Names should be sorted.
		for i := 1; i < len(names); i++ {
			if names[i] < names[i-1] {
				t.Errorf("names not sorted: %q appears before %q", names[i-1], names[i])
			}
		}

		// Known modules should be present.
		nameSet := make(map[string]bool)
		for _, n := range names {
			nameSet[n] = true
		}
		if !nameSet["owasp"] {
			t.Error("expected 'owasp' in module names")
		}
		if !nameSet["injection"] {
			t.Error("expected 'injection' in module names")
		}
	})

	t.Run("GetModule_existing", func(t *testing.T) {
		mod, err := GetModule("owasp")
		if err != nil {
			t.Fatalf("GetModule('owasp') returned error: %v", err)
		}
		if mod.Name() != "owasp" {
			t.Errorf("expected module name 'owasp', got %q", mod.Name())
		}
	})

	t.Run("GetModule_nonexistent", func(t *testing.T) {
		_, err := GetModule("nonexistent-module")
		if err == nil {
			t.Error("expected error for nonexistent module, got nil")
		}
	})

	t.Run("ListModules_info", func(t *testing.T) {
		infos := ListModules()
		if len(infos) == 0 {
			t.Fatal("ListModules returned no info")
		}

		for _, info := range infos {
			if info.Name == "" {
				t.Error("module info has empty name")
			}
			if info.Category == "" {
				t.Error("module info has empty category")
			}
			if info.Requests == 0 {
				t.Errorf("module %q reports 0 requests", info.Name)
			}
		}
	})

	t.Run("FilterModules_empty_returns_all", func(t *testing.T) {
		all := AllModules()
		filtered := FilterModules(nil)
		if len(filtered) != len(all) {
			t.Errorf("FilterModules(nil) returned %d modules, expected %d", len(filtered), len(all))
		}
	})

	t.Run("FilterModules_specific", func(t *testing.T) {
		filtered := FilterModules([]string{"owasp"})
		if len(filtered) != 1 {
			t.Fatalf("expected 1 filtered module, got %d", len(filtered))
		}
		if filtered[0].Name() != "owasp" {
			t.Errorf("expected 'owasp', got %q", filtered[0].Name())
		}
	})

	t.Run("FilterModules_nonexistent", func(t *testing.T) {
		filtered := FilterModules([]string{"does-not-exist"})
		if len(filtered) != 0 {
			t.Errorf("expected 0 filtered modules for unknown name, got %d", len(filtered))
		}
	})
}
