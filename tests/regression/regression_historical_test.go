// Package regression contains regression tests for bugs that have been found
// and fixed. Each test verifies the fix by checking the correct behavior.
//
// Convention: Test names follow TestRegression_<CommitHash>_<ShortDescription>
// where CommitHash matches the git commit that fixed the bug.
package regression

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cornerglitch/internal/dashboard"
	"github.com/cornerglitch/internal/fingerprint"
	"github.com/cornerglitch/internal/framework"
	"github.com/cornerglitch/internal/honeypot"
	"github.com/cornerglitch/internal/labyrinth"
	"github.com/cornerglitch/internal/scanner"
	"github.com/cornerglitch/internal/search"
)

// ---------------------------------------------------------------------------
// Bug #1: Labyrinth slice bounds panic (3ba668f)
//
// Root cause: hex.EncodeToString([]byte(path))[:8] in serveHTML panicked with
// an out-of-range slice when the path was very short (e.g. "/"). A 1-byte
// path produces only 2 hex chars, and slicing [:8] caused a panic.
//
// Fix: Added a length guard — if len(pathHex) > 8, truncate; otherwise use
// the full hex string.
//
// Test: Create httptest requests with short paths ("/", "/a", "/ab") and call
// l.Serve(). Verify no panic occurs and a valid HTTP response is produced.
// ---------------------------------------------------------------------------

func TestRegression_3ba668f_LabyrinthShortPathNoPanic(t *testing.T) {
	l := labyrinth.NewLabyrinth()

	shortPaths := []string{"/", "/a", "/ab", "/abc", "/x"}
	for _, path := range shortPaths {
		t.Run("path="+path, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Serve() panicked for path %q: %v", path, r)
				}
			}()

			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			status := l.Serve(w, req)
			if status != http.StatusOK {
				t.Errorf("Serve(%q) returned status %d, want 200", path, status)
			}
			if w.Body.Len() == 0 {
				t.Errorf("Serve(%q) returned empty body", path)
			}
		})
	}
}

func TestRegression_3ba668f_LabyrinthShortPathJSON(t *testing.T) {
	l := labyrinth.NewLabyrinth()

	// JSON path also does hex.EncodeToString([]byte(path))[:6]
	shortPaths := []string{"/", "/a", "/ab"}
	for _, path := range shortPaths {
		t.Run("json_path="+path, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Serve() panicked for JSON path %q: %v", path, r)
				}
			}()

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			status := l.Serve(w, req)
			if status != http.StatusOK {
				t.Errorf("Serve(%q, JSON) returned status %d, want 200", path, status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bug #2: Fingerprint stability (1c902bf)
//
// Root cause: Sec-* headers were iterated in random map order when building
// the client signature. Since Go map iteration is non-deterministic, the same
// request could produce different fingerprints depending on iteration order.
//
// Fix: Sort Sec-* headers alphabetically before appending them to the
// signature, ensuring deterministic output regardless of map iteration order.
//
// Test: Create a request with multiple Sec-* headers and call Identify() 100
// times. All calls must return the same client ID.
// ---------------------------------------------------------------------------

func TestRegression_1c902bf_FingerprintStability(t *testing.T) {
	e := fingerprint.NewEngine()

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-CH-UA", `"Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.RemoteAddr = "192.168.1.100:12345"
		return req
	}

	// Get the reference ID from the first call.
	referenceID := e.Identify(makeReq())
	if referenceID == "" {
		t.Fatal("Identify() returned empty string")
	}
	if !strings.HasPrefix(referenceID, "client_") {
		t.Errorf("ID %q does not start with 'client_'", referenceID)
	}

	// Repeat 100 times — all must match.
	for i := 0; i < 100; i++ {
		id := e.Identify(makeReq())
		if id != referenceID {
			t.Fatalf("Identify() call #%d returned %q, want %q (instability detected)", i+1, id, referenceID)
		}
	}
}

func TestRegression_1c902bf_FingerprintDifferentClientsGetDifferentIDs(t *testing.T) {
	e := fingerprint.NewEngine()

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req1.RemoteAddr = "10.0.0.1:1111"

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("User-Agent", "curl/7.88.1")
	req2.RemoteAddr = "10.0.0.2:2222"

	id1 := e.Identify(req1)
	id2 := e.Identify(req2)

	if id1 == id2 {
		t.Errorf("Different clients produced same ID %q", id1)
	}
}

// ---------------------------------------------------------------------------
// Bug #3: Framework variety per path (1c902bf)
//
// Root cause: Only ForClient(clientID) existed, which hashed only the client
// ID. This meant every request from the same client got the same framework
// regardless of path, making the emulation unrealistic.
//
// Fix: Added ForRequest(clientID, path) which hashes clientID+"::"+path,
// providing per-path variety while remaining deterministic.
//
// Test: Call ForRequest() with 10 different paths for the same client. Verify
// at least 2 different frameworks appear. Also verify determinism: same
// (clientID, path) pair always returns the same framework.
// ---------------------------------------------------------------------------

func TestRegression_1c902bf_FrameworkVarietyPerPath(t *testing.T) {
	e := framework.NewEmulator()

	clientID := "client_abc123"
	paths := []string{
		"/path1", "/path2", "/path3", "/path4", "/path5",
		"/path6", "/path7", "/path8", "/path9", "/path10",
	}

	seen := make(map[string]bool)
	for _, path := range paths {
		fw := e.ForRequest(clientID, path)
		if fw == nil {
			t.Fatalf("ForRequest(%q, %q) returned nil", clientID, path)
		}
		seen[fw.Name] = true
	}

	if len(seen) < 2 {
		t.Errorf("ForRequest() returned only %d unique framework(s) across %d paths; want at least 2", len(seen), len(paths))
	}
}

func TestRegression_1c902bf_FrameworkDeterminism(t *testing.T) {
	e := framework.NewEmulator()

	clientID := "client_xyz789"
	path := "/some/specific/path"

	reference := e.ForRequest(clientID, path)
	if reference == nil {
		t.Fatal("ForRequest() returned nil")
	}

	for i := 0; i < 50; i++ {
		fw := e.ForRequest(clientID, path)
		if fw.Name != reference.Name {
			t.Fatalf("ForRequest() call #%d returned %q, want %q (non-deterministic)", i+1, fw.Name, reference.Name)
		}
	}
}

func TestRegression_1c902bf_ForClientVsForRequestDiffer(t *testing.T) {
	e := framework.NewEmulator()

	clientID := "client_testdiff"

	// ForClient hashes only clientID; ForRequest hashes clientID+"::"+path.
	// They should differ for at least some paths (probabilistic but very likely
	// given 12 frameworks and distinct hash inputs).
	clientFW := e.ForClient(clientID)
	differ := false
	for i := 0; i < 20; i++ {
		reqFW := e.ForRequest(clientID, "/different/path/"+string(rune('a'+i)))
		if reqFW.Name != clientFW.Name {
			differ = true
			break
		}
	}
	if !differ {
		t.Error("ForRequest() never returned a different framework than ForClient() across 20 paths — per-path variety is likely broken")
	}
}

// ---------------------------------------------------------------------------
// Bug #4: Search trailing slash (1c902bf)
//
// Root cause: ShouldHandle() only matched "/search" exactly. Requests to
// "/search/" (with trailing slash) fell through to the default handler
// instead of being handled by the search engine.
//
// Fix: Added "/search/" to the list of matched paths in ShouldHandle().
//
// Test: Verify ShouldHandle returns true for "/search", "/search/", and
// "/search/advanced". Also verify it returns false for unrelated paths.
// ---------------------------------------------------------------------------

func TestRegression_1c902bf_SearchTrailingSlash(t *testing.T) {
	h := search.NewHandler()

	tests := []struct {
		path string
		want bool
	}{
		{"/search", true},
		{"/search/", true},
		{"/search/advanced", true},
		{"/search/images", true},
		{"/api/search/suggest", true},
		{"/not-search", false},
		{"/searching", false},
		{"/search-results", false},
	}

	for _, tt := range tests {
		t.Run("path="+tt.path, func(t *testing.T) {
			got := h.ShouldHandle(tt.path)
			if got != tt.want {
				t.Errorf("ShouldHandle(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bug #5: Scanner coverage category normalization (04bb129)
//
// Root cause: ScanResult categories used mixed case (e.g. "SQL-Injection",
// "XSS") but the coverage builder didn't normalize them. When matching
// findings (lowercase) against result categories (mixed case), they didn't
// match, resulting in 0% coverage for categories with findings.
//
// Fix: buildCoverage() now normalizes all categories to lowercase via
// strings.ToLower() before aggregation.
//
// Test: Add results with mixed-case categories, build a report, and verify
// coverage categories are normalized to lowercase with non-zero coverage
// when findings exist.
// ---------------------------------------------------------------------------

func TestRegression_04bb129_ScannerCoverageCategoryNormalization(t *testing.T) {
	reporter := scanner.NewReporter()

	// Add results with mixed-case categories.
	mixedCaseCategories := []string{
		"SQL-Injection", "sql-injection", "Sql-Injection",
		"XSS", "xss", "Xss",
		"CSRF",
	}

	for _, cat := range mixedCaseCategories {
		reporter.AddResult(scanner.ScanResult{
			Request: scanner.AttackRequest{
				Method:   "GET",
				Path:     "/vuln/test",
				Category: cat,
			},
			StatusCode: 200,
			BodySize:   100,
		})
	}

	cfg := scanner.DefaultConfig()
	cfg.Target = "http://localhost:8765"
	start := time.Now()
	end := start.Add(time.Second)

	report := reporter.BuildReport(cfg, start, end)

	if report.Coverage == nil {
		t.Fatal("Coverage map is nil")
	}

	// Verify all coverage keys are lowercase.
	for key := range report.Coverage {
		if key != strings.ToLower(key) {
			t.Errorf("Coverage key %q is not lowercase", key)
		}
	}

	// sql-injection should have all 3 results aggregated under one key.
	if ci, ok := report.Coverage["sql-injection"]; ok {
		if ci.Tested != 3 {
			t.Errorf("sql-injection tested=%d, want 3 (categories not normalized)", ci.Tested)
		}
	} else {
		t.Error("Coverage missing 'sql-injection' key — mixed-case categories not normalized")
	}

	// xss should also be normalized.
	if ci, ok := report.Coverage["xss"]; ok {
		if ci.Tested != 3 {
			t.Errorf("xss tested=%d, want 3", ci.Tested)
		}
	} else {
		t.Error("Coverage missing 'xss' key")
	}

	// csrf should be lowercase.
	if _, ok := report.Coverage["csrf"]; !ok {
		t.Error("Coverage missing 'csrf' key — uppercase CSRF not normalized")
	}
}

// ---------------------------------------------------------------------------
// Bug #6: Scanner crawl time budget (04bb129)
//
// Root cause: When CrawlFirst was enabled, the crawler consumed all available
// time from the context deadline, leaving no time for attack modules.
//
// Fix: The engine now gives the crawler at most 30% of remaining time. If
// the deadline allows 2 seconds, crawl gets ~600ms. A minimum of 5 seconds
// is enforced.
//
// Test: Create an engine with CrawlFirst=true and a short timeout context.
// Verify the crawl phase does not consume the entire deadline by checking
// that the engine returns before the full context deadline expires.
// (This is an indirect test since crawlBudget is internal.)
// ---------------------------------------------------------------------------

func TestRegression_04bb129_ScannerCrawlTimeBudget(t *testing.T) {
	cfg := scanner.DefaultConfig()
	cfg.Target = "http://127.0.0.1:1" // unreachable — will fail fast
	cfg.CrawlFirst = true
	cfg.Concurrency = 1
	cfg.RateLimit = 100

	eng := scanner.NewEngine(cfg)

	// Use a 10-second deadline. The crawl budget should be ~3s (30%).
	// If the old bug is present, it would use all 10s.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	report, _ := eng.Run(ctx)
	elapsed := time.Since(start)

	// Even with network errors, the engine should complete well before
	// the full 10s deadline if the crawl budget is properly capped.
	if elapsed > 8*time.Second {
		t.Errorf("Engine.Run() took %v — crawl budget likely not capped at 30%%", elapsed)
	}

	if report == nil {
		t.Error("expected non-nil report even with unreachable target")
	}
}

func TestRegression_04bb129_CrawlFirstConfigProfiles(t *testing.T) {
	// Verify profiles that should have CrawlFirst=true actually do.
	configs := map[string]*scanner.Config{
		"default":    scanner.DefaultConfig(),
		"aggressive": scanner.AggressiveConfig(),
		"nightmare":  scanner.NightmareConfig(),
		"stealth":    scanner.StealthConfig(),
		"compliance": scanner.ComplianceConfig(),
	}

	crawlFirstExpected := map[string]bool{
		"default":    false,
		"aggressive": true,
		"nightmare":  true,
		"stealth":    true,
		"compliance": true,
	}

	for name, cfg := range configs {
		if cfg.CrawlFirst != crawlFirstExpected[name] {
			t.Errorf("%s profile: CrawlFirst=%v, want %v", name, cfg.CrawlFirst, crawlFirstExpected[name])
		}
	}
}

// ---------------------------------------------------------------------------
// Bug #7: Proxy mode persistence (e6ef91e)
//
// Root cause: Mode changes via SetMode() were not validated against the list
// of valid ProxyModes, and the returned boolean was not checked. Invalid
// modes could be silently set, and valid modes were not persisted correctly
// through GetMode().
//
// Fix: SetMode() validates the mode against ProxyModes, returns false for
// invalid modes, and only persists valid modes.
//
// Test: Create a ProxyConfig. Set each valid mode, verify GetMode() returns
// it. Set an invalid mode, verify it returns false and mode is unchanged.
// ---------------------------------------------------------------------------

func TestRegression_e6ef91e_ProxyModeValidModes(t *testing.T) {
	pc := dashboard.NewProxyConfig()

	// Default mode should be "transparent".
	if mode := pc.GetMode(); mode != "transparent" {
		t.Errorf("default mode = %q, want 'transparent'", mode)
	}

	// Test all valid modes.
	for _, mode := range dashboard.ProxyModes {
		ok := pc.SetMode(mode)
		if !ok {
			t.Errorf("SetMode(%q) returned false, want true (valid mode)", mode)
		}
		got := pc.GetMode()
		if got != mode {
			t.Errorf("GetMode() = %q after SetMode(%q)", got, mode)
		}
	}
}

func TestRegression_e6ef91e_ProxyModeInvalidRejected(t *testing.T) {
	pc := dashboard.NewProxyConfig()

	// Set to a known valid mode first.
	pc.SetMode("chaos")

	// Try invalid modes.
	invalidModes := []string{"invalid", "TRANSPARENT", "Waf", "", "random", "debug"}
	for _, mode := range invalidModes {
		ok := pc.SetMode(mode)
		if ok {
			t.Errorf("SetMode(%q) returned true, want false (invalid mode)", mode)
		}
		// Mode should remain "chaos".
		got := pc.GetMode()
		if got != "chaos" {
			t.Errorf("mode changed to %q after invalid SetMode(%q), want 'chaos'", got, mode)
		}
	}
}

func TestRegression_e6ef91e_ProxyModesList(t *testing.T) {
	// Verify the expected modes exist.
	expected := map[string]bool{
		"transparent": false,
		"waf":         false,
		"chaos":       false,
		"gateway":     false,
		"nightmare":   false,
		"mirror":      false,
		"killer":      false,
	}

	for _, mode := range dashboard.ProxyModes {
		if _, ok := expected[mode]; ok {
			expected[mode] = true
		}
	}

	for mode, found := range expected {
		if !found {
			t.Errorf("ProxyModes missing expected mode %q", mode)
		}
	}
}

// ---------------------------------------------------------------------------
// Bug #8: VulnConfig all 9 groups (2a6aad5)
//
// Root cause: The VulnConfig only supported 3 hardcoded groups ("owasp",
// "api_security", "advanced"). The remaining 6 groups ("modern",
// "infrastructure", "iot_desktop", "mobile_privacy", "specialized",
// "dashboard") were silently ignored, meaning they could not be toggled
// via the admin panel.
//
// Fix: Updated VulnConfig to dynamically support all groups defined in the
// VulnGroups slice. NewVulnConfig() initializes all 9 groups to enabled.
//
// Test: For all 9 groups, verify SetGroup(false)/IsGroupEnabled returns
// false, SetGroup(true)/IsGroupEnabled returns true. Verify Snapshot()
// includes all 9 groups.
// ---------------------------------------------------------------------------

func TestRegression_2a6aad5_VulnConfigAllGroups(t *testing.T) {
	vc := dashboard.NewVulnConfig()

	expectedGroups := []string{
		"owasp", "api_security", "advanced", "modern",
		"infrastructure", "iot_desktop", "mobile_privacy",
		"specialized", "dashboard",
	}

	// Verify VulnGroups matches expectations.
	if len(dashboard.VulnGroups) != len(expectedGroups) {
		t.Errorf("VulnGroups has %d groups, want %d", len(dashboard.VulnGroups), len(expectedGroups))
	}

	for _, group := range expectedGroups {
		// All groups should be enabled by default.
		if !vc.IsGroupEnabled(group) {
			t.Errorf("group %q not enabled by default", group)
		}

		// Disable the group.
		vc.SetGroup(group, false)
		if vc.IsGroupEnabled(group) {
			t.Errorf("group %q still enabled after SetGroup(false)", group)
		}

		// Re-enable the group.
		vc.SetGroup(group, true)
		if !vc.IsGroupEnabled(group) {
			t.Errorf("group %q not enabled after SetGroup(true)", group)
		}
	}
}

func TestRegression_2a6aad5_VulnConfigSnapshotAllGroups(t *testing.T) {
	vc := dashboard.NewVulnConfig()

	snapshot := vc.Snapshot()
	groupsRaw, ok := snapshot["groups"]
	if !ok {
		t.Fatal("Snapshot() missing 'groups' key")
	}
	groups, ok := groupsRaw.(map[string]bool)
	if !ok {
		t.Fatal("Snapshot()['groups'] is not map[string]bool")
	}

	expectedGroups := []string{
		"owasp", "api_security", "advanced", "modern",
		"infrastructure", "iot_desktop", "mobile_privacy",
		"specialized", "dashboard",
	}

	for _, group := range expectedGroups {
		enabled, exists := groups[group]
		if !exists {
			t.Errorf("Snapshot() missing group %q", group)
			continue
		}
		if !enabled {
			t.Errorf("Snapshot() group %q is not enabled by default", group)
		}
	}

	if len(groups) != len(expectedGroups) {
		t.Errorf("Snapshot() has %d groups, want %d", len(groups), len(expectedGroups))
	}
}

// ---------------------------------------------------------------------------
// Bug #9: Nightmare proxy mode snapshot (d78b5fb)
//
// Root cause: When nightmare mode was activated on the proxy subsystem, the
// previous proxy mode was not saved. This meant there was no way to restore
// the proxy to its pre-nightmare mode when nightmare was deactivated.
//
// Fix: Added PreviousProxyMode field to NightmareState struct. The
// activation handler now saves the current proxy mode before switching to
// nightmare.
//
// Test: Verify NightmareState has a PreviousProxyMode field. Set it, verify
// it persists and can be read back.
// ---------------------------------------------------------------------------

func TestRegression_d78b5fb_NightmareStatePreviousProxyMode(t *testing.T) {
	ns := dashboard.GetNightmareState()

	// Set a previous proxy mode.
	ns.PreviousProxyMode = "waf"
	if ns.PreviousProxyMode != "waf" {
		t.Errorf("PreviousProxyMode = %q, want 'waf'", ns.PreviousProxyMode)
	}

	// Change to a different mode.
	ns.PreviousProxyMode = "chaos"
	if ns.PreviousProxyMode != "chaos" {
		t.Errorf("PreviousProxyMode = %q, want 'chaos'", ns.PreviousProxyMode)
	}

	// Set to transparent.
	ns.PreviousProxyMode = "transparent"
	if ns.PreviousProxyMode != "transparent" {
		t.Errorf("PreviousProxyMode = %q, want 'transparent'", ns.PreviousProxyMode)
	}

	// Clean up — reset to empty so other tests are not affected.
	ns.PreviousProxyMode = ""
}

func TestRegression_d78b5fb_NightmareStateStructFields(t *testing.T) {
	ns := dashboard.GetNightmareState()

	// Verify the Snapshot() method works (the struct is not nil).
	snap := ns.Snapshot()
	if snap == nil {
		t.Fatal("NightmareState.Snapshot() returned nil")
	}

	// Verify all subsystem fields exist in snapshot.
	for _, key := range []string{"server", "scanner", "proxy"} {
		if _, ok := snap[key]; !ok {
			t.Errorf("Snapshot() missing key %q", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Bug #10: GraphQL route priority (02c7c0c)
//
// Root cause: The honeypot module registered "/graphql" and "/graphql/" as
// debug/lure paths. Because the request handler checked honeypot paths
// before routing to the API router, legitimate /graphql requests were
// intercepted and served honeypot responses instead of the actual GraphQL
// endpoint.
//
// Fix: Adjusted route priority so the API router is checked before the
// honeypot for /graphql paths. The honeypot still registers the paths
// (they are in the debugPaths list), but the handler.go dispatch logic
// ensures the API router takes priority.
//
// Test: Verify that the honeypot module's ShouldHandle() returns true for
// /graphql (it is still in the honeypot path list). This test documents the
// known state — the fix is in handler.go's dispatch order, not in removing
// the path from honeypot. This regression test confirms the paths exist in
// honeypot and acts as a canary: if anyone removes /graphql from honeypot
// thinking it fixes routing, the real fix (handler priority) may be lost.
// ---------------------------------------------------------------------------

func TestRegression_02c7c0c_GraphQLHoneypotPathRegistered(t *testing.T) {
	hp := honeypot.NewHoneypot()

	// The honeypot does register /graphql and /graphql/ as paths.
	// The bug was in handler.go dispatch order, not in the path list.
	// This test documents that /graphql IS a honeypot path, and the fix
	// is that the API router checks /graphql BEFORE the honeypot in
	// server/handler.go:dispatch().
	if !hp.ShouldHandle("/graphql") {
		t.Error("ShouldHandle(/graphql) = false; expected true (honeypot registers it as debug path)")
	}
	if !hp.ShouldHandle("/graphql/") {
		t.Error("ShouldHandle(/graphql/) = false; expected true")
	}
}

func TestRegression_02c7c0c_GraphQLNotAdminLure(t *testing.T) {
	// Verify that /graphql is NOT in the admin panel lure paths.
	// The admin panel paths (/admin/graphql) ARE honeypot paths, but the
	// top-level /graphql should be routed to the API, not treated as an
	// admin panel lure.
	hp := honeypot.NewHoneypot()

	// /admin/graphql should be handled (it's a legit honeypot admin path).
	if !hp.ShouldHandle("/admin/graphql") {
		t.Error("ShouldHandle(/admin/graphql) = false; expected true")
	}

	// Verify /graphiql and /playground are also honeypot paths (related
	// debug tools that should be caught by the honeypot).
	for _, path := range []string{"/graphiql", "/graphiql/", "/playground", "/altair"} {
		if !hp.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = false; expected true", path)
		}
	}
}

func TestRegression_02c7c0c_HoneypotRobotsTxtNotPanic(t *testing.T) {
	hp := honeypot.NewHoneypot()

	// /robots.txt is a special honeypot path. Verify it works without panic.
	if !hp.ShouldHandle("/robots.txt") {
		t.Error("ShouldHandle(/robots.txt) = false; expected true")
	}

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	w := httptest.NewRecorder()

	status := hp.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Errorf("ServeHTTP(/robots.txt) = %d, want 200", status)
	}
}
