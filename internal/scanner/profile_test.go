package scanner

import (
	"testing"
)

// allFeaturesEnabled returns a feature map with every feature turned on.
func allFeaturesEnabled() map[string]bool {
	return map[string]bool{
		"labyrinth":       true,
		"error_inject":    true,
		"captcha":         true,
		"honeypot":        true,
		"vuln":            true,
		"analytics":       true,
		"cdn":             true,
		"oauth":           true,
		"header_corrupt":  true,
		"cookie_traps":    true,
		"js_traps":        true,
		"bot_detection":   true,
		"random_blocking": true,
		"framework_emul":  true,
		"search":          true,
		"email":           true,
		"i18n":            true,
		"recorder":        true,
		"websocket":       true,
		"privacy":         true,
		"health":          true,
	}
}

func defaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"max_labyrinth_depth":    50,
		"error_rate_multiplier":  1.0,
		"captcha_trigger_thresh": 100,
		"block_chance":           0.02,
		"block_duration_sec":     30,
		"bot_score_threshold":    60.0,
		"header_corrupt_level":   1,
		"delay_min_ms":           0,
		"delay_max_ms":           0,
		"labyrinth_link_density": 8,
		"adaptive_interval_sec":  30,
	}
}

func TestComputeProfile_AllFeaturesEnabled(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	if profile == nil {
		t.Fatal("ComputeProfile returned nil")
	}

	if profile.ServerPort != 8765 {
		t.Errorf("ServerPort = %d, want 8765", profile.ServerPort)
	}

	if profile.DashboardPort != 8766 {
		t.Errorf("DashboardPort = %d, want 8766", profile.DashboardPort)
	}

	// With all features enabled, we should have 40+ vuln categories
	if profile.TotalVulns < 40 {
		t.Errorf("TotalVulns = %d, want >= 40", profile.TotalVulns)
	}

	// Check that all OWASP categories are present
	owaspIDs := []string{
		"owasp-a01", "owasp-a02", "owasp-a03", "owasp-a04", "owasp-a05",
		"owasp-a06", "owasp-a07", "owasp-a08", "owasp-a09", "owasp-a10",
	}
	vulnIDs := make(map[string]bool)
	for _, v := range profile.Vulnerabilities {
		vulnIDs[v.ID] = true
	}
	for _, id := range owaspIDs {
		if !vulnIDs[id] {
			t.Errorf("missing OWASP category %s in profile", id)
		}
	}

	// Check advanced vulns are present
	advancedIDs := []string{
		"cors-misconfig", "xxe-injection", "ssti", "crlf-injection",
		"host-header-injection", "verb-tamper", "hpp", "file-upload",
		"cmd-injection", "graphql-vuln", "jwt-vuln", "race-condition",
		"deserialization", "path-traversal", "open-redirect",
	}
	for _, id := range advancedIDs {
		if !vulnIDs[id] {
			t.Errorf("missing advanced vuln %s in profile", id)
		}
	}

	// Check dashboard vulns are present
	dashIDs := []string{
		"dashboard-unauth", "debug-info", "api-keys-exposed",
		"user-data-exposed", "backup-download", "insecure-settings",
		"database-creds", "email-creds", "integration-keys",
		"audit-log", "feature-flags-secrets", "service-credentials",
	}
	for _, id := range dashIDs {
		if !vulnIDs[id] {
			t.Errorf("missing dashboard vuln %s in profile", id)
		}
	}

	// Check honeypot vulns are present
	honeyIDs := []string{
		"honeypot-admin", "honeypot-config", "honeypot-backup",
		"honeypot-git", "honeypot-debug", "honeypot-shell",
	}
	for _, id := range honeyIDs {
		if !vulnIDs[id] {
			t.Errorf("missing honeypot vuln %s in profile", id)
		}
	}

	// Check missing header vulns
	headerIDs := []string{
		"missing-hsts", "missing-csp", "missing-x-frame-options",
		"missing-x-content-type-options", "missing-referrer-policy",
		"missing-permissions-policy",
	}
	for _, id := range headerIDs {
		if !vulnIDs[id] {
			t.Errorf("missing header vuln %s in profile", id)
		}
	}

	// Check cookie trap vulns
	cookieIDs := []string{
		"cookie-no-secure", "cookie-no-httponly", "cookie-tracking",
	}
	for _, id := range cookieIDs {
		if !vulnIDs[id] {
			t.Errorf("missing cookie vuln %s in profile", id)
		}
	}

	// Check header corruption vulns
	corruptIDs := []string{
		"header-corruption", "header-huge",
	}
	for _, id := range corruptIDs {
		if !vulnIDs[id] {
			t.Errorf("missing header corruption vuln %s in profile", id)
		}
	}

	// Check server info vulns
	infoIDs := []string{
		"server-version-disclosure", "x-powered-by", "debug-mode-header",
	}
	for _, id := range infoIDs {
		if !vulnIDs[id] {
			t.Errorf("missing server info vuln %s in profile", id)
		}
	}

	// Check severity breakdown has all levels
	for _, sev := range []string{"critical", "high", "medium"} {
		if profile.BySeverity[sev] == 0 {
			t.Errorf("no vulns with severity %s", sev)
		}
	}

	// Check endpoints
	if profile.TotalEndpoints < 50 {
		t.Errorf("TotalEndpoints = %d, want >= 50", profile.TotalEndpoints)
	}

	// Check expected rates are set
	if profile.ExpectedErrorRate <= 0 {
		t.Errorf("ExpectedErrorRate = %f, want > 0", profile.ExpectedErrorRate)
	}
	if profile.ExpectedLabyrinthRate <= 0 {
		t.Errorf("ExpectedLabyrinthRate = %f, want > 0", profile.ExpectedLabyrinthRate)
	}
	if profile.ExpectedBlockRate <= 0 {
		t.Errorf("ExpectedBlockRate = %f, want > 0", profile.ExpectedBlockRate)
	}
}

func TestComputeProfile_VulnDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["vuln"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Should not contain any OWASP vulns when vuln is disabled
	for _, v := range profile.Vulnerabilities {
		if v.ID == "owasp-a01" || v.ID == "cors-misconfig" || v.ID == "dashboard-unauth" {
			t.Errorf("profile contains vuln %s despite vuln feature being disabled", v.ID)
		}
	}

	// Should still have header and server info vulns
	found := false
	for _, v := range profile.Vulnerabilities {
		if v.ID == "missing-hsts" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing missing-hsts when vuln disabled (should always be present)")
	}
}

func TestComputeProfile_HoneypotDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["honeypot"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	for _, v := range profile.Vulnerabilities {
		if v.ID == "honeypot-admin" || v.ID == "honeypot-config" {
			t.Errorf("profile contains %s despite honeypot being disabled", v.ID)
		}
	}
}

func TestComputeProfile_ErrorInjectDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["error_inject"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	if profile.ExpectedErrorRate != 0.0 {
		t.Errorf("ExpectedErrorRate = %f, want 0 when error_inject disabled", profile.ExpectedErrorRate)
	}
}

func TestComputeProfile_LabyrinthDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["labyrinth"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	if profile.ExpectedLabyrinthRate != 0.0 {
		t.Errorf("ExpectedLabyrinthRate = %f, want 0 when labyrinth disabled", profile.ExpectedLabyrinthRate)
	}
}

func TestComputeProfile_BlockingDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["random_blocking"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	if profile.ExpectedBlockRate != 0.0 {
		t.Errorf("ExpectedBlockRate = %f, want 0 when random_blocking disabled", profile.ExpectedBlockRate)
	}
}

func TestComputeProfile_CaptchaDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["captcha"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	if profile.ExpectedCaptchaRate != 0.0 {
		t.Errorf("ExpectedCaptchaRate = %f, want 0 when captcha disabled", profile.ExpectedCaptchaRate)
	}
}

func TestComputeProfile_ErrorRateMultiplier(t *testing.T) {
	features := allFeaturesEnabled()

	config1 := defaultConfig()
	config1["error_rate_multiplier"] = 1.0
	p1 := ComputeProfile(features, config1, 8765, 8766)

	config2 := defaultConfig()
	config2["error_rate_multiplier"] = 2.0
	p2 := ComputeProfile(features, config2, 8765, 8766)

	if p2.ExpectedErrorRate <= p1.ExpectedErrorRate {
		t.Errorf("higher error_rate_multiplier should produce higher ExpectedErrorRate: %f <= %f",
			p2.ExpectedErrorRate, p1.ExpectedErrorRate)
	}
}

func TestComputeProfile_HeaderCorruptDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["header_corrupt"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	for _, v := range profile.Vulnerabilities {
		if v.ID == "header-corruption" || v.ID == "header-huge" {
			t.Errorf("profile contains %s despite header_corrupt being disabled", v.ID)
		}
	}
}

func TestComputeProfile_CookieTrapsDisabled(t *testing.T) {
	features := allFeaturesEnabled()
	features["cookie_traps"] = false
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	for _, v := range profile.Vulnerabilities {
		if v.ID == "cookie-no-secure" || v.ID == "cookie-no-httponly" || v.ID == "cookie-tracking" {
			t.Errorf("profile contains %s despite cookie_traps being disabled", v.ID)
		}
	}
}

func TestComputeProfile_SeverityBreakdown(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Verify BySeverity sums to TotalVulns
	total := 0
	for _, count := range profile.BySeverity {
		total += count
	}
	if total != profile.TotalVulns {
		t.Errorf("BySeverity sum %d != TotalVulns %d", total, profile.TotalVulns)
	}
}

func TestComputeProfile_EndpointsByType(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Should have endpoint types
	if len(profile.EndpointsByType) == 0 {
		t.Error("EndpointsByType is empty")
	}
}

// ---------------------------------------------------------------------------
// CompareResults tests
// ---------------------------------------------------------------------------

func TestCompareResults_PerfectScanner(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Build a perfect scan result that finds every detectable vuln
	result := &ScanResult{
		Scanner: "perfect-scanner",
	}
	for _, v := range profile.Vulnerabilities {
		if v.Detectable {
			url := ""
			if len(v.Endpoints) > 0 {
				url = v.Endpoints[0]
			}
			result.Findings = append(result.Findings, Finding{
				ID:          "found-" + v.ID,
				Title:       v.Name,
				Severity:    v.Severity,
				URL:         url,
				Description: v.Description,
				CWE:         v.CWE,
			})
		}
	}

	report := CompareResults(profile, result)

	if report.Grade != "A" {
		t.Errorf("Grade = %s, want A for perfect scanner", report.Grade)
	}

	if report.DetectionRate < 0.80 {
		t.Errorf("DetectionRate = %f, want >= 0.80 for perfect scanner", report.DetectionRate)
	}

	if len(report.FalseNegatives) > 0 {
		t.Errorf("FalseNegatives = %d, want 0 for perfect scanner", len(report.FalseNegatives))
	}

	if len(report.FalsePositives) > 0 {
		t.Errorf("FalsePositives = %d, want 0 for perfect scanner", len(report.FalsePositives))
	}
}

func TestCompareResults_EmptyScanner(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	result := &ScanResult{
		Scanner: "empty-scanner",
	}

	report := CompareResults(profile, result)

	if report.Grade != "F" {
		t.Errorf("Grade = %s, want F for empty scanner", report.Grade)
	}

	if report.DetectionRate != 0 {
		t.Errorf("DetectionRate = %f, want 0 for empty scanner", report.DetectionRate)
	}

	if len(report.TruePositives) != 0 {
		t.Errorf("TruePositives = %d, want 0 for empty scanner", len(report.TruePositives))
	}

	// All detectable vulns should be false negatives
	detectableCount := 0
	for _, v := range profile.Vulnerabilities {
		if v.Detectable {
			detectableCount++
		}
	}
	if len(report.FalseNegatives) != detectableCount {
		t.Errorf("FalseNegatives = %d, want %d for empty scanner", len(report.FalseNegatives), detectableCount)
	}
}

func TestCompareResults_PartialScanner(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Find only OWASP vulns
	result := &ScanResult{
		Scanner: "partial-scanner",
	}
	for _, v := range profile.Vulnerabilities {
		if v.Detectable && (v.OWASP == "A01:2021" || v.OWASP == "A03:2021") {
			url := ""
			if len(v.Endpoints) > 0 {
				url = v.Endpoints[0]
			}
			result.Findings = append(result.Findings, Finding{
				ID:          "found-" + v.ID,
				Title:       v.Name,
				Severity:    v.Severity,
				URL:         url,
				Description: v.Description,
				CWE:         v.CWE,
			})
		}
	}

	report := CompareResults(profile, result)

	if report.DetectionRate <= 0 {
		t.Error("DetectionRate should be > 0 for partial scanner")
	}
	if report.DetectionRate >= 1.0 {
		t.Error("DetectionRate should be < 1.0 for partial scanner")
	}

	if len(report.TruePositives) == 0 {
		t.Error("TruePositives should be > 0 for partial scanner")
	}

	if len(report.FalseNegatives) == 0 {
		t.Error("FalseNegatives should be > 0 for partial scanner")
	}

	// Grade should be between A and F
	validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !validGrades[report.Grade] {
		t.Errorf("invalid grade: %s", report.Grade)
	}
}

func TestCompareResults_FalsePositives(t *testing.T) {
	// Use a minimal profile with only one very specific vuln to ensure
	// gibberish findings cannot keyword-match against it.
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{
				ID:          "specific-xyzzy",
				Name:        "Zyglorphian Quuxblatter",
				Severity:    "high",
				Endpoints:   []string{"/zyglorp/quux"},
				Description: "A zyglorphian quuxblatter on the frobnitz endpoint",
				Detectable:  true,
			},
		},
		TotalVulns: 1,
		BySeverity: map[string]int{"high": 1},
	}

	// Scanner reports unrelated findings that cannot match the single vuln
	result := &ScanResult{
		Scanner: "false-positive-scanner",
		Findings: []Finding{
			{
				ID:          "fp-aaa",
				Title:       "Wombat Sneezeguard Missing",
				Severity:    "critical",
				URL:         "/wombat/sneeze",
				Description: "Sneezeguard not found on wombat",
			},
			{
				ID:          "fp-bbb",
				Title:       "Platypus Venom Overflow",
				Severity:    "high",
				URL:         "/platypus/venom",
				Description: "Venom overflow in platypus subsystem",
			},
		},
	}

	report := CompareResults(profile, result)

	if len(report.FalsePositives) != 2 {
		t.Errorf("FalsePositives = %d, want 2", len(report.FalsePositives))
	}

	if report.FalsePositiveRate <= 0 {
		t.Error("FalsePositiveRate should be > 0 when there are false positives and no true positives")
	}

	if len(report.FalseNegatives) != 1 {
		t.Errorf("FalseNegatives = %d, want 1 (the single expected vuln)", len(report.FalseNegatives))
	}
}

func TestCompareResults_CrashedScanner(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	result := &ScanResult{
		Scanner: "crashed-scanner",
		Crashed: true,
		Errors:  []string{"segfault at address 0x0"},
	}

	report := CompareResults(profile, result)

	if !report.ScannerCrashed {
		t.Error("ScannerCrashed should be true")
	}
	if len(report.ScannerErrors) != 1 {
		t.Errorf("ScannerErrors = %d, want 1", len(report.ScannerErrors))
	}
}

func TestCompareResults_TimedOutScanner(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	result := &ScanResult{
		Scanner:  "timeout-scanner",
		TimedOut: true,
	}

	report := CompareResults(profile, result)

	if !report.ScannerTimedOut {
		t.Error("ScannerTimedOut should be true")
	}
}

func TestCompareResults_CWEMatching(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	// Find vulns only by CWE, using a different URL
	result := &ScanResult{
		Scanner: "cwe-scanner",
		Findings: []Finding{
			{
				ID:          "cwe-match-1",
				Title:       "SQL Injection Found",
				Severity:    "critical",
				URL:         "/vuln/a03/sqli",
				Description: "injection detected",
				CWE:         "CWE-79",
			},
		},
	}

	report := CompareResults(profile, result)

	// Should match owasp-a03 via CWE + URL
	if len(report.TruePositives) == 0 {
		t.Error("should have at least one true positive from CWE matching")
	}
}

func TestCompareResults_URLMatching(t *testing.T) {
	features := allFeaturesEnabled()
	config := defaultConfig()
	profile := ComputeProfile(features, config, 8765, 8766)

	result := &ScanResult{
		Scanner: "url-scanner",
		Findings: []Finding{
			{
				ID:       "url-match-1",
				Title:    "Found something at vuln endpoint",
				Severity: "medium",
				URL:      "http://localhost:8765/vuln/cors/reflect",
			},
		},
	}

	report := CompareResults(profile, result)

	if len(report.TruePositives) == 0 {
		t.Error("should have at least one true positive from URL matching")
	}
}

func TestComputeGrade(t *testing.T) {
	tests := []struct {
		rate float64
		want string
	}{
		{0.95, "A"},
		{0.81, "A"},
		{0.80, "B"},
		{0.61, "B"},
		{0.60, "C"},
		{0.41, "C"},
		{0.40, "D"},
		{0.21, "D"},
		{0.20, "F"},
		{0.0, "F"},
	}

	for _, tt := range tests {
		got := computeGrade(tt.rate)
		if got != tt.want {
			t.Errorf("computeGrade(%f) = %s, want %s", tt.rate, got, tt.want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CWE-79", "CWE-79"},
		{"cwe-79", "CWE-79"},
		{"CWE79", "CWE-79"},
		{"79", "CWE-79"},
		{" CWE-284 ", "CWE-284"},
	}

	for _, tt := range tests {
		got := normalizeCWE(tt.input)
		if got != tt.want {
			t.Errorf("normalizeCWE(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestURLOverlap(t *testing.T) {
	endpoints := []string{"/vuln/a01/", "/admin/users"}

	tests := []struct {
		url  string
		want bool
	}{
		{"/vuln/a01/idor", true},
		{"http://localhost:8765/vuln/a01/test", true},
		{"/admin/users", true},
		{"/something/else", false},
		{"", false},
	}

	for _, tt := range tests {
		got := urlOverlap(endpoints, tt.url)
		if got != tt.want {
			t.Errorf("urlOverlap(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestKeywordMatch(t *testing.T) {
	vuln := VulnCategory{
		ID:          "owasp-a03",
		Name:        "Injection",
		Description: "SQL injection and XSS attacks with reflected user input",
	}

	tests := []struct {
		finding Finding
		want    bool
	}{
		{
			Finding{Title: "SQL Injection in search parameter", Description: "reflected input found"},
			true,
		},
		{
			Finding{Title: "Completely unrelated thing", Description: "nothing to see here"},
			false,
		},
	}

	for _, tt := range tests {
		got := keywordMatch(vuln, tt.finding)
		if got != tt.want {
			t.Errorf("keywordMatch with title=%q = %v, want %v", tt.finding.Title, got, tt.want)
		}
	}
}

func TestFeatureEnabled(t *testing.T) {
	features := map[string]bool{
		"vuln":   true,
		"captcha": false,
	}

	if !featureEnabled(features, "vuln") {
		t.Error("featureEnabled should return true for enabled feature")
	}
	if featureEnabled(features, "captcha") {
		t.Error("featureEnabled should return false for disabled feature")
	}
	if featureEnabled(features, "nonexistent") {
		t.Error("featureEnabled should return false for missing feature")
	}
}
