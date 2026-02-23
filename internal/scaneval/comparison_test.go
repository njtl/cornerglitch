package scaneval

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: build a ComparisonReport from a set of found vuln IDs against a
// profile. This avoids duplicating profile+result construction in every test.
// ---------------------------------------------------------------------------

func buildTestProfile() *ExpectedProfile {
	return &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "vuln-1", Name: "SQL Injection", Severity: "critical", Endpoints: []string{"/vuln/sqli"}, CWE: "CWE-89", Detectable: true},
			{ID: "vuln-2", Name: "XSS", Severity: "high", Endpoints: []string{"/vuln/xss"}, CWE: "CWE-79", Detectable: true},
			{ID: "vuln-3", Name: "SSRF", Severity: "high", Endpoints: []string{"/vuln/ssrf"}, CWE: "CWE-918", Detectable: true},
			{ID: "vuln-4", Name: "Open Redirect", Severity: "medium", Endpoints: []string{"/vuln/redirect"}, CWE: "CWE-601", Detectable: true},
			{ID: "vuln-5", Name: "Missing HSTS", Severity: "low", Endpoints: []string{"/"}, CWE: "CWE-319", Detectable: true},
		},
		TotalVulns: 5,
		BySeverity: map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 1},
	}
}

func buildReportForVulns(scannerName string, profile *ExpectedProfile, foundIDs []string) *ComparisonReport {
	foundSet := make(map[string]bool)
	for _, id := range foundIDs {
		foundSet[id] = true
	}

	result := &ScanResult{Scanner: scannerName}
	for _, v := range profile.Vulnerabilities {
		if v.Detectable && foundSet[v.ID] {
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

	return CompareResults(profile, result)
}

// ---------------------------------------------------------------------------
// TestCompareMultiple_TwoScanners
// ---------------------------------------------------------------------------

func TestCompareMultiple_TwoScanners(t *testing.T) {
	profile := buildTestProfile()

	nucleiReport := buildReportForVulns("nuclei", profile, []string{"vuln-1", "vuln-2", "vuln-3"})
	ffufReport := buildReportForVulns("ffuf", profile, []string{"vuln-1", "vuln-4", "vuln-5"})

	reports := map[string]*ComparisonReport{
		"nuclei": nucleiReport,
		"ffuf":   ffufReport,
	}

	mc := CompareMultiple(reports, profile)

	if mc == nil {
		t.Fatal("CompareMultiple returned nil")
	}

	if len(mc.Reports) != 2 {
		t.Errorf("Reports count = %d, want 2", len(mc.Reports))
	}

	// vuln-1 found by both
	if len(mc.ConsensusVulns) != 1 || mc.ConsensusVulns[0] != "vuln-1" {
		t.Errorf("ConsensusVulns = %v, want [vuln-1]", mc.ConsensusVulns)
	}

	// vuln-2 and vuln-3 only by nuclei; vuln-4 and vuln-5 only by ffuf
	nucleiUnique := mc.UniqueFinds["nuclei"]
	ffufUnique := mc.UniqueFinds["ffuf"]
	if len(nucleiUnique) != 2 {
		t.Errorf("nuclei unique finds = %d, want 2", len(nucleiUnique))
	}
	if len(ffufUnique) != 2 {
		t.Errorf("ffuf unique finds = %d, want 2", len(ffufUnique))
	}

	// Best detection should be nuclei (3/5 = 0.6) vs ffuf (3/5 = 0.6) — same
	if mc.BestDetection != mc.WorstDetection {
		// Both found 3 of 5 so they should be equal
		t.Errorf("BestDetection (%f) != WorstDetection (%f), expected equal", mc.BestDetection, mc.WorstDetection)
	}

	if mc.Recommendation == "" {
		t.Error("Recommendation should not be empty")
	}
}

// ---------------------------------------------------------------------------
// TestCompareMultiple_AllConsensus
// ---------------------------------------------------------------------------

func TestCompareMultiple_AllConsensus(t *testing.T) {
	profile := buildTestProfile()
	allVulns := []string{"vuln-1", "vuln-2", "vuln-3", "vuln-4", "vuln-5"}

	reports := map[string]*ComparisonReport{
		"nuclei": buildReportForVulns("nuclei", profile, allVulns),
		"nikto":  buildReportForVulns("nikto", profile, allVulns),
		"ffuf":   buildReportForVulns("ffuf", profile, allVulns),
	}

	mc := CompareMultiple(reports, profile)

	if len(mc.ConsensusVulns) != 5 {
		t.Errorf("ConsensusVulns = %d, want 5 (all vulns found by all scanners)", len(mc.ConsensusVulns))
	}

	// No unique finds since all scanners found everything
	totalUnique := 0
	for _, vulns := range mc.UniqueFinds {
		totalUnique += len(vulns)
	}
	if totalUnique != 0 {
		t.Errorf("total unique finds = %d, want 0 when all scanners find same vulns", totalUnique)
	}

	if mc.BestDetection != 1.0 {
		t.Errorf("BestDetection = %f, want 1.0", mc.BestDetection)
	}
	if mc.WorstDetection != 1.0 {
		t.Errorf("WorstDetection = %f, want 1.0", mc.WorstDetection)
	}
	if mc.AvgDetection != 1.0 {
		t.Errorf("AvgDetection = %f, want 1.0", mc.AvgDetection)
	}
}

// ---------------------------------------------------------------------------
// TestCompareMultiple_UniqueFinds
// ---------------------------------------------------------------------------

func TestCompareMultiple_UniqueFinds(t *testing.T) {
	profile := buildTestProfile()

	reports := map[string]*ComparisonReport{
		"scanner-a": buildReportForVulns("scanner-a", profile, []string{"vuln-1"}),
		"scanner-b": buildReportForVulns("scanner-b", profile, []string{"vuln-2"}),
		"scanner-c": buildReportForVulns("scanner-c", profile, []string{"vuln-3"}),
	}

	mc := CompareMultiple(reports, profile)

	// No consensus since no vuln is found by all three
	if len(mc.ConsensusVulns) != 0 {
		t.Errorf("ConsensusVulns = %d, want 0 when each scanner finds different vulns", len(mc.ConsensusVulns))
	}

	// Each scanner has exactly 1 unique find
	for name, vulns := range mc.UniqueFinds {
		if len(vulns) != 1 {
			t.Errorf("%s unique finds = %d, want 1", name, len(vulns))
		}
	}

	if len(mc.UniqueFinds) != 3 {
		t.Errorf("UniqueFinds scanner count = %d, want 3", len(mc.UniqueFinds))
	}
}

// ---------------------------------------------------------------------------
// TestCompareMultiple_EmptyResults
// ---------------------------------------------------------------------------

func TestCompareMultiple_EmptyResults(t *testing.T) {
	profile := buildTestProfile()

	// Completely empty reports map
	mc := CompareMultiple(map[string]*ComparisonReport{}, profile)
	if mc == nil {
		t.Fatal("CompareMultiple returned nil for empty reports")
	}
	if len(mc.ConsensusVulns) != 0 {
		t.Errorf("ConsensusVulns = %d, want 0 for empty reports", len(mc.ConsensusVulns))
	}
	if mc.BestDetection != 0 {
		t.Errorf("BestDetection = %f, want 0 for empty reports", mc.BestDetection)
	}
	if mc.Recommendation == "" {
		t.Error("Recommendation should not be empty even for empty reports")
	}

	// Reports map with a nil entry
	mc2 := CompareMultiple(map[string]*ComparisonReport{"nuclei": nil}, profile)
	if mc2 == nil {
		t.Fatal("CompareMultiple returned nil for nil report entry")
	}

	// Reports with an empty scanner result (no findings)
	emptyReport := buildReportForVulns("empty", profile, []string{})
	mc3 := CompareMultiple(map[string]*ComparisonReport{"empty": emptyReport}, profile)
	if mc3 == nil {
		t.Fatal("CompareMultiple returned nil for empty scan result")
	}
	if len(mc3.CoverageMatrix) != 0 {
		t.Errorf("CoverageMatrix should be empty for scanner with no findings, got %d entries", len(mc3.CoverageMatrix))
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_AddAndGet
// ---------------------------------------------------------------------------

func TestComparisonHistory_AddAndGet(t *testing.T) {
	h := NewComparisonHistory(100)

	report := &ComparisonReport{
		Scanner:       "nuclei",
		Timestamp:     time.Now(),
		Grade:         "B",
		DetectionRate: 0.65,
		FalsePositiveRate: 0.10,
		ExpectedVulns: 10,
		TruePositives: []MatchedVuln{
			{Expected: VulnCategory{ID: "v1"}, Found: Finding{ID: "f1"}},
			{Expected: VulnCategory{ID: "v2"}, Found: Finding{ID: "f2"}},
		},
	}

	h.Add(report)
	entries := h.GetAll()

	if len(entries) != 1 {
		t.Fatalf("GetAll returned %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.Scanner != "nuclei" {
		t.Errorf("Scanner = %q, want nuclei", e.Scanner)
	}
	if e.Grade != "B" {
		t.Errorf("Grade = %q, want B", e.Grade)
	}
	if e.Detection != 0.65 {
		t.Errorf("Detection = %f, want 0.65", e.Detection)
	}
	if e.FPRate != 0.10 {
		t.Errorf("FPRate = %f, want 0.10", e.FPRate)
	}
	if e.VulnsFound != 2 {
		t.Errorf("VulnsFound = %d, want 2", e.VulnsFound)
	}
	if e.VulnsTotal != 10 {
		t.Errorf("VulnsTotal = %d, want 10", e.VulnsTotal)
	}
	if e.ID == "" {
		t.Error("ID should not be empty")
	}
	if e.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_MaxSize
// ---------------------------------------------------------------------------

func TestComparisonHistory_MaxSize(t *testing.T) {
	maxSize := 5
	h := NewComparisonHistory(maxSize)

	for i := 0; i < 20; i++ {
		report := &ComparisonReport{
			Scanner:       "nuclei",
			Timestamp:     time.Now(),
			Grade:         "C",
			DetectionRate: float64(i) / 20.0,
			ExpectedVulns: 10,
		}
		h.Add(report)
	}

	entries := h.GetAll()
	if len(entries) != maxSize {
		t.Errorf("GetAll returned %d entries, want max %d", len(entries), maxSize)
	}

	// The entries should be the last 5 added (oldest evicted)
	// Entry 15..19 should remain, with detection rates 0.75..0.95
	if entries[0].Detection < 0.7 {
		t.Errorf("oldest remaining entry detection = %f, expected >= 0.7 (entries 15-19 should remain)", entries[0].Detection)
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_GetByScanner
// ---------------------------------------------------------------------------

func TestComparisonHistory_GetByScanner(t *testing.T) {
	h := NewComparisonHistory(100)

	scanners := []string{"nuclei", "nikto", "nuclei", "ffuf", "nuclei"}
	for _, s := range scanners {
		h.Add(&ComparisonReport{
			Scanner:       s,
			Timestamp:     time.Now(),
			Grade:         "C",
			DetectionRate: 0.5,
			ExpectedVulns: 10,
		})
	}

	nucleiEntries := h.GetByScanner("nuclei")
	if len(nucleiEntries) != 3 {
		t.Errorf("nuclei entries = %d, want 3", len(nucleiEntries))
	}

	niktoEntries := h.GetByScanner("nikto")
	if len(niktoEntries) != 1 {
		t.Errorf("nikto entries = %d, want 1", len(niktoEntries))
	}

	ffufEntries := h.GetByScanner("ffuf")
	if len(ffufEntries) != 1 {
		t.Errorf("ffuf entries = %d, want 1", len(ffufEntries))
	}

	// Non-existent scanner returns empty
	noneEntries := h.GetByScanner("nonexistent")
	if len(noneEntries) != 0 {
		t.Errorf("nonexistent entries = %d, want 0", len(noneEntries))
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_Baseline
// ---------------------------------------------------------------------------

func TestComparisonHistory_Baseline(t *testing.T) {
	h := NewComparisonHistory(100)

	// Add several nuclei results with varying detection rates
	rates := []float64{0.3, 0.7, 0.5, 0.9, 0.6}
	for _, rate := range rates {
		h.Add(&ComparisonReport{
			Scanner:       "nuclei",
			Timestamp:     time.Now(),
			Grade:         computeGrade(rate),
			DetectionRate: rate,
			ExpectedVulns: 10,
		})
	}

	baseline := h.GetBaseline("nuclei")
	if baseline == nil {
		t.Fatal("GetBaseline returned nil")
	}
	if baseline.Detection != 0.9 {
		t.Errorf("baseline detection = %f, want 0.9 (best)", baseline.Detection)
	}
	if baseline.Grade != "A" {
		t.Errorf("baseline grade = %s, want A", baseline.Grade)
	}

	// Non-existent scanner baseline returns nil
	noBaseline := h.GetBaseline("nonexistent")
	if noBaseline != nil {
		t.Error("GetBaseline should return nil for scanner with no history")
	}
}

// ---------------------------------------------------------------------------
// TestCompareToBaseline_Improvement
// ---------------------------------------------------------------------------

func TestCompareToBaseline_Improvement(t *testing.T) {
	h := NewComparisonHistory(100)

	// Add a baseline with 50% detection
	h.Add(&ComparisonReport{
		Scanner:       "nuclei",
		Timestamp:     time.Now(),
		Grade:         "C",
		DetectionRate: 0.50,
		ExpectedVulns: 10,
		TruePositives: make([]MatchedVuln, 5),
	})

	// New report with 80% detection (improvement)
	current := &ComparisonReport{
		Scanner:       "nuclei",
		Timestamp:     time.Now(),
		Grade:         "B",
		DetectionRate: 0.80,
		ExpectedVulns: 10,
		TruePositives: make([]MatchedVuln, 8),
	}

	bc := h.CompareToBaseline(current)
	if bc == nil {
		t.Fatal("CompareToBaseline returned nil")
	}

	if !bc.Improved {
		t.Error("Improved should be true when detection rate increased")
	}

	if bc.DetectionDelta <= 0 {
		t.Errorf("DetectionDelta = %f, want > 0 for improvement", bc.DetectionDelta)
	}

	expectedDelta := 0.80 - 0.50
	if bc.DetectionDelta < expectedDelta-0.001 || bc.DetectionDelta > expectedDelta+0.001 {
		t.Errorf("DetectionDelta = %f, want ~%f", bc.DetectionDelta, expectedDelta)
	}

	if bc.CurrentGrade != "B" {
		t.Errorf("CurrentGrade = %s, want B", bc.CurrentGrade)
	}
	if bc.BaselineGrade != "C" {
		t.Errorf("BaselineGrade = %s, want C", bc.BaselineGrade)
	}
}

// ---------------------------------------------------------------------------
// TestCompareToBaseline_Regression
// ---------------------------------------------------------------------------

func TestCompareToBaseline_Regression(t *testing.T) {
	h := NewComparisonHistory(100)

	// Add a baseline with 90% detection
	h.Add(&ComparisonReport{
		Scanner:       "nikto",
		Timestamp:     time.Now(),
		Grade:         "A",
		DetectionRate: 0.90,
		ExpectedVulns: 10,
		TruePositives: make([]MatchedVuln, 9),
	})

	// New report with 40% detection (regression)
	current := &ComparisonReport{
		Scanner:       "nikto",
		Timestamp:     time.Now(),
		Grade:         "D",
		DetectionRate: 0.40,
		ExpectedVulns: 10,
		TruePositives: make([]MatchedVuln, 4),
	}

	bc := h.CompareToBaseline(current)
	if bc == nil {
		t.Fatal("CompareToBaseline returned nil")
	}

	if bc.Improved {
		t.Error("Improved should be false when detection rate decreased")
	}

	if bc.DetectionDelta >= 0 {
		t.Errorf("DetectionDelta = %f, want < 0 for regression", bc.DetectionDelta)
	}

	expectedDelta := 0.40 - 0.90
	if bc.DetectionDelta < expectedDelta-0.001 || bc.DetectionDelta > expectedDelta+0.001 {
		t.Errorf("DetectionDelta = %f, want ~%f", bc.DetectionDelta, expectedDelta)
	}

	if bc.CurrentGrade != "D" {
		t.Errorf("CurrentGrade = %s, want D", bc.CurrentGrade)
	}
	if bc.BaselineGrade != "A" {
		t.Errorf("BaselineGrade = %s, want A", bc.BaselineGrade)
	}
}

// ---------------------------------------------------------------------------
// TestCompareToBaseline_NoBaseline
// ---------------------------------------------------------------------------

func TestCompareToBaseline_NoBaseline(t *testing.T) {
	h := NewComparisonHistory(100)

	// No entries at all
	current := &ComparisonReport{
		Scanner:       "nuclei",
		Timestamp:     time.Now(),
		Grade:         "B",
		DetectionRate: 0.70,
	}

	bc := h.CompareToBaseline(current)
	if bc != nil {
		t.Error("CompareToBaseline should return nil when no baseline exists")
	}

	// Add entries for a different scanner
	h.Add(&ComparisonReport{
		Scanner:       "nikto",
		Timestamp:     time.Now(),
		Grade:         "A",
		DetectionRate: 0.95,
	})

	bc2 := h.CompareToBaseline(current)
	if bc2 != nil {
		t.Error("CompareToBaseline should return nil when baseline only exists for a different scanner")
	}

	// Nil report
	bc3 := h.CompareToBaseline(nil)
	if bc3 != nil {
		t.Error("CompareToBaseline should return nil for nil report")
	}
}

// ---------------------------------------------------------------------------
// TestCoverageMatrix
// ---------------------------------------------------------------------------

func TestCoverageMatrix(t *testing.T) {
	profile := buildTestProfile()

	// nuclei finds vuln-1, vuln-2, vuln-3
	// nikto finds vuln-1, vuln-3, vuln-4
	// ffuf finds vuln-1, vuln-5
	reports := map[string]*ComparisonReport{
		"nuclei": buildReportForVulns("nuclei", profile, []string{"vuln-1", "vuln-2", "vuln-3"}),
		"nikto":  buildReportForVulns("nikto", profile, []string{"vuln-1", "vuln-3", "vuln-4"}),
		"ffuf":   buildReportForVulns("ffuf", profile, []string{"vuln-1", "vuln-5"}),
	}

	mc := CompareMultiple(reports, profile)

	// vuln-1 should be found by all three
	v1 := mc.CoverageMatrix["vuln-1"]
	if v1 == nil {
		t.Fatal("CoverageMatrix missing vuln-1")
	}
	if !v1["nuclei"] || !v1["nikto"] || !v1["ffuf"] {
		t.Errorf("vuln-1 coverage: nuclei=%v nikto=%v ffuf=%v, want all true",
			v1["nuclei"], v1["nikto"], v1["ffuf"])
	}

	// vuln-2 should be found only by nuclei
	v2 := mc.CoverageMatrix["vuln-2"]
	if v2 == nil {
		t.Fatal("CoverageMatrix missing vuln-2")
	}
	if !v2["nuclei"] {
		t.Error("vuln-2 should be found by nuclei")
	}
	if v2["nikto"] || v2["ffuf"] {
		t.Error("vuln-2 should NOT be found by nikto or ffuf")
	}

	// vuln-3 should be found by nuclei and nikto
	v3 := mc.CoverageMatrix["vuln-3"]
	if v3 == nil {
		t.Fatal("CoverageMatrix missing vuln-3")
	}
	if !v3["nuclei"] || !v3["nikto"] {
		t.Error("vuln-3 should be found by nuclei and nikto")
	}
	if v3["ffuf"] {
		t.Error("vuln-3 should NOT be found by ffuf")
	}

	// vuln-4 should be found only by nikto
	v4 := mc.CoverageMatrix["vuln-4"]
	if v4 == nil {
		t.Fatal("CoverageMatrix missing vuln-4")
	}
	if !v4["nikto"] {
		t.Error("vuln-4 should be found by nikto")
	}
	if v4["nuclei"] || v4["ffuf"] {
		t.Error("vuln-4 should NOT be found by nuclei or ffuf")
	}

	// vuln-5 should be found only by ffuf
	v5 := mc.CoverageMatrix["vuln-5"]
	if v5 == nil {
		t.Fatal("CoverageMatrix missing vuln-5")
	}
	if !v5["ffuf"] {
		t.Error("vuln-5 should be found by ffuf")
	}
	if v5["nuclei"] || v5["nikto"] {
		t.Error("vuln-5 should NOT be found by nuclei or nikto")
	}

	// Total matrix entries should be 5 (one per vuln found by at least one scanner)
	if len(mc.CoverageMatrix) != 5 {
		t.Errorf("CoverageMatrix has %d entries, want 5", len(mc.CoverageMatrix))
	}

	// Consensus: only vuln-1 found by all three
	if len(mc.ConsensusVulns) != 1 || mc.ConsensusVulns[0] != "vuln-1" {
		t.Errorf("ConsensusVulns = %v, want [vuln-1]", mc.ConsensusVulns)
	}

	// Unique finds: vuln-2 by nuclei, vuln-4 by nikto, vuln-5 by ffuf
	if len(mc.UniqueFinds["nuclei"]) != 1 || mc.UniqueFinds["nuclei"][0] != "vuln-2" {
		t.Errorf("nuclei unique = %v, want [vuln-2]", mc.UniqueFinds["nuclei"])
	}
	if len(mc.UniqueFinds["nikto"]) != 1 || mc.UniqueFinds["nikto"][0] != "vuln-4" {
		t.Errorf("nikto unique = %v, want [vuln-4]", mc.UniqueFinds["nikto"])
	}
	if len(mc.UniqueFinds["ffuf"]) != 1 || mc.UniqueFinds["ffuf"][0] != "vuln-5" {
		t.Errorf("ffuf unique = %v, want [vuln-5]", mc.UniqueFinds["ffuf"])
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_AddNilReport
// ---------------------------------------------------------------------------

func TestComparisonHistory_AddNilReport(t *testing.T) {
	h := NewComparisonHistory(100)
	h.Add(nil)
	entries := h.GetAll()
	if len(entries) != 0 {
		t.Errorf("GetAll returned %d entries after adding nil report, want 0", len(entries))
	}
}

// ---------------------------------------------------------------------------
// TestComparisonHistory_MinMaxSize
// ---------------------------------------------------------------------------

func TestComparisonHistory_MinMaxSize(t *testing.T) {
	// maxSize < 1 should be clamped to 1
	h := NewComparisonHistory(0)
	h.Add(&ComparisonReport{Scanner: "test", Timestamp: time.Now(), Grade: "A", DetectionRate: 0.9})
	h.Add(&ComparisonReport{Scanner: "test", Timestamp: time.Now(), Grade: "B", DetectionRate: 0.7})

	entries := h.GetAll()
	if len(entries) != 1 {
		t.Errorf("expected maxSize clamped to 1, got %d entries", len(entries))
	}
}

// ---------------------------------------------------------------------------
// TestGenerateID
// ---------------------------------------------------------------------------

func TestComparisonHistory_UniqueIDs(t *testing.T) {
	h := NewComparisonHistory(100)
	for i := 0; i < 10; i++ {
		h.Add(&ComparisonReport{
			Scanner:       "nuclei",
			Timestamp:     time.Now(),
			Grade:         "C",
			DetectionRate: 0.5,
		})
	}

	entries := h.GetAll()
	ids := make(map[string]bool)
	for _, e := range entries {
		if ids[e.ID] {
			t.Errorf("duplicate ID found: %s", e.ID)
		}
		ids[e.ID] = true
	}
}
