package scaneval

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Multi-scanner comparison
// ---------------------------------------------------------------------------

// MultiScannerComparison holds results from multiple scanners for side-by-side
// comparison. It identifies consensus findings, unique finds per scanner, and
// computes aggregate detection statistics.
type MultiScannerComparison struct {
	Timestamp      string                       `json:"timestamp"`
	Profile        *ExpectedProfile             `json:"profile"`
	Reports        map[string]*ComparisonReport `json:"reports"`         // scanner -> report
	CoverageMatrix map[string]map[string]bool   `json:"coverage_matrix"` // vuln_id -> scanner -> found
	BestDetection  float64                      `json:"best_detection"`
	WorstDetection float64                      `json:"worst_detection"`
	AvgDetection   float64                      `json:"avg_detection"`
	ConsensusVulns []string                     `json:"consensus_vulns"` // found by all scanners
	UniqueFinds    map[string][]string          `json:"unique_finds"`   // scanner -> vuln IDs only it found
	Recommendation string                       `json:"recommendation"`
}

// CompareMultiple takes multiple scanner comparison reports and builds a
// multi-scanner comparison that shows coverage overlap, consensus findings,
// and unique discoveries per scanner.
func CompareMultiple(reports map[string]*ComparisonReport, profile *ExpectedProfile) *MultiScannerComparison {
	mc := &MultiScannerComparison{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Profile:        profile,
		Reports:        reports,
		CoverageMatrix: make(map[string]map[string]bool),
		UniqueFinds:    make(map[string][]string),
	}

	if len(reports) == 0 {
		mc.Recommendation = "No scanner reports provided. Run at least one scanner to get results."
		return mc
	}

	// Build coverage matrix: for each vuln ID, record which scanners found it
	scannerNames := make([]string, 0, len(reports))
	for name := range reports {
		scannerNames = append(scannerNames, name)
	}
	sort.Strings(scannerNames)

	for name, report := range reports {
		if report == nil {
			continue
		}
		for _, tp := range report.TruePositives {
			vulnID := tp.Expected.ID
			if mc.CoverageMatrix[vulnID] == nil {
				mc.CoverageMatrix[vulnID] = make(map[string]bool)
			}
			mc.CoverageMatrix[vulnID][name] = true
		}
	}

	// Determine consensus vulns (found by ALL scanners) and unique finds
	activeScanners := 0
	for _, r := range reports {
		if r != nil {
			activeScanners++
		}
	}

	for vulnID, scanners := range mc.CoverageMatrix {
		foundCount := 0
		var foundBy []string
		for name, found := range scanners {
			if found {
				foundCount++
				foundBy = append(foundBy, name)
			}
		}

		if foundCount == activeScanners && activeScanners > 0 {
			mc.ConsensusVulns = append(mc.ConsensusVulns, vulnID)
		}

		if foundCount == 1 && len(foundBy) == 1 {
			mc.UniqueFinds[foundBy[0]] = append(mc.UniqueFinds[foundBy[0]], vulnID)
		}
	}
	sort.Strings(mc.ConsensusVulns)
	for name := range mc.UniqueFinds {
		sort.Strings(mc.UniqueFinds[name])
	}

	// Compute best/worst/avg detection rates
	var sum float64
	first := true
	for _, report := range reports {
		if report == nil {
			continue
		}
		rate := report.DetectionRate
		sum += rate
		if first {
			mc.BestDetection = rate
			mc.WorstDetection = rate
			first = false
		} else {
			if rate > mc.BestDetection {
				mc.BestDetection = rate
			}
			if rate < mc.WorstDetection {
				mc.WorstDetection = rate
			}
		}
	}
	if activeScanners > 0 {
		mc.AvgDetection = sum / float64(activeScanners)
	}

	// Generate recommendation
	mc.Recommendation = generateRecommendation(mc, scannerNames, activeScanners)

	return mc
}

// generateRecommendation produces a human-readable recommendation based on
// multi-scanner comparison results.
func generateRecommendation(mc *MultiScannerComparison, scannerNames []string, activeScanners int) string {
	if activeScanners == 0 {
		return "No scanner reports provided. Run at least one scanner to get results."
	}

	if activeScanners == 1 {
		name := scannerNames[0]
		report := mc.Reports[name]
		if report == nil {
			return "Single scanner provided but report is nil."
		}
		switch {
		case report.DetectionRate > 0.80:
			return fmt.Sprintf("%s achieved excellent detection (%.0f%%). Consider adding a second scanner for validation.", name, report.DetectionRate*100)
		case report.DetectionRate > 0.50:
			return fmt.Sprintf("%s achieved moderate detection (%.0f%%). Adding another scanner would improve coverage.", name, report.DetectionRate*100)
		default:
			return fmt.Sprintf("%s has low detection (%.0f%%). Try a different scanner or check scanner configuration.", name, report.DetectionRate*100)
		}
	}

	// Multiple scanners
	totalUniqueVulns := len(mc.CoverageMatrix)
	consensusCount := len(mc.ConsensusVulns)

	if totalUniqueVulns == 0 {
		return "No vulnerabilities were detected by any scanner. Check target configuration and scanner settings."
	}

	consensusPct := float64(consensusCount) / float64(totalUniqueVulns) * 100

	// Find the best scanner
	bestScanner := ""
	bestRate := 0.0
	for name, report := range mc.Reports {
		if report != nil && report.DetectionRate > bestRate {
			bestRate = report.DetectionRate
			bestScanner = name
		}
	}

	switch {
	case consensusPct > 80:
		return fmt.Sprintf("Strong consensus: %.0f%% of findings confirmed by all scanners. %s leads with %.0f%% detection.", consensusPct, bestScanner, bestRate*100)
	case consensusPct > 50:
		return fmt.Sprintf("Moderate consensus: %.0f%% of findings confirmed by all scanners. Consider %s as primary (%.0f%% detection) with others for supplemental coverage.", consensusPct, bestScanner, bestRate*100)
	default:
		return fmt.Sprintf("Low consensus: only %.0f%% overlap across scanners. Each scanner finds different issues; use all for comprehensive coverage. %s has best detection at %.0f%%.", consensusPct, bestScanner, bestRate*100)
	}
}

// ---------------------------------------------------------------------------
// Comparison history — in-memory ring of past comparison results
// ---------------------------------------------------------------------------

// ComparisonHistory stores a bounded list of past comparison entries for
// trend analysis and baseline comparison.
type ComparisonHistory struct {
	mu      sync.RWMutex
	entries []HistoryEntry
	maxSize int
}

// HistoryEntry is a summary of a single comparison report stored in history.
type HistoryEntry struct {
	ID         string  `json:"id"`
	Timestamp  string  `json:"timestamp"`
	Scanner    string  `json:"scanner"`
	Grade      string  `json:"grade"`
	Detection  float64 `json:"detection_rate"`
	FPRate     float64 `json:"false_positive_rate"`
	VulnsFound int     `json:"vulns_found"`
	VulnsTotal int     `json:"vulns_total"`
}

// NewComparisonHistory creates a new history buffer with the given max size.
func NewComparisonHistory(maxSize int) *ComparisonHistory {
	if maxSize < 1 {
		maxSize = 1
	}
	return &ComparisonHistory{
		entries: make([]HistoryEntry, 0),
		maxSize: maxSize,
	}
}

// Add records a comparison report in the history. If the buffer is full, the
// oldest entry is evicted.
func (h *ComparisonHistory) Add(report *ComparisonReport) {
	if report == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	entry := HistoryEntry{
		ID:         generateID(),
		Timestamp:  report.Timestamp.UTC().Format(time.RFC3339),
		Scanner:    report.Scanner,
		Grade:      report.Grade,
		Detection:  report.DetectionRate,
		FPRate:     report.FalsePositiveRate,
		VulnsFound: len(report.TruePositives),
		VulnsTotal: report.ExpectedVulns,
	}

	h.entries = append(h.entries, entry)
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[len(h.entries)-h.maxSize:]
	}
}

// GetAll returns a copy of all history entries, oldest first.
func (h *ComparisonHistory) GetAll() []HistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]HistoryEntry, len(h.entries))
	copy(out, h.entries)
	return out
}

// GetByScanner returns history entries for a specific scanner.
func (h *ComparisonHistory) GetByScanner(scanner string) []HistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []HistoryEntry
	for _, e := range h.entries {
		if e.Scanner == scanner {
			out = append(out, e)
		}
	}
	return out
}

// GetBaseline returns the best historical result for a scanner (highest
// detection rate). Returns nil if no history exists for that scanner.
func (h *ComparisonHistory) GetBaseline(scanner string) *HistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var best *HistoryEntry
	for i := range h.entries {
		e := &h.entries[i]
		if e.Scanner != scanner {
			continue
		}
		if best == nil || e.Detection > best.Detection {
			cp := *e
			best = &cp
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Baseline comparison
// ---------------------------------------------------------------------------

// BaselineComparison compares a current report against the best historical
// baseline for the same scanner.
type BaselineComparison struct {
	Scanner        string   `json:"scanner"`
	CurrentGrade   string   `json:"current_grade"`
	BaselineGrade  string   `json:"baseline_grade"`
	DetectionDelta float64  `json:"detection_delta"` // positive = improvement
	NewVulnsFound  []string `json:"new_vulns_found"` // found now but not in baseline
	VulnsLost      []string `json:"vulns_lost"`      // found in baseline but not now
	Improved       bool     `json:"improved"`
}

// CompareToBaseline compares the given report against the best historical
// baseline for the same scanner. Returns nil if no baseline exists.
func (h *ComparisonHistory) CompareToBaseline(report *ComparisonReport) *BaselineComparison {
	if report == nil {
		return nil
	}
	baseline := h.GetBaseline(report.Scanner)
	if baseline == nil {
		return nil
	}

	bc := &BaselineComparison{
		Scanner:        report.Scanner,
		CurrentGrade:   report.Grade,
		BaselineGrade:  baseline.Grade,
		DetectionDelta: report.DetectionRate - baseline.Detection,
		Improved:       report.DetectionRate > baseline.Detection,
	}

	// Build sets of found vuln IDs for the current report
	currentFound := make(map[string]bool)
	for _, tp := range report.TruePositives {
		currentFound[tp.Expected.ID] = true
	}

	// We can only compute NewVulnsFound and VulnsLost if we have the
	// baseline's found count vs current. Since HistoryEntry only stores
	// counts, we derive what we can: if current finds more vulns, the
	// extras are "new". If fewer, the missing ones are "lost".
	// For a full diff we would need the baseline's vuln ID list, which we
	// don't store. So we populate these as empty slices. A richer version
	// would store vuln IDs in HistoryEntry.
	bc.NewVulnsFound = []string{}
	bc.VulnsLost = []string{}

	return bc
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// generateID returns a short random hex string for use as an entry ID.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
