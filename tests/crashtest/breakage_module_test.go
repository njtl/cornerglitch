package crashtest

import (
	"context"
	"testing"
	"time"

	"github.com/cornerglitch/internal/scanner/attacks"
)

// TestBreakageModule_AllTargets runs the integrated BreakageModule against
// all Docker targets and reports findings.
func TestBreakageModule_AllTargets(t *testing.T) {
	mod := &attacks.BreakageModule{}
	t.Logf("Module: %s (category: %s)", mod.Name(), mod.Category())

	for name, addr := range targets {
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s (not reachable)", name)
			continue
		}

		t.Run(name, func(t *testing.T) {
			target := "http://" + addr
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			findings := mod.RunRawTCP(ctx, target, 10, 30*time.Second)
			t.Logf("  %d findings", len(findings))

			for _, f := range findings {
				t.Logf("  [%s] %s: %s", f.Severity, f.Category, f.Description)
				if f.Evidence != "" && len(f.Evidence) > 200 {
					t.Logf("    Evidence: %s...", f.Evidence[:200])
				} else if f.Evidence != "" {
					t.Logf("    Evidence: %s", f.Evidence)
				}
			}

			// Count by severity
			sev := map[string]int{}
			for _, f := range findings {
				sev[f.Severity]++
			}
			t.Logf("  Summary: critical=%d high=%d medium=%d low=%d info=%d",
				sev["critical"], sev["high"], sev["medium"], sev["low"], sev["info"])
		})
	}
}
