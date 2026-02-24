package errors

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPick_ReturnsValidType(t *testing.T) {
	g := NewGenerator()
	profile := DefaultProfile()
	known := profile.Weights
	for i := 0; i < 100; i++ {
		et := g.Pick(profile)
		if _, ok := known[et]; !ok && et != ErrNone {
			t.Fatalf("Pick returned unknown error type: %q", et)
		}
	}
}

func TestPick_WeightDistribution(t *testing.T) {
	g := NewGenerator()
	profile := DefaultProfile()
	counts := make(map[ErrorType]int)
	n := 10000
	for i := 0; i < n; i++ {
		counts[g.Pick(profile)]++
	}
	// ErrNone should appear most often
	for et, c := range counts {
		if et != ErrNone && c > counts[ErrNone] {
			t.Fatalf("expected ErrNone to be most frequent, but %q appeared %d times vs ErrNone %d", et, c, counts[ErrNone])
		}
	}
	if counts[ErrNone] < n/4 {
		t.Fatalf("ErrNone appeared only %d times out of %d, expected at least %d", counts[ErrNone], n, n/4)
	}
}

func TestApply_ErrNone(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, ErrNone)
	if handled {
		t.Fatal("Apply(ErrNone) should return false so caller handles the response")
	}
}

func TestApply_Err500(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, Err500)
	if !handled {
		t.Fatal("Apply(Err500) should return true")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestApply_Err404(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/missing", nil)
	handled := g.Apply(w, r, Err404)
	if !handled {
		t.Fatal("Apply(Err404) should return true")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestApply_EmptyBody(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, ErrEmptyBody)
	if !handled {
		t.Fatal("Apply(ErrEmptyBody) should return true")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %d bytes", w.Body.Len())
	}
}

func TestIsError(t *testing.T) {
	if IsError(ErrNone) {
		t.Fatal("ErrNone should not be an error")
	}
	if !IsError(Err500) {
		t.Fatal("Err500 should be an error")
	}
	if !IsError(Err404) {
		t.Fatal("Err404 should be an error")
	}
	if IsError(ErrDelayed1s) {
		t.Fatal("ErrDelayed1s should not be an error")
	}
}

func TestIsDelay(t *testing.T) {
	if !IsDelay(ErrDelayed1s) {
		t.Fatal("ErrDelayed1s should be a delay")
	}
	if !IsDelay(ErrDelayed3s) {
		t.Fatal("ErrDelayed3s should be a delay")
	}
	if !IsDelay(ErrDelayed10s) {
		t.Fatal("ErrDelayed10s should be a delay")
	}
	if !IsDelay(ErrDelayedRandom) {
		t.Fatal("ErrDelayedRandom should be a delay")
	}
	if IsDelay(ErrNone) {
		t.Fatal("ErrNone should not be a delay")
	}
	if IsDelay(Err500) {
		t.Fatal("Err500 should not be a delay")
	}
}

// ---------------------------------------------------------------------------
// Protocol Glitch Tests
// ---------------------------------------------------------------------------

func TestDefaultProfile_WeightsSumToOne(t *testing.T) {
	profile := DefaultProfile()
	var total float64
	for _, w := range profile.Weights {
		total += w
	}
	if math.Abs(total-1.0) > 0.01 {
		t.Fatalf("DefaultProfile weights sum to %.4f, expected ~1.0", total)
	}
}

func TestAggressiveProfile_WeightsSumToOne(t *testing.T) {
	profile := AggressiveProfile()
	var total float64
	for _, w := range profile.Weights {
		total += w
	}
	if math.Abs(total-1.0) > 0.01 {
		t.Fatalf("AggressiveProfile weights sum to %.4f, expected ~1.0", total)
	}
}

func TestIsProtocolGlitch(t *testing.T) {
	protocolTypes := []ErrorType{
		ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade, ErrMixedVersions, ErrInfoNoFinal,
		ErrH2UpgradeReject, ErrFalseH2Preface, ErrH2BadStreamID, ErrH2PriorityLoop, ErrFalseServerPush,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
		ErrBothCLAndTE, ErrFalseCompression, ErrMultiEncodings,
		ErrKeepAliveUpgrade,
	}
	for _, et := range protocolTypes {
		if !IsProtocolGlitch(et) {
			t.Fatalf("expected %q to be a protocol glitch", et)
		}
	}

	nonProtocol := []ErrorType{ErrNone, Err500, Err404, ErrSlowDrip, ErrConnectionReset, ErrTCPReset}
	for _, et := range nonProtocol {
		if IsProtocolGlitch(et) {
			t.Fatalf("expected %q NOT to be a protocol glitch", et)
		}
	}
}

// TestApply_ProtocolHeaderBased tests header-based protocol glitches that do NOT
// require the http.Hijacker interface — they work with httptest.ResponseRecorder.
func TestApply_ProtocolHeaderBased(t *testing.T) {
	headerBasedTypes := []struct {
		errType       ErrorType
		expectHeaders map[string]string // header key -> expected substring
	}{
		{
			ErrH2UpgradeReject,
			map[string]string{"Upgrade": "h2c", "Connection": "Upgrade"},
		},
		{
			ErrH2BadStreamID,
			map[string]string{"X-H2-Stream-Id": "-1"},
		},
		{
			ErrH2PriorityLoop,
			map[string]string{"X-H2-Priority": "parent=self"},
		},
		{
			ErrFalseServerPush,
			map[string]string{"Link": "preload"},
		},
		{
			ErrBothCLAndTE,
			map[string]string{"Content-Length": "5", "Transfer-Encoding": "chunked"},
		},
		{
			ErrFalseCompression,
			map[string]string{"Content-Encoding": "br"},
		},
		{
			ErrMultiEncodings,
			map[string]string{"Content-Encoding": "gzip"},
		},
		{
			ErrKeepAliveUpgrade,
			map[string]string{"Upgrade": "websocket"},
		},
	}

	g := NewGenerator()
	for _, tc := range headerBasedTypes {
		t.Run(string(tc.errType), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			handled := g.Apply(w, r, tc.errType)
			if !handled {
				t.Fatalf("Apply(%s) should return true", tc.errType)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("Apply(%s): expected status 200, got %d", tc.errType, w.Code)
			}
			for hdr, substr := range tc.expectHeaders {
				got := w.Header().Get(hdr)
				if got == "" {
					// Check all values
					vals := w.Header().Values(hdr)
					found := false
					for _, v := range vals {
						if containsSubstring(v, substr) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("Apply(%s): expected header %q containing %q, got none", tc.errType, hdr, substr)
					}
				} else if !containsSubstring(got, substr) {
					// Check all values for multi-valued headers
					vals := w.Header().Values(hdr)
					found := false
					for _, v := range vals {
						if containsSubstring(v, substr) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("Apply(%s): expected header %q containing %q, got %q", tc.errType, hdr, substr, got)
					}
				}
			}
			if w.Body.Len() == 0 {
				t.Fatalf("Apply(%s): expected non-empty body", tc.errType)
			}
		})
	}
}

// TestApply_ProtocolHijackerBased tests hijacker-based protocol glitches
// with httptest.ResponseRecorder (which does NOT implement http.Hijacker).
// These should fall back to writing a 500 status.
func TestApply_ProtocolHijackerFallback(t *testing.T) {
	hijackerTypes := []ErrorType{
		ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade,
		ErrMixedVersions, ErrInfoNoFinal, ErrFalseH2Preface,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
	}

	g := NewGenerator()
	for _, et := range hijackerTypes {
		t.Run(string(et), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			handled := g.Apply(w, r, et)
			if !handled {
				t.Fatalf("Apply(%s) should return true even on hijacker fallback", et)
			}
			// Hijacker-based errors should fall back to 500 when Hijacker is unavailable
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("Apply(%s): expected fallback status 500, got %d", et, w.Code)
			}
		})
	}
}

// TestApply_AllProtocolGlitchesHandled verifies every protocol glitch
// error type is handled in Apply() and returns true (fully handled).
func TestApply_AllProtocolGlitchesHandled(t *testing.T) {
	allProtocol := []ErrorType{
		ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade, ErrMixedVersions, ErrInfoNoFinal,
		ErrH2UpgradeReject, ErrFalseH2Preface, ErrH2BadStreamID, ErrH2PriorityLoop, ErrFalseServerPush,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
		ErrBothCLAndTE, ErrFalseCompression, ErrMultiEncodings,
		ErrKeepAliveUpgrade,
	}

	g := NewGenerator()
	for _, et := range allProtocol {
		t.Run(string(et), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			handled := g.Apply(w, r, et)
			if !handled {
				t.Fatalf("Apply(%s) should return true (fully handled)", et)
			}
		})
	}
}

// TestDefaultProfile_ContainsAllProtocolGlitches ensures all 18 protocol glitch
// types appear in the DefaultProfile weights.
func TestDefaultProfile_ContainsAllProtocolGlitches(t *testing.T) {
	profile := DefaultProfile()
	allProtocol := []ErrorType{
		ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade, ErrMixedVersions, ErrInfoNoFinal,
		ErrH2UpgradeReject, ErrFalseH2Preface, ErrH2BadStreamID, ErrH2PriorityLoop, ErrFalseServerPush,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
		ErrBothCLAndTE, ErrFalseCompression, ErrMultiEncodings,
		ErrKeepAliveUpgrade,
	}
	for _, et := range allProtocol {
		w, ok := profile.Weights[et]
		if !ok {
			t.Fatalf("DefaultProfile missing protocol glitch type %q", et)
		}
		if w <= 0 {
			t.Fatalf("DefaultProfile weight for %q is %f, expected > 0", et, w)
		}
	}
}

// TestAggressiveProfile_ContainsAllProtocolGlitches ensures all 18 protocol glitch
// types appear in the AggressiveProfile weights.
func TestAggressiveProfile_ContainsAllProtocolGlitches(t *testing.T) {
	profile := AggressiveProfile()
	allProtocol := []ErrorType{
		ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade, ErrMixedVersions, ErrInfoNoFinal,
		ErrH2UpgradeReject, ErrFalseH2Preface, ErrH2BadStreamID, ErrH2PriorityLoop, ErrFalseServerPush,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
		ErrBothCLAndTE, ErrFalseCompression, ErrMultiEncodings,
		ErrKeepAliveUpgrade,
	}
	for _, et := range allProtocol {
		w, ok := profile.Weights[et]
		if !ok {
			t.Fatalf("AggressiveProfile missing protocol glitch type %q", et)
		}
		if w <= 0 {
			t.Fatalf("AggressiveProfile weight for %q is %f, expected > 0", et, w)
		}
	}
}

// TestAggressiveProfile_HigherProtocolWeights verifies aggressive profile has
// higher protocol glitch weights than default.
func TestAggressiveProfile_HigherProtocolWeights(t *testing.T) {
	def := DefaultProfile()
	agg := AggressiveProfile()
	for _, et := range []ErrorType{ErrHTTP10Chunked, ErrFalseH2Preface, ErrDuplicateStatus, ErrBothCLAndTE} {
		if agg.Weights[et] <= def.Weights[et] {
			t.Fatalf("AggressiveProfile weight for %q (%.4f) should be higher than DefaultProfile (%.4f)",
				et, agg.Weights[et], def.Weights[et])
		}
	}
}

// containsSubstring is a simple helper for test assertions.
func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
