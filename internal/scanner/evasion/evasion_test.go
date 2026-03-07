package evasion

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TestEncoder_URLEncode
// ---------------------------------------------------------------------------

func TestEncoder_URLEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"<script>", "%3Cscript%3E"},
		{"a b", "a%20b"},
		{"test@123", "test%40123"},
		{"foo/bar", "foo%2Fbar"},
		{"", ""},
		{"abc", "abc"}, // pure alphanumeric stays the same
		{"a=b&c=d", "a%3Db%26c%3Dd"},
	}

	for _, tt := range tests {
		result := URLEncode(tt.input)
		if result != tt.expected {
			t.Errorf("URLEncode(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// TestEncoder_DoubleURLEncode
// ---------------------------------------------------------------------------

func TestEncoder_DoubleURLEncode(t *testing.T) {
	// Double encoding should encode the percent signs from the first pass.
	input := "<script>"
	single := URLEncode(input)
	double := DoubleURLEncode(input)

	if double == single {
		t.Error("DoubleURLEncode should differ from single URLEncode")
	}

	// The % in %3C should become %253C
	if !strings.Contains(double, "%25") {
		t.Errorf("expected double encoding to contain %%25, got %q", double)
	}

	// Verify consistency: DoubleURLEncode(x) == URLEncode(URLEncode(x))
	if double != URLEncode(single) {
		t.Errorf("DoubleURLEncode != URLEncode(URLEncode): %q vs %q", double, URLEncode(single))
	}
}

// ---------------------------------------------------------------------------
// TestEncoder_Encode
// ---------------------------------------------------------------------------

func TestEncoder_Encode(t *testing.T) {
	payload := "' OR 1=1--"

	t.Run("mode_none", func(t *testing.T) {
		enc := NewEncoder("none")
		variants := enc.Encode(payload)
		if len(variants) != 1 {
			t.Errorf("mode 'none' should return 1 variant, got %d", len(variants))
		}
		if variants[0] != payload {
			t.Errorf("mode 'none' should return original payload, got %q", variants[0])
		}
	})

	t.Run("mode_basic", func(t *testing.T) {
		enc := NewEncoder("basic")
		variants := enc.Encode(payload)
		if len(variants) < 2 {
			t.Errorf("mode 'basic' should return at least 2 variants, got %d", len(variants))
		}
		// First variant should be the original.
		if variants[0] != payload {
			t.Errorf("first variant should be original payload, got %q", variants[0])
		}
		// Should include URL-encoded variant.
		hasURLEncoded := false
		for _, v := range variants {
			if v != payload && strings.Contains(v, "%") {
				hasURLEncoded = true
				break
			}
		}
		if !hasURLEncoded {
			t.Error("mode 'basic' should include URL-encoded variant")
		}
	})

	t.Run("mode_advanced", func(t *testing.T) {
		enc := NewEncoder("advanced")
		variants := enc.Encode(payload)
		if len(variants) < 5 {
			t.Errorf("mode 'advanced' should return at least 5 variants, got %d", len(variants))
		}
		// Check uniqueness.
		seen := make(map[string]bool)
		for _, v := range variants {
			if seen[v] {
				t.Errorf("duplicate variant found: %q", v)
			}
			seen[v] = true
		}
	})

	t.Run("mode_nightmare", func(t *testing.T) {
		enc := NewEncoder("nightmare")
		variants := enc.Encode(payload)
		if len(variants) < 8 {
			t.Errorf("mode 'nightmare' should return at least 8 variants, got %d", len(variants))
		}
		// Check uniqueness.
		seen := make(map[string]bool)
		for _, v := range variants {
			if seen[v] {
				t.Errorf("duplicate variant found: %q", v)
			}
			seen[v] = true
		}
		// First variant should be original.
		if variants[0] != payload {
			t.Errorf("first variant should be original, got %q", variants[0])
		}
	})

	t.Run("invalid_mode_defaults_to_none", func(t *testing.T) {
		enc := NewEncoder("invalid")
		if enc.Mode != "none" {
			t.Errorf("invalid mode should default to 'none', got %q", enc.Mode)
		}
		variants := enc.Encode(payload)
		if len(variants) != 1 {
			t.Errorf("expected 1 variant for defaulted none mode, got %d", len(variants))
		}
	})
}

// ---------------------------------------------------------------------------
// TestEncoder_UnicodeEncode
// ---------------------------------------------------------------------------

func TestEncoder_UnicodeEncode(t *testing.T) {
	result := UnicodeEncode("<script>")
	if !strings.Contains(result, "\\u") {
		t.Errorf("UnicodeEncode should contain \\u sequences, got %q", result)
	}
	// Alphanumeric chars should remain unchanged.
	if !strings.Contains(result, "script") {
		t.Errorf("UnicodeEncode should preserve alphanumeric, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestEncoder_HTMLEntityEncode
// ---------------------------------------------------------------------------

func TestEncoder_HTMLEntityEncode(t *testing.T) {
	result := HTMLEntityEncode("<script>")
	if !strings.Contains(result, "&#x") {
		t.Errorf("HTMLEntityEncode should contain &#x sequences, got %q", result)
	}
	if !strings.Contains(result, "script") {
		t.Errorf("HTMLEntityEncode should preserve alphanumeric, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestEncoder_Base64Encode
// ---------------------------------------------------------------------------

func TestEncoder_Base64Encode(t *testing.T) {
	result := Base64Encode("hello")
	// "hello" in base64 is "aGVsbG8="
	if result != "aGVsbG8=" {
		t.Errorf("Base64Encode('hello') = %q, expected 'aGVsbG8='", result)
	}
}

// ---------------------------------------------------------------------------
// TestEncoder_HexEncode
// ---------------------------------------------------------------------------

func TestEncoder_HexEncode(t *testing.T) {
	result := HexEncode("AB")
	if !strings.Contains(result, "0x") {
		t.Errorf("HexEncode should contain 0x prefix, got %q", result)
	}
	// "A" is 0x41, "B" is 0x42
	if !strings.Contains(result, "41") || !strings.Contains(result, "42") {
		t.Errorf("HexEncode('AB') should contain '41' and '42', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestHeaderManipulator_RotateUserAgent
// ---------------------------------------------------------------------------

func TestHeaderManipulator_RotateUserAgent(t *testing.T) {
	hm := NewHeaderManipulator("basic")

	// Should cycle through UAs.
	first := hm.RotateUserAgent()
	if first == "" {
		t.Error("first UA should not be empty")
	}

	second := hm.RotateUserAgent()
	if second == "" {
		t.Error("second UA should not be empty")
	}

	// Should be different (unless there's only 1 UA).
	if len(hm.UserAgents) > 1 && first == second {
		t.Error("consecutive calls should return different UAs when multiple are available")
	}

	// After cycling through all UAs, should wrap around.
	// Note: The default UA list may contain duplicates (e.g. Brave reports
	// the same string as Chrome), so count unique entries in the source list
	// to determine the expected number of unique values from rotation.
	allUAs := make(map[string]bool)
	for i := 0; i < len(hm.UserAgents)*2; i++ {
		ua := hm.RotateUserAgent()
		allUAs[ua] = true
	}
	expectedUnique := make(map[string]bool)
	for _, ua := range hm.UserAgents {
		expectedUnique[ua] = true
	}
	if len(allUAs) != len(expectedUnique) {
		t.Errorf("expected %d unique UAs after full rotation, got %d", len(expectedUnique), len(allUAs))
	}
}

func TestHeaderManipulator_RotateUserAgent_EmptyList(t *testing.T) {
	hm := &HeaderManipulator{
		Mode:       "basic",
		UserAgents: nil,
	}
	ua := hm.RotateUserAgent()
	if ua != "Mozilla/5.0" {
		t.Errorf("expected fallback UA 'Mozilla/5.0', got %q", ua)
	}
}

// ---------------------------------------------------------------------------
// TestHeaderManipulator_Apply
// ---------------------------------------------------------------------------

func TestHeaderManipulator_Apply(t *testing.T) {
	t.Run("mode_none", func(t *testing.T) {
		hm := NewHeaderManipulator("none")
		req := httptest.NewRequest("GET", "/test", nil)
		originalUA := req.Header.Get("User-Agent")

		hm.Apply(req)

		// Headers should be unchanged.
		if req.Header.Get("User-Agent") != originalUA {
			t.Error("mode 'none' should not modify headers")
		}
	})

	t.Run("mode_basic", func(t *testing.T) {
		hm := NewHeaderManipulator("basic")
		req := httptest.NewRequest("GET", "/test", nil)

		hm.Apply(req)

		ua := req.Header.Get("User-Agent")
		if ua == "" {
			t.Error("mode 'basic' should set a User-Agent")
		}
		// Should be one of the default UAs.
		found := false
		for _, defaultUA := range hm.UserAgents {
			if ua == defaultUA {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("User-Agent %q is not from the default list", ua)
		}
	})

	t.Run("mode_advanced", func(t *testing.T) {
		hm := NewHeaderManipulator("advanced")
		req := httptest.NewRequest("GET", "/test", nil)

		hm.Apply(req)

		// Should have User-Agent set.
		if req.Header.Get("User-Agent") == "" {
			t.Error("advanced mode should set User-Agent")
		}
		// Should have decoy headers.
		if req.Header.Get("Accept") == "" {
			t.Error("advanced mode should add Accept header")
		}
		if req.Header.Get("Accept-Language") == "" {
			t.Error("advanced mode should add Accept-Language header")
		}
		if req.Header.Get("Accept-Encoding") == "" {
			t.Error("advanced mode should add Accept-Encoding header")
		}
	})

	t.Run("mode_nightmare", func(t *testing.T) {
		hm := NewHeaderManipulator("nightmare")
		req := httptest.NewRequest("GET", "/test", nil)

		hm.Apply(req)

		// Should have User-Agent.
		if req.Header.Get("User-Agent") == "" {
			t.Error("nightmare mode should set User-Agent")
		}
		// Should have decoy headers.
		if req.Header.Get("Accept") == "" {
			t.Error("nightmare mode should add Accept header")
		}
		// Should have forged IP headers.
		forgedHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP"}
		for _, h := range forgedHeaders {
			if req.Header.Get(h) == "" {
				t.Errorf("nightmare mode should set %s header", h)
			}
		}
		// Should have cache busters.
		if req.Header.Get("Cache-Control") == "" {
			t.Error("nightmare mode should add Cache-Control header")
		}
		if req.Header.Get("Pragma") == "" {
			t.Error("nightmare mode should add Pragma header")
		}
	})

	t.Run("doesnt_override_existing_headers", func(t *testing.T) {
		hm := NewHeaderManipulator("advanced")
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Accept", "custom/accept")
		req.Header.Set("Accept-Language", "custom-lang")

		hm.Apply(req)

		if req.Header.Get("Accept") != "custom/accept" {
			t.Error("should not override existing Accept header")
		}
		if req.Header.Get("Accept-Language") != "custom-lang" {
			t.Error("should not override existing Accept-Language header")
		}
	})

	t.Run("invalid_mode_defaults_to_none", func(t *testing.T) {
		hm := NewHeaderManipulator("bad-mode")
		if hm.Mode != "none" {
			t.Errorf("expected mode 'none' for invalid input, got %q", hm.Mode)
		}
	})
}

// ---------------------------------------------------------------------------
// TestAddDecoyHeaders
// ---------------------------------------------------------------------------

func TestAddDecoyHeaders(t *testing.T) {
	hm := NewHeaderManipulator("advanced")
	req := httptest.NewRequest("GET", "/test", nil)

	hm.AddDecoyHeaders(req)

	headers := []string{
		"Accept", "Accept-Language", "Accept-Encoding",
		"Connection", "Upgrade-Insecure-Requests", "DNT",
		"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
	}
	for _, h := range headers {
		if req.Header.Get(h) == "" {
			t.Errorf("AddDecoyHeaders should set %s", h)
		}
	}
}

// ---------------------------------------------------------------------------
// TestRandomizeHeaders
// ---------------------------------------------------------------------------

func TestRandomizeHeaders(t *testing.T) {
	hm := NewHeaderManipulator("advanced")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("User-Agent", "TestBot")

	originalHeaders := make(http.Header)
	for k, v := range req.Header {
		originalHeaders[k] = v
	}

	hm.RandomizeHeaders(req)

	// All original headers should still be present.
	for k, v := range originalHeaders {
		got := req.Header[k]
		if len(got) != len(v) {
			t.Errorf("header %s value count changed after randomize", k)
		}
		for i, val := range v {
			if got[i] != val {
				t.Errorf("header %s value changed after randomize", k)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestUTF7Encode
// ---------------------------------------------------------------------------

func TestUTF7Encode(t *testing.T) {
	result := UTF7Encode("<script>")
	if !strings.Contains(result, "+") {
		t.Errorf("UTF7Encode should contain + sequences, got %q", result)
	}
	// Alphanumeric chars should remain unchanged.
	if !strings.Contains(result, "script") {
		t.Errorf("UTF7Encode should preserve alphanumeric, got %q", result)
	}
	// Space should remain unchanged.
	result2 := UTF7Encode("hello world")
	if !strings.Contains(result2, " ") {
		t.Errorf("UTF7Encode should preserve spaces, got %q", result2)
	}
}

// ---------------------------------------------------------------------------
// TestIBM037Encode
// ---------------------------------------------------------------------------

func TestIBM037Encode(t *testing.T) {
	result := IBM037Encode("AB")
	// A=0xC1, B=0xC2 in EBCDIC
	if result[0] != 0xC1 || result[1] != 0xC2 {
		t.Errorf("IBM037Encode('AB') = %x, expected C1C2", []byte(result))
	}
	// Space should map to 0x40
	spaceResult := IBM037Encode(" ")
	if spaceResult[0] != 0x40 {
		t.Errorf("IBM037Encode(' ') = %x, expected 40", []byte(spaceResult))
	}
}

// ---------------------------------------------------------------------------
// TestHTMLEntityEncodeWithLeadingZeros
// ---------------------------------------------------------------------------

func TestHTMLEntityEncodeWithLeadingZeros(t *testing.T) {
	result := HTMLEntityEncodeWithLeadingZeros("<script>")
	// Should contain leading zeros in entity
	if !strings.Contains(result, "&#00000") {
		t.Errorf("HTMLEntityEncodeWithLeadingZeros should contain &#00000 sequences, got %q", result)
	}
	// Alphanumeric chars should remain unchanged.
	if !strings.Contains(result, "script") {
		t.Errorf("HTMLEntityEncodeWithLeadingZeros should preserve alphanumeric, got %q", result)
	}
	// < is decimal 60, should produce &#0000060;
	if !strings.Contains(result, "&#0000060;") {
		t.Errorf("HTMLEntityEncodeWithLeadingZeros('<') should produce &#0000060;, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestOverlongUTF8Encode
// ---------------------------------------------------------------------------

func TestOverlongUTF8Encode(t *testing.T) {
	result := OverlongUTF8Encode("../etc/passwd")
	if !strings.Contains(result, "%C0%AE") {
		t.Errorf("OverlongUTF8Encode should replace . with %%C0%%AE, got %q", result)
	}
	if !strings.Contains(result, "%C0%AF") {
		t.Errorf("OverlongUTF8Encode should replace / with %%C0%%AF, got %q", result)
	}
	// Letters should remain unchanged.
	if !strings.Contains(result, "etc") {
		t.Errorf("OverlongUTF8Encode should preserve letters, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestIISUnicodeEncode
// ---------------------------------------------------------------------------

func TestIISUnicodeEncode(t *testing.T) {
	result := IISUnicodeEncode("<script>")
	if !strings.Contains(result, "%u") {
		t.Errorf("IISUnicodeEncode should contain %%u sequences, got %q", result)
	}
	// Alphanumeric chars should remain unchanged.
	if !strings.Contains(result, "script") {
		t.Errorf("IISUnicodeEncode should preserve alphanumeric, got %q", result)
	}
	// < is U+003C, should produce %u003C
	if !strings.Contains(result, "%u003C") {
		t.Errorf("IISUnicodeEncode('<') should produce %%u003C, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestNightmareIncludesWAFEncodings
// ---------------------------------------------------------------------------

func TestNightmareIncludesWAFEncodings(t *testing.T) {
	enc := NewEncoder("nightmare")
	variants := enc.Encode("<script>alert(1)</script>")

	// Should have more variants than before (at least 14 unique)
	if len(variants) < 14 {
		t.Errorf("nightmare mode should return at least 14 variants with WAF encodings, got %d", len(variants))
	}

	// Check that some WAF-specific variants are present
	hasUTF7 := false
	hasOverlong := false
	hasIIS := false
	for _, v := range variants {
		if strings.Contains(v, "+") && strings.Contains(v, "-") && v != variants[0] {
			hasUTF7 = true
		}
		if strings.Contains(v, "%C0%") {
			hasOverlong = true
		}
		if strings.Contains(v, "%u") {
			hasIIS = true
		}
	}
	if !hasUTF7 {
		t.Error("nightmare should include UTF-7 encoded variant")
	}
	if !hasOverlong {
		t.Error("nightmare should include overlong UTF-8 encoded variant")
	}
	if !hasIIS {
		t.Error("nightmare should include IIS Unicode encoded variant")
	}
}

// ---------------------------------------------------------------------------
// TestCommentInject
// ---------------------------------------------------------------------------

func TestCommentInject(t *testing.T) {
	result := commentInject("SELECT * FROM users")
	if !strings.Contains(result, "/**/") {
		t.Errorf("commentInject should insert SQL comments, got %q", result)
	}
	if strings.Contains(result, "SELECT") {
		t.Errorf("commentInject should break 'SELECT' keyword, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestNullByteInject
// ---------------------------------------------------------------------------

func TestNullByteInject(t *testing.T) {
	result := nullByteInject("test/path=value")
	if !strings.Contains(result, "%00") {
		t.Errorf("nullByteInject should insert %%00 sequences, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestMixedCaseEncode
// ---------------------------------------------------------------------------

func TestMixedCaseEncode(t *testing.T) {
	result := mixedCaseEncode("select")
	// Should alternate case at even/odd positions.
	if result == "select" {
		t.Errorf("mixedCaseEncode should change case, got %q", result)
	}
	// Should be the same length.
	if len(result) != len("select") {
		t.Errorf("mixedCaseEncode should not change length, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// TestUniqueStrings
// ---------------------------------------------------------------------------

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	result := uniqueStrings(input)

	if len(result) != 4 {
		t.Errorf("expected 4 unique strings, got %d: %v", len(result), result)
	}

	// Verify order is preserved (first occurrence order).
	expected := []string{"a", "b", "c", "d"}
	for i, e := range expected {
		if result[i] != e {
			t.Errorf("expected result[%d]=%q, got %q", i, e, result[i])
		}
	}
}
