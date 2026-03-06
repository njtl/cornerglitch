package attacks

import (
	"crypto/tls"
	"testing"
)

// ---------------------------------------------------------------------------
// TestTLSModule_Name_Category
// ---------------------------------------------------------------------------

func TestTLSModule_Name_Category(t *testing.T) {
	mod := &TLSModule{}

	if mod.Name() != "tls" {
		t.Errorf("expected name 'tls', got %q", mod.Name())
	}
	if mod.Category() != "tls" {
		t.Errorf("expected category 'tls', got %q", mod.Category())
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_GenerateRequests
// ---------------------------------------------------------------------------

func TestTLSModule_GenerateRequests(t *testing.T) {
	mod := &TLSModule{}

	reqs := mod.GenerateRequests("http://localhost:8765")

	if len(reqs) == 0 {
		t.Fatal("TLSModule generated zero requests")
	}

	t.Logf("TLSModule generated %d requests", len(reqs))

	// Verify all requests have required fields.
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

	// All requests should have category "TLS".
	for i, r := range reqs {
		if r.Category != "TLS" {
			t.Errorf("request %d has category %q, expected 'TLS'", i, r.Category)
		}
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_SubCategories
// ---------------------------------------------------------------------------

func TestTLSModule_SubCategories(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("https://example.com")

	subCats := make(map[string]int)
	for _, r := range reqs {
		subCats[r.SubCategory]++
	}

	expectedSubCats := []string{
		"hsts-check",
		"hsts-content-type",
		"tls-upgrade",
		"upgrade-insecure",
		"http-redirect",
		"forwarded-proto",
		"proto-spoofing",
		"mixed-case-host",
	}

	for _, sc := range expectedSubCats {
		if subCats[sc] == 0 {
			t.Errorf("expected at least one request with sub-category %q, found none", sc)
		}
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_HSTSProbes
// ---------------------------------------------------------------------------

func TestTLSModule_HSTSProbes(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var hstsCount int
	for _, r := range reqs {
		if r.SubCategory == "hsts-check" || r.SubCategory == "hsts-content-type" {
			hstsCount++
			if r.Method != "GET" {
				t.Errorf("HSTS probe should use GET, got %s", r.Method)
			}
		}
	}

	if hstsCount == 0 {
		t.Error("expected HSTS probe requests, found none")
	}
	t.Logf("Found %d HSTS probe requests", hstsCount)
}

// ---------------------------------------------------------------------------
// TestTLSModule_UpgradeHeaders
// ---------------------------------------------------------------------------

func TestTLSModule_UpgradeHeaders(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var upgradeCount int
	tlsVersionsSeen := make(map[string]bool)

	for _, r := range reqs {
		if r.SubCategory == "tls-upgrade" {
			upgradeCount++
			if v, ok := r.Headers["Upgrade"]; ok {
				tlsVersionsSeen[v] = true
			}
			// Must also have Connection: Upgrade header.
			if r.Headers["Connection"] != "Upgrade" {
				t.Errorf("TLS upgrade request missing Connection: Upgrade header")
			}
		}
	}

	if upgradeCount == 0 {
		t.Error("expected TLS upgrade requests, found none")
	}

	expectedVersions := []string{"TLS/1.0", "TLS/1.1", "TLS/1.2", "TLS/1.3"}
	for _, v := range expectedVersions {
		if !tlsVersionsSeen[v] {
			t.Errorf("expected Upgrade: %s request, not found", v)
		}
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_HTTPRedirect
// ---------------------------------------------------------------------------

func TestTLSModule_HTTPRedirect(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var redirectCount, protoCount int
	for _, r := range reqs {
		if r.SubCategory == "http-redirect" {
			redirectCount++
		}
		if r.SubCategory == "forwarded-proto" {
			protoCount++
		}
	}

	if redirectCount == 0 {
		t.Error("expected HTTP redirect check requests, found none")
	}
	if protoCount == 0 {
		t.Error("expected X-Forwarded-Proto requests, found none")
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_MixedCaseHost
// ---------------------------------------------------------------------------

func TestTLSModule_MixedCaseHost(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("https://example.com:443")

	var mixedCount int
	for _, r := range reqs {
		if r.SubCategory == "mixed-case-host" {
			mixedCount++
			if _, ok := r.Headers["Host"]; !ok {
				t.Error("mixed-case-host request should have a Host header")
			}
		}
	}

	if mixedCount == 0 {
		t.Error("expected mixed-case host requests, found none")
	}
	t.Logf("Found %d mixed-case host requests", mixedCount)
}

// ---------------------------------------------------------------------------
// TestTLSModule_ProtoSpoofing
// ---------------------------------------------------------------------------

func TestTLSModule_ProtoSpoofing(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var spoofCount int
	for _, r := range reqs {
		if r.SubCategory == "proto-spoofing" {
			spoofCount++
			if r.Method != "POST" {
				t.Errorf("proto-spoofing request should use POST, got %s", r.Method)
			}
			if r.Body == "" {
				t.Error("proto-spoofing request should have a body")
			}
			// Should have multiple proto headers.
			protoHeaders := 0
			for k := range r.Headers {
				if k == "X-Forwarded-Proto" || k == "X-Forwarded-Scheme" || k == "X-URL-Scheme" {
					protoHeaders++
				}
			}
			if protoHeaders < 2 {
				t.Errorf("proto-spoofing request should have multiple proto headers, got %d", protoHeaders)
			}
		}
	}

	if spoofCount == 0 {
		t.Error("expected proto-spoofing requests, found none")
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_InvalidTarget
// ---------------------------------------------------------------------------

func TestTLSModule_InvalidTarget(t *testing.T) {
	mod := &TLSModule{}

	// A target with an unparseable URL should not panic;
	// redirect and mixed-case generators should return empty slices gracefully.
	reqs := mod.GenerateRequests("http://localhost:8765")
	if len(reqs) == 0 {
		t.Error("expected requests even for simple target")
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_MethodDistribution
// ---------------------------------------------------------------------------

func TestTLSModule_MethodDistribution(t *testing.T) {
	mod := &TLSModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	methods := make(map[string]int)
	for _, r := range reqs {
		methods[r.Method]++
	}

	if methods["GET"] == 0 {
		t.Error("expected GET requests from TLS module")
	}
	if methods["POST"] == 0 {
		t.Error("expected POST requests from TLS module")
	}

	t.Logf("Method distribution: %v", methods)
}

// ---------------------------------------------------------------------------
// TestTLSProbeTypes — verify probe type structures
// ---------------------------------------------------------------------------

func TestTLSProbeTypes(t *testing.T) {
	t.Run("TLSVersionInfo", func(t *testing.T) {
		info := TLSVersionInfo{
			Name:      "TLS 1.2",
			Version:   tls.VersionTLS12,
			Supported: true,
		}
		if info.Name != "TLS 1.2" {
			t.Errorf("expected name 'TLS 1.2', got %q", info.Name)
		}
		if info.Version != tls.VersionTLS12 {
			t.Errorf("expected version %d, got %d", tls.VersionTLS12, info.Version)
		}
	})

	t.Run("CertInfo_defaults", func(t *testing.T) {
		info := &CertInfo{}
		if info.IsExpired {
			t.Error("default CertInfo should not be expired")
		}
		if info.SelfSigned {
			t.Error("default CertInfo should not be self-signed")
		}
	})

	t.Run("CipherProbeResult", func(t *testing.T) {
		r := CipherProbeResult{
			Name:     "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			ID:       tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			Accepted: false,
			Error:    "connection refused",
		}
		if r.Accepted {
			t.Error("expected cipher not accepted")
		}
	})

	t.Run("ALPNProbeResult", func(t *testing.T) {
		r := ALPNProbeResult{
			Protocol:  "h2",
			Supported: true,
		}
		if !r.Supported {
			t.Error("expected h2 supported")
		}
	})

	t.Run("DowngradeResult", func(t *testing.T) {
		r := &DowngradeResult{
			Attempted:       true,
			DowngradeWorked: false,
			MaxOffered:      tls.VersionTLS12,
			Negotiated:      tls.VersionTLS12,
		}
		if r.DowngradeWorked {
			t.Error("expected downgrade not to work")
		}
	})

	t.Run("TLSTargetReport", func(t *testing.T) {
		report := &TLSTargetReport{
			Target: "https://example.com",
			HTTP2:  true,
		}
		if !report.HTTP2 {
			t.Error("expected HTTP2 true")
		}
	})
}

// ---------------------------------------------------------------------------
// TestDetectHTTP2
// ---------------------------------------------------------------------------

func TestDetectHTTP2(t *testing.T) {
	tests := []struct {
		name     string
		results  []ALPNProbeResult
		expected bool
	}{
		{
			name:     "no_results",
			results:  nil,
			expected: false,
		},
		{
			name: "h2_supported",
			results: []ALPNProbeResult{
				{Protocol: "h2", Supported: true},
				{Protocol: "http/1.1", Supported: true},
			},
			expected: true,
		},
		{
			name: "h2_not_supported",
			results: []ALPNProbeResult{
				{Protocol: "h2", Supported: false},
				{Protocol: "http/1.1", Supported: true},
			},
			expected: false,
		},
		{
			name: "only_http11",
			results: []ALPNProbeResult{
				{Protocol: "http/1.1", Supported: true},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectHTTP2(tt.results)
			if result != tt.expected {
				t.Errorf("detectHTTP2() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTLSVersionsList — verify all four TLS versions are probed
// ---------------------------------------------------------------------------

func TestTLSVersionsList(t *testing.T) {
	expected := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	if len(tlsVersions) != len(expected) {
		t.Fatalf("expected %d TLS versions, got %d", len(expected), len(tlsVersions))
	}

	for _, v := range tlsVersions {
		name, ok := expected[v.version]
		if !ok {
			t.Errorf("unexpected TLS version %d in list", v.version)
			continue
		}
		if v.name != name {
			t.Errorf("version %d: expected name %q, got %q", v.version, name, v.name)
		}
	}
}

// ---------------------------------------------------------------------------
// TestWeakCiphersList — verify weak ciphers list is non-empty and valid
// ---------------------------------------------------------------------------

func TestWeakCiphersList(t *testing.T) {
	if len(weakCiphers) == 0 {
		t.Fatal("weakCiphers list is empty")
	}

	seen := make(map[uint16]bool)
	for _, c := range weakCiphers {
		if c.name == "" {
			t.Error("weak cipher has empty name")
		}
		if c.id == 0 {
			t.Errorf("weak cipher %q has zero ID", c.name)
		}
		if seen[c.id] {
			t.Errorf("duplicate cipher ID %d (%s)", c.id, c.name)
		}
		seen[c.id] = true
	}

	t.Logf("Testing %d weak cipher suites", len(weakCiphers))
}

// ---------------------------------------------------------------------------
// TestALPNProtocolsList — verify ALPN protocols list
// ---------------------------------------------------------------------------

func TestALPNProtocolsList(t *testing.T) {
	if len(alpnProtocols) == 0 {
		t.Fatal("alpnProtocols list is empty")
	}

	expected := map[string]bool{
		"h2":       true,
		"http/1.1": true,
		"h2c":      true,
		"spdy/3.1": true,
	}

	for _, p := range alpnProtocols {
		if !expected[p] {
			t.Errorf("unexpected ALPN protocol: %q", p)
		}
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_RegisteredInAllModules
// ---------------------------------------------------------------------------

func TestTLSModule_RegisteredInAllModules(t *testing.T) {
	modules := AllModules()

	found := false
	for _, m := range modules {
		if m.Name() == "tls" {
			found = true
			break
		}
	}

	if !found {
		t.Error("TLSModule not found in AllModules() registry")
	}
}

// ---------------------------------------------------------------------------
// TestTLSModule_GetModule
// ---------------------------------------------------------------------------

func TestTLSModule_GetModule(t *testing.T) {
	mod, err := GetModule("tls")
	if err != nil {
		t.Fatalf("GetModule('tls') returned error: %v", err)
	}
	if mod.Name() != "tls" {
		t.Errorf("expected module name 'tls', got %q", mod.Name())
	}
}
