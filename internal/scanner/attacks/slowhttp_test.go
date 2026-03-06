package attacks

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_GenerateRequests
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_GenerateRequests(t *testing.T) {
	mod := &SlowHTTPModule{}

	if mod.Name() != "slowhttp" {
		t.Errorf("expected name 'slowhttp', got %q", mod.Name())
	}
	if mod.Category() != "denial-of-service" {
		t.Errorf("expected category 'denial-of-service', got %q", mod.Category())
	}

	reqs := mod.GenerateRequests("http://localhost:8765")

	if len(reqs) == 0 {
		t.Fatal("SlowHTTPModule generated zero requests")
	}

	t.Logf("SlowHTTPModule generated %d requests", len(reqs))

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

	// Verify all sub-categories are present.
	subCats := make(map[string]int)
	for _, r := range reqs {
		subCats[r.SubCategory]++
	}

	expectedSubCats := []string{
		"slowloris",
		"slow-post",
		"slow-read",
		"connection-exhaustion",
		"large-headers",
		"chunked-abuse",
		"multipart-bomb",
		"redos",
		"compression-bomb",
	}
	for _, sc := range expectedSubCats {
		if subCats[sc] == 0 {
			t.Errorf("expected sub-category %q, found none", sc)
		}
	}

	// Verify all requests use the "Slow-HTTP" category.
	for i, r := range reqs {
		if r.Category != "Slow-HTTP" {
			t.Errorf("request %d has category %q, expected 'Slow-HTTP'", i, r.Category)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_Slowloris
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_Slowloris(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var slowlorisReqs []int
	for i, r := range reqs {
		if r.SubCategory == "slowloris" {
			slowlorisReqs = append(slowlorisReqs, i)
		}
	}

	if len(slowlorisReqs) == 0 {
		t.Fatal("no slowloris requests generated")
	}

	// Verify slowloris requests have X-Slowloris-N headers and X-Glitch-Slow.
	for _, idx := range slowlorisReqs {
		r := reqs[idx]
		if r.Headers == nil {
			t.Errorf("slowloris request %d has nil headers", idx)
			continue
		}
		if r.Headers["X-Glitch-Slow"] != "true" {
			t.Errorf("slowloris request %d missing X-Glitch-Slow header", idx)
		}

		// At least one X-Slowloris-N header should exist
		hasSlowloris := false
		for k := range r.Headers {
			if strings.HasPrefix(k, "X-Slowloris-") {
				hasSlowloris = true
				break
			}
		}
		if !hasSlowloris {
			t.Errorf("slowloris request %d has no X-Slowloris-N headers", idx)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_SlowPost
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_SlowPost(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var slowPostReqs []int
	for i, r := range reqs {
		if r.SubCategory == "slow-post" {
			slowPostReqs = append(slowPostReqs, i)
		}
	}

	if len(slowPostReqs) == 0 {
		t.Fatal("no slow-post requests generated")
	}

	// All slow-post requests should be POST with a large declared Content-Length.
	for _, idx := range slowPostReqs {
		r := reqs[idx]
		if r.Method != "POST" {
			t.Errorf("slow-post request %d has method %q, expected POST", idx, r.Method)
		}
		if r.Headers == nil {
			t.Errorf("slow-post request %d has nil headers", idx)
			continue
		}
		cl := r.Headers["Content-Length"]
		if cl == "" {
			t.Errorf("slow-post request %d missing Content-Length header", idx)
			continue
		}
		// Body should be much smaller than declared Content-Length
		if len(r.Body) >= 1024 {
			t.Errorf("slow-post request %d body is %d bytes, expected small body", idx, len(r.Body))
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_ConnectionExhaustion
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_ConnectionExhaustion(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var connReqs []int
	for i, r := range reqs {
		if r.SubCategory == "connection-exhaustion" {
			connReqs = append(connReqs, i)
		}
	}

	if len(connReqs) == 0 {
		t.Fatal("no connection-exhaustion requests generated")
	}

	// All should have Connection: keep-alive
	for _, idx := range connReqs {
		r := reqs[idx]
		if r.Headers == nil {
			t.Errorf("connection-exhaustion request %d has nil headers", idx)
			continue
		}
		if r.Headers["Connection"] != "keep-alive" {
			t.Errorf("connection-exhaustion request %d has Connection=%q, expected 'keep-alive'", idx, r.Headers["Connection"])
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_LargeHeaders
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_LargeHeaders(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var largeHeaderReqs []int
	for i, r := range reqs {
		if r.SubCategory == "large-headers" {
			largeHeaderReqs = append(largeHeaderReqs, i)
		}
	}

	if len(largeHeaderReqs) == 0 {
		t.Fatal("no large-headers requests generated")
	}

	// At least one request should have headers totaling 32KB+
	found32k := false
	for _, idx := range largeHeaderReqs {
		r := reqs[idx]
		totalSize := 0
		for k, v := range r.Headers {
			totalSize += len(k) + len(v)
		}
		if totalSize >= 32768 {
			found32k = true
			break
		}
	}
	if !found32k {
		t.Error("expected at least one large-headers request with 32KB+ total header size")
	}

	// At least one request should have headers totaling 64KB+
	found64k := false
	for _, idx := range largeHeaderReqs {
		r := reqs[idx]
		totalSize := 0
		for k, v := range r.Headers {
			totalSize += len(k) + len(v)
		}
		if totalSize >= 65536 {
			found64k = true
			break
		}
	}
	if !found64k {
		t.Error("expected at least one large-headers request with 64KB+ total header size")
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_ChunkedAbuse
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_ChunkedAbuse(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var chunkedReqs []int
	for i, r := range reqs {
		if r.SubCategory == "chunked-abuse" {
			chunkedReqs = append(chunkedReqs, i)
		}
	}

	if len(chunkedReqs) == 0 {
		t.Fatal("no chunked-abuse requests generated")
	}

	// All chunked-abuse requests should have Transfer-Encoding: chunked
	for _, idx := range chunkedReqs {
		r := reqs[idx]
		if r.Headers == nil {
			t.Errorf("chunked-abuse request %d has nil headers", idx)
			continue
		}
		if r.Headers["Transfer-Encoding"] != "chunked" {
			t.Errorf("chunked-abuse request %d has Transfer-Encoding=%q, expected 'chunked'", idx, r.Headers["Transfer-Encoding"])
		}
		if r.Method != "POST" {
			t.Errorf("chunked-abuse request %d has method %q, expected POST", idx, r.Method)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_MultipartBomb
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_MultipartBomb(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var mpReqs []int
	for i, r := range reqs {
		if r.SubCategory == "multipart-bomb" {
			mpReqs = append(mpReqs, i)
		}
	}

	if len(mpReqs) == 0 {
		t.Fatal("no multipart-bomb requests generated")
	}

	// All should be POST with multipart/form-data content type
	for _, idx := range mpReqs {
		r := reqs[idx]
		if r.Method != "POST" {
			t.Errorf("multipart-bomb request %d has method %q, expected POST", idx, r.Method)
		}
		if !strings.HasPrefix(r.BodyType, "multipart/form-data") {
			t.Errorf("multipart-bomb request %d has BodyType %q, expected multipart/form-data prefix", idx, r.BodyType)
		}
		if r.Body == "" {
			t.Errorf("multipart-bomb request %d has empty body", idx)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_ReDoS
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_ReDoS(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var redosReqs []int
	for i, r := range reqs {
		if r.SubCategory == "redos" {
			redosReqs = append(redosReqs, i)
		}
	}

	if len(redosReqs) == 0 {
		t.Fatal("no redos requests generated")
	}

	// Verify both GET and POST methods are present.
	methods := make(map[string]bool)
	for _, idx := range redosReqs {
		methods[reqs[idx].Method] = true
	}
	if !methods["GET"] {
		t.Error("expected GET requests in ReDoS payloads")
	}
	if !methods["POST"] {
		t.Error("expected POST requests in ReDoS payloads")
	}

	// Verify header-based ReDoS exists (User-Agent with payload)
	foundHeaderReDoS := false
	for _, idx := range redosReqs {
		r := reqs[idx]
		if r.Headers != nil && r.Headers["User-Agent"] != "" && strings.Contains(r.Headers["User-Agent"], "aaa") {
			foundHeaderReDoS = true
			break
		}
	}
	if !foundHeaderReDoS {
		t.Error("expected at least one ReDoS payload in User-Agent header")
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_CompressionBomb
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_CompressionBomb(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var bombReqs []int
	for i, r := range reqs {
		if r.SubCategory == "compression-bomb" {
			bombReqs = append(bombReqs, i)
		}
	}

	if len(bombReqs) == 0 {
		t.Fatal("no compression-bomb requests generated")
	}

	// All should be POST with Content-Encoding: gzip (possibly "gzip, gzip")
	for _, idx := range bombReqs {
		r := reqs[idx]
		if r.Method != "POST" {
			t.Errorf("compression-bomb request %d has method %q, expected POST", idx, r.Method)
		}
		if r.Headers == nil {
			t.Errorf("compression-bomb request %d has nil headers", idx)
			continue
		}
		ce := r.Headers["Content-Encoding"]
		if !strings.Contains(ce, "gzip") {
			t.Errorf("compression-bomb request %d has Content-Encoding=%q, expected gzip", idx, ce)
		}
		// Body should be non-empty (compressed data)
		if r.Body == "" {
			t.Errorf("compression-bomb request %d has empty body", idx)
		}
		// Compressed body should be much smaller than 10MB
		if len(r.Body) >= 1048576 {
			t.Errorf("compression-bomb request %d body is %d bytes, expected effective compression", idx, len(r.Body))
		}
	}
}

// ---------------------------------------------------------------------------
// TestSlowHTTPModule_SlowRead
// ---------------------------------------------------------------------------

func TestSlowHTTPModule_SlowRead(t *testing.T) {
	mod := &SlowHTTPModule{}
	reqs := mod.GenerateRequests("http://localhost:8765")

	var slowReadReqs []int
	for i, r := range reqs {
		if r.SubCategory == "slow-read" {
			slowReadReqs = append(slowReadReqs, i)
		}
	}

	if len(slowReadReqs) == 0 {
		t.Fatal("no slow-read requests generated")
	}

	// All slow-read requests should use identity encoding
	for _, idx := range slowReadReqs {
		r := reqs[idx]
		if r.Headers == nil {
			t.Errorf("slow-read request %d has nil headers", idx)
			continue
		}
		if r.Headers["Accept-Encoding"] != "identity" {
			t.Errorf("slow-read request %d has Accept-Encoding=%q, expected 'identity'", idx, r.Headers["Accept-Encoding"])
		}
		if r.Headers["X-Glitch-Slow"] != "true" {
			t.Errorf("slow-read request %d missing X-Glitch-Slow header", idx)
		}
	}
}
