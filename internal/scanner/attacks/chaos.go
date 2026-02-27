// Package attacks provides attack modules for the Glitch Scanner.
// ChaosModule generates malformed and impossible HTTP requests designed to
// stress-test servers and expose edge cases in request parsing.
package attacks

import (
	"fmt"
	"strings"

	"github.com/glitchWebServer/internal/scanner"
)

// ChaosModule generates malformed and impossible HTTP requests designed to
// stress-test servers and expose edge cases in request parsing.
type ChaosModule struct{}

func (m *ChaosModule) Name() string     { return "chaos" }
func (m *ChaosModule) Category() string { return "chaos" }

func (m *ChaosModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.invalidMethods(target)...)
	reqs = append(reqs, m.contradictoryHeaders(target)...)
	reqs = append(reqs, m.oversizedHeaders(target)...)
	reqs = append(reqs, m.malformedURLs(target)...)
	reqs = append(reqs, m.binaryPayloads(target)...)
	reqs = append(reqs, m.duplicateHeaders(target)...)

	return reqs
}

// invalidMethods generates requests with invalid or unusual HTTP methods.
func (m *ChaosModule) invalidMethods(target string) []scanner.AttackRequest {
	longMethod := strings.Repeat("A", 1000)
	methods := []struct {
		method string
		desc   string
	}{
		{"AAAAA", "5-char garbage method"},
		{"!@#$%", "special characters method"},
		{"G\x00ET", "null byte in method"},
		{"PROPFIND", "WebDAV PROPFIND method"},
		{"MKCOL", "WebDAV MKCOL method"},
		{"GET\r\n", "method with CRLF"},
		{longMethod, "1000-char method"},
		{"GET POST", "method with space"},
		{"PURGE", "Varnish PURGE method"},
		{"LOCK", "WebDAV LOCK method"},
		{"UNLOCK", "WebDAV UNLOCK method"},
		{"COPY", "WebDAV COPY method"},
		{"MOVE", "WebDAV MOVE method"},
		{"SEARCH", "WebDAV SEARCH method"},
		{"REPORT", "WebDAV REPORT method"},
		{"PROPPATCH", "WebDAV PROPPATCH method"},
		{"CHECKOUT", "WebDAV CHECKOUT method"},
		{"MERGE", "WebDAV MERGE method"},
		{"NOTIFY", "SIP NOTIFY method"},
		{"SUBSCRIBE", "SIP SUBSCRIBE method"},
	}

	reqs := make([]scanner.AttackRequest, 0, len(methods))
	for _, m := range methods {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      m.method,
			Path:        "/",
			Category:    "chaos",
			SubCategory: "invalid-method",
			Description: fmt.Sprintf("Invalid method: %s", m.desc),
		})
	}
	return reqs
}

// contradictoryHeaders generates requests with conflicting or contradictory headers.
func (m *ChaosModule) contradictoryHeaders(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Content-Length + Transfer-Encoding conflicts
	clTeConflicts := []struct {
		cl   string
		te   string
		desc string
	}{
		{"0", "chunked", "CL=0 with TE chunked"},
		{"100", "chunked", "CL=100 with TE chunked"},
		{"-1", "chunked", "negative CL with TE chunked"},
		{"999999", "chunked", "huge CL with TE chunked"},
		{"abc", "chunked", "non-numeric CL with TE chunked"},
		{"0", "identity", "CL=0 with TE identity"},
		{"10", "gzip, chunked", "CL with TE gzip+chunked"},
		{"5", "chunked, identity", "CL with TE chunked+identity"},
	}
	for _, c := range clTeConflicts {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/",
			Body:        "test",
			BodyType:    "text/plain",
			Category:    "chaos",
			SubCategory: "contradictory-headers",
			Description: fmt.Sprintf("CL/TE conflict: %s", c.desc),
			Headers: map[string]string{
				"Content-Length":    c.cl,
				"Transfer-Encoding": c.te,
			},
		})
	}

	// Accept contradicts Content-Type
	acceptConflicts := []struct {
		accept      string
		contentType string
		desc        string
	}{
		{"application/json", "text/xml", "Accept JSON but send XML"},
		{"text/html", "application/octet-stream", "Accept HTML but send binary"},
		{"image/png", "text/plain", "Accept PNG but send text"},
		{"application/pdf", "application/json", "Accept PDF but send JSON"},
	}
	for _, c := range acceptConflicts {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/",
			Body:        "data",
			BodyType:    c.contentType,
			Category:    "chaos",
			SubCategory: "contradictory-headers",
			Description: fmt.Sprintf("Accept/Content-Type conflict: %s", c.desc),
			Headers: map[string]string{
				"Accept":       c.accept,
				"Content-Type": c.contentType,
			},
		})
	}

	// Multiple Host headers via different header names
	hostConflicts := []struct {
		host       string
		xForwarded string
		desc       string
	}{
		{"evil.com", "localhost", "Host evil.com, X-Forwarded-Host localhost"},
		{"localhost", "evil.com", "Host localhost, X-Forwarded-Host evil.com"},
		{"internal.server", "external.server", "Host internal, X-Forwarded-Host external"},
		{"127.0.0.1", "10.0.0.1", "Host loopback, X-Forwarded-Host private"},
	}
	for _, c := range hostConflicts {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        "/",
			Category:    "chaos",
			SubCategory: "contradictory-headers",
			Description: fmt.Sprintf("Host conflict: %s", c.desc),
			Headers: map[string]string{
				"Host":             c.host,
				"X-Forwarded-Host": c.xForwarded,
			},
		})
	}

	return reqs
}

// oversizedHeaders generates requests with abnormally large headers.
func (m *ChaosModule) oversizedHeaders(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Headers with 8KB+ values
	largeValues := []struct {
		header string
		size   int
		desc   string
	}{
		{"X-Large-Header", 8192, "8KB custom header"},
		{"Cookie", 16384, "16KB cookie header"},
		{"Authorization", 8192, "8KB authorization header"},
		{"Referer", 10000, "10KB referer header"},
		{"User-Agent", 8192, "8KB user agent"},
		{"Accept", 8192, "8KB accept header"},
		{"X-Overflow-1", 32768, "32KB custom header"},
		{"X-Overflow-2", 65536, "64KB custom header"},
	}
	for _, lv := range largeValues {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        "/",
			Category:    "chaos",
			SubCategory: "oversized-headers",
			Description: fmt.Sprintf("Oversized header: %s", lv.desc),
			Headers: map[string]string{
				lv.header: strings.Repeat("X", lv.size),
			},
		})
	}

	// Hundreds of small headers
	manyHeaders := make(map[string]string)
	for i := 0; i < 200; i++ {
		manyHeaders[fmt.Sprintf("X-Flood-%03d", i)] = fmt.Sprintf("value-%d", i)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Category:    "chaos",
		SubCategory: "oversized-headers",
		Description: "200 small custom headers",
		Headers:     manyHeaders,
	})

	// Cookie header with 100+ cookies
	cookies := make([]string, 100)
	for i := 0; i < 100; i++ {
		cookies[i] = fmt.Sprintf("cookie%d=value%d", i, i)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Category:    "chaos",
		SubCategory: "oversized-headers",
		Description: "Cookie header with 100 cookies",
		Headers: map[string]string{
			"Cookie": strings.Join(cookies, "; "),
		},
	})

	return reqs
}

// malformedURLs generates requests with malformed or adversarial URL paths.
func (m *ChaosModule) malformedURLs(target string) []scanner.AttackRequest {
	paths := []struct {
		path string
		desc string
	}{
		{"/path%00with%00nulls", "encoded null bytes in path"},
		{"/%252e%252e/%252e%252e/etc/passwd", "double-encoded path traversal"},
		{"/パス/テスト", "Unicode Japanese in path"},
		{"/Üñíçödé/path", "Unicode Latin in path"},
		{"/path\\with\\backslashes", "backslashes in path"},
		{"/../../../etc/passwd", "relative path traversal"},
		{"/./././././././file", "dot segments in path"},
		{"//double//slashes//path", "double slashes"},
		{"/path?a=1&a=2&a=3&a=4&a=5", "duplicate query parameters"},
		{"/path#fragment#fragment", "multiple fragments"},
		{"/%00", "encoded null path"},
		{"/%0a%0d", "CRLF in path"},
		{"/path;param=value", "semicolon path parameter"},
		{"/path%20with%20spaces", "encoded spaces"},
		{"/AAAA" + strings.Repeat("/AAAA", 200), "extremely deep path nesting"},
		{"/" + strings.Repeat("A", 4096), "4KB path component"},
		{"/path?q=" + strings.Repeat("A", 4096), "4KB query string"},
		{"/path\t\twith\ttabs", "tabs in path"},
		{"/path\nwith\nnewlines", "newlines in path"},
		{"/.git/HEAD", "git metadata path"},
		{"/.env", "dotenv path"},
		{"/wp-admin/", "WordPress admin path"},
		{"/../", "parent directory"},
		{"/path/../../../etc/shadow", "deep traversal to shadow"},
		{"/path%252f..%252f..%252fetc%252fpasswd", "double-encoded slash traversal"},
	}

	reqs := make([]scanner.AttackRequest, 0, len(paths))
	for _, p := range paths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p.path,
			Category:    "chaos",
			SubCategory: "malformed-url",
			Description: fmt.Sprintf("Malformed URL: %s", p.desc),
		})
	}
	return reqs
}

// binaryPayloads generates POST requests with binary or garbage bodies.
func (m *ChaosModule) binaryPayloads(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Random binary-looking bodies
	binaryBodies := []struct {
		body     string
		bodyType string
		desc     string
	}{
		{"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", "application/octet-stream", "16 bytes binary"},
		{strings.Repeat("\xff\xfe\xfd\xfc", 64), "application/octet-stream", "256 bytes high bytes"},
		{"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03GARBAGE", "application/gzip", "fake gzip header with garbage"},
		{"\x1f\x8b" + strings.Repeat("\x00", 100), "application/gzip", "gzip header with null padding"},
		{"\x50\x4b\x03\x04NOTAZIP", "application/zip", "fake zip header"},
		{"%PDF-1.4NOTAPDF", "application/pdf", "fake PDF header"},
		{"\x89PNG\r\n\x1a\nNOTAPNG", "image/png", "fake PNG header"},
		{strings.Repeat("\x00\xff\xfe\x00", 256), "application/octet-stream", "1KB null-ff pattern"},
		{strings.Repeat("\xde\xad\xbe\xef", 256), "application/octet-stream", "1KB deadbeef pattern"},
		{strings.Repeat("\x41", 102400), "text/plain", "100KB of 'A's"},
	}
	for _, b := range binaryBodies {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/",
			Body:        b.body,
			BodyType:    b.bodyType,
			Category:    "chaos",
			SubCategory: "binary-payload",
			Description: fmt.Sprintf("Binary payload: %s", b.desc),
		})
	}

	// Additional paths for binary payloads
	targetPaths := []string{"/api/v1/users", "/upload", "/login", "/search", "/api/graphql"}
	for _, path := range targetPaths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Body:        strings.Repeat("\x00\xff\xfe\x00", 256),
			BodyType:    "application/octet-stream",
			Category:    "chaos",
			SubCategory: "binary-payload",
			Description: fmt.Sprintf("Binary payload to %s", path),
		})
	}

	// POST with wrong Content-Length
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/",
		Body:        "short",
		BodyType:    "text/plain",
		Category:    "chaos",
		SubCategory: "binary-payload",
		Description: "Body shorter than declared Content-Length",
		Headers: map[string]string{
			"Content-Length": "99999",
		},
	})

	return reqs
}

// duplicateHeaders generates requests where the same header appears with
// different values (via header map, only one value per key is possible in Go,
// so we simulate this with closely related header variations).
func (m *ChaosModule) duplicateHeaders(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Simulate duplicate-like headers using case variations and related headers
	headerSets := []struct {
		headers map[string]string
		desc    string
	}{
		{
			map[string]string{
				"Content-Type":   "text/html",
				"content-type":   "application/json",
				"CONTENT-TYPE":   "text/xml",
			},
			"Content-Type case variations",
		},
		{
			map[string]string{
				"Host":             "site-a.com",
				"X-Forwarded-Host": "site-b.com",
				"X-Host":           "site-c.com",
			},
			"multiple host-like headers",
		},
		{
			map[string]string{
				"Authorization":       "Bearer token1",
				"X-Authorization":     "Bearer token2",
				"Proxy-Authorization": "Bearer token3",
			},
			"multiple auth headers",
		},
		{
			map[string]string{
				"X-Forwarded-For":  "1.1.1.1",
				"X-Real-IP":       "2.2.2.2",
				"X-Client-IP":     "3.3.3.3",
				"Forwarded":       "for=4.4.4.4",
				"True-Client-IP":  "5.5.5.5",
			},
			"multiple IP forwarding headers",
		},
		{
			map[string]string{
				"Accept":          "*/*",
				"Accept-Charset":  "utf-8, iso-8859-1;q=0.5",
				"Accept-Encoding": "gzip, deflate, br, zstd",
				"Accept-Language": "en, fr, de, ja, zh",
			},
			"all Accept variants populated",
		},
		{
			map[string]string{
				"Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
				"Pragma":        "no-cache",
				"Expires":       "0",
				"If-None-Match": "W/\"fake-etag\"",
				"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT",
			},
			"conflicting cache headers",
		},
		{
			map[string]string{
				"Origin":  "http://evil.com",
				"Referer": "http://trusted.com/page",
			},
			"conflicting Origin and Referer",
		},
		{
			map[string]string{
				"Content-Encoding": "gzip",
				"Transfer-Encoding": "chunked",
				"Content-Length":    "0",
			},
			"triple encoding conflict",
		},
		{
			map[string]string{
				"X-Request-ID":   "id-1",
				"X-Correlation-ID": "id-2",
				"X-Trace-ID":    "id-3",
			},
			"multiple request ID headers",
		},
		{
			map[string]string{
				"Connection":     "keep-alive, close",
				"Keep-Alive":    "timeout=5, max=1000",
				"Proxy-Connection": "keep-alive",
			},
			"conflicting connection headers",
		},
	}

	for _, hs := range headerSets {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        "/",
			Category:    "chaos",
			SubCategory: "duplicate-headers",
			Description: fmt.Sprintf("Duplicate/conflicting headers: %s", hs.desc),
			Headers:     hs.headers,
		})
	}

	return reqs
}
