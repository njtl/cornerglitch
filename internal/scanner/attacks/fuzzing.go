package attacks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/glitchWebServer/internal/scanner"
)

// FuzzingModule generates requests for path fuzzing, parameter boundary testing,
// HTTP method fuzzing, header fuzzing, and Content-Type fuzzing.
type FuzzingModule struct{}

func (m *FuzzingModule) Name() string     { return "fuzzing" }
func (m *FuzzingModule) Category() string { return "fuzzing" }

func (m *FuzzingModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.pathFuzzing()...)
	reqs = append(reqs, m.parameterFuzzing()...)
	reqs = append(reqs, m.methodFuzzing()...)
	reqs = append(reqs, m.headerFuzzing()...)
	reqs = append(reqs, m.contentTypeFuzzing()...)

	return reqs
}

// ---------------------------------------------------------------------------
// Path Fuzzing — discover hidden/sensitive paths
// ---------------------------------------------------------------------------

func (m *FuzzingModule) pathFuzzing() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Admin paths
	adminPaths := []string{
		"/admin", "/admin/", "/admin/login", "/admin/dashboard",
		"/administrator", "/manager", "/manage", "/panel",
		"/wp-admin", "/wp-login.php", "/administrator/index.php",
		"/admin/config", "/admin/settings", "/admin/users",
		"/cpanel", "/phpmyadmin", "/pma", "/adminer",
		"/console", "/debug", "/debug/default/view",
		"/_admin", "/__admin", "/secret-admin",
	}
	for _, p := range adminPaths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p,
			Headers:     map[string]string{},
			Category:    "Fuzzing",
			SubCategory: "path-admin",
			Description: fmt.Sprintf("Admin path discovery: %s", p),
		})
	}

	// Backup files
	backupFiles := []string{
		"/backup.sql", "/backup.tar.gz", "/backup.zip",
		"/db.sql", "/database.sql", "/dump.sql",
		"/site.tar.gz", "/www.zip", "/htdocs.tar.gz",
		"/.backup", "/old/", "/temp/", "/tmp/",
		"/backup/", "/backups/", "/bak/",
		"/data.json", "/export.csv", "/users.csv",
	}
	for _, p := range backupFiles {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p,
			Headers:     map[string]string{},
			Category:    "Fuzzing",
			SubCategory: "path-backup",
			Description: fmt.Sprintf("Backup file discovery: %s", p),
		})
	}

	// Config files
	configFiles := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.backup",
		"/config.json", "/config.yaml", "/config.yml", "/config.xml",
		"/settings.json", "/settings.py", "/settings.ini",
		"/application.properties", "/application.yml",
		"/web.config", "/Web.config",
		"/appsettings.json", "/appsettings.Development.json",
		"/wp-config.php", "/wp-config.php.bak",
		"/docker-compose.yml", "/Dockerfile",
		"/Makefile", "/Rakefile", "/Gemfile",
		"/package.json", "/composer.json", "/requirements.txt",
		"/go.mod", "/go.sum", "/Cargo.toml",
	}
	for _, p := range configFiles {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p,
			Headers:     map[string]string{},
			Category:    "Fuzzing",
			SubCategory: "path-config",
			Description: fmt.Sprintf("Config file discovery: %s", p),
		})
	}

	// Dot files (version control, IDE, etc.)
	dotFiles := []string{
		"/.git/HEAD", "/.git/config", "/.gitignore",
		"/.svn/entries", "/.svn/wc.db",
		"/.hg/store/", "/.hg/hgrc",
		"/.DS_Store", "/Thumbs.db",
		"/.htaccess", "/.htpasswd",
		"/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
		"/.vscode/settings.json", "/.idea/workspace.xml",
		"/.ssh/authorized_keys", "/.ssh/id_rsa",
		"/.aws/credentials", "/.docker/config.json",
	}
	for _, p := range dotFiles {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p,
			Headers:     map[string]string{},
			Category:    "Fuzzing",
			SubCategory: "path-dotfile",
			Description: fmt.Sprintf("Dot file discovery: %s", p),
		})
	}

	// API version paths
	apiPaths := []string{
		"/api/", "/api/v1/", "/api/v2/", "/api/v3/",
		"/api/internal/", "/api/debug/", "/api/admin/",
		"/api/health", "/api/status", "/api/info",
		"/api/swagger.json", "/api/openapi.json", "/api/docs",
		"/swagger-ui/", "/swagger-ui.html",
		"/graphql", "/graphiql",
		"/api/metrics", "/api/prometheus",
		"/healthz", "/readyz", "/livez",
		"/_health", "/_status",
	}
	for _, p := range apiPaths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        p,
			Headers:     map[string]string{},
			Category:    "Fuzzing",
			SubCategory: "path-api",
			Description: fmt.Sprintf("API path discovery: %s", p),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Parameter Fuzzing — boundary values and type confusion
// ---------------------------------------------------------------------------

func (m *FuzzingModule) parameterFuzzing() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Boundary values for numeric parameters
	numericValues := []struct {
		value string
		desc  string
	}{
		{"0", "Zero value"},
		{"-1", "Negative value"},
		{"-0", "Negative zero"},
		{"1", "Minimum positive"},
		{"2147483647", "INT32_MAX"},
		{"-2147483648", "INT32_MIN"},
		{"9999999999999999999", "Overflow large number"},
		{"1.1", "Float value"},
		{"1e308", "Float max exponent"},
		{"NaN", "Not a Number"},
		{"Infinity", "Infinity"},
		{"-Infinity", "Negative Infinity"},
		{"0x41", "Hex value"},
		{"0b1010", "Binary value"},
		{"00", "Octal-like zero"},
	}

	// String boundary values
	stringValues := []struct {
		value string
		desc  string
	}{
		{"", "Empty string"},
		{" ", "Single space"},
		{"null", "Literal null"},
		{"undefined", "Literal undefined"},
		{"None", "Python None"},
		{"nil", "Ruby/Go nil"},
		{"true", "Boolean true string"},
		{"false", "Boolean false string"},
		{strings.Repeat("A", 1000), "1000-char string"},
		{strings.Repeat("A", 10000), "10000-char string"},
		{strings.Repeat("../", 50), "Deep traversal string"},
		{"\x00", "Null byte"},
		{"\x00\x00\x00\x00", "Multiple null bytes"},
		{"\t\n\r", "Whitespace characters"},
		{"%00", "URL-encoded null byte"},
		{"%0d%0a", "URL-encoded CRLF"},
		{"{{7*7}}", "Template expression"},
		{"${7*7}", "Expression language"},
		{"<>\"'`;/\\", "Special characters"},
		{"\xef\xbb\xbf", "UTF-8 BOM"},
		{"\xff\xfe", "UTF-16 LE BOM"},
	}

	params := []string{"id", "page", "limit", "offset", "count"}
	paths := []string{"/", "/search", "/api/v1/users"}

	for _, path := range paths {
		for _, param := range params {
			for _, v := range numericValues {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(v.value)),
					Headers:     map[string]string{},
					Category:    "Fuzzing",
					SubCategory: "param-numeric",
					Description: fmt.Sprintf("Numeric fuzz %s?%s: %s", path, param, v.desc),
				})
			}
		}
	}

	strParams := []string{"q", "name", "search", "input"}
	for _, path := range paths {
		for _, param := range strParams {
			for _, v := range stringValues {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(v.value)),
					Headers:     map[string]string{},
					Category:    "Fuzzing",
					SubCategory: "param-string",
					Description: fmt.Sprintf("String fuzz %s?%s: %s", path, param, v.desc),
				})
			}
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Method Fuzzing — unusual HTTP methods
// ---------------------------------------------------------------------------

func (m *FuzzingModule) methodFuzzing() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	methods := []struct {
		method string
		desc   string
	}{
		{"OPTIONS", "OPTIONS method probe"},
		{"TRACE", "TRACE method (XST attack)"},
		{"CONNECT", "CONNECT method tunnel"},
		{"PATCH", "PATCH method probe"},
		{"DELETE", "DELETE method probe"},
		{"PUT", "PUT method probe"},
		{"HEAD", "HEAD method probe"},
		{"PROPFIND", "WebDAV PROPFIND"},
		{"PROPPATCH", "WebDAV PROPPATCH"},
		{"MKCOL", "WebDAV MKCOL"},
		{"COPY", "WebDAV COPY"},
		{"MOVE", "WebDAV MOVE"},
		{"LOCK", "WebDAV LOCK"},
		{"UNLOCK", "WebDAV UNLOCK"},
		{"SEARCH", "WebDAV SEARCH"},
		{"PURGE", "Cache PURGE method"},
		{"DEBUG", "ASP.NET DEBUG method"},
		{"TRACK", "TRACK method (similar to TRACE)"},
		{"JEFF", "Arbitrary custom method"},
		{"GXSS", "Custom method for WAF testing"},
	}

	paths := []string{"/", "/admin", "/api/v1/users", "/login", "/vuln/a01/admin-panel", "/vuln/verb/admin"}

	for _, path := range paths {
		for _, m := range methods {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      m.method,
				Path:        path,
				Headers:     map[string]string{},
				Category:    "Fuzzing",
				SubCategory: "method-fuzzing",
				Description: fmt.Sprintf("Method fuzz %s on %s: %s", m.method, path, m.desc),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Header Fuzzing — unusual/oversized/malicious headers
// ---------------------------------------------------------------------------

func (m *FuzzingModule) headerFuzzing() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/admin", "/api/v1/users"}

	for _, path := range paths {
		// Oversized headers
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-Large": strings.Repeat("A", 8192)},
			Category:    "Fuzzing",
			SubCategory: "header-oversize",
			Description: fmt.Sprintf("Oversized header (8KB) on %s", path),
		})
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-Huge": strings.Repeat("B", 65536)},
			Category:    "Fuzzing",
			SubCategory: "header-oversize",
			Description: fmt.Sprintf("Oversized header (64KB) on %s", path),
		})

		// Null bytes in headers
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-Null": "value\x00injected"},
			Category:    "Fuzzing",
			SubCategory: "header-null",
			Description: fmt.Sprintf("Null byte in header value on %s", path),
		})
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Null\x00Header": "value"},
			Category:    "Fuzzing",
			SubCategory: "header-null",
			Description: fmt.Sprintf("Null byte in header name on %s", path),
		})

		// CRLF in headers
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-CRLF": "value\r\nInjected-Header: true"},
			Category:    "Fuzzing",
			SubCategory: "header-crlf",
			Description: fmt.Sprintf("CRLF injection in header on %s", path),
		})

		// Special characters
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-Special": "<script>alert(1)</script>"},
			Category:    "Fuzzing",
			SubCategory: "header-special",
			Description: fmt.Sprintf("HTML/JS in header value on %s", path),
		})
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"X-Fuzz-Special": "{{7*7}}"},
			Category:    "Fuzzing",
			SubCategory: "header-special",
			Description: fmt.Sprintf("Template expression in header on %s", path),
		})

		// Many headers
		manyHeaders := make(map[string]string)
		for i := 0; i < 100; i++ {
			manyHeaders[fmt.Sprintf("X-Fuzz-%d", i)] = fmt.Sprintf("value-%d", i)
		}
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     manyHeaders,
			Category:    "Fuzzing",
			SubCategory: "header-count",
			Description: fmt.Sprintf("100 custom headers on %s", path),
		})

		// Spoofed proxy headers
		spoofHeaders := map[string]string{
			"X-Forwarded-For":   "127.0.0.1",
			"X-Real-IP":         "127.0.0.1",
			"X-Forwarded-Host":  "localhost",
			"X-Forwarded-Proto": "https",
			"X-Original-URL":    "/admin",
			"X-Rewrite-URL":     "/admin",
		}
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     spoofHeaders,
			Category:    "Fuzzing",
			SubCategory: "header-spoof",
			Description: fmt.Sprintf("Spoofed proxy headers on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Content-Type Fuzzing — mismatched and unusual content types
// ---------------------------------------------------------------------------

func (m *FuzzingModule) contentTypeFuzzing() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	contentTypes := []struct {
		ct   string
		body string
		desc string
	}{
		{"application/json", `{"key":"value"}`, "JSON body with JSON content-type"},
		{"application/xml", `<root><key>value</key></root>`, "XML body with XML content-type"},
		{"text/plain", `{"key":"value"}`, "JSON body with text/plain content-type"},
		{"application/x-www-form-urlencoded", "key=value", "Form body"},
		{"application/json", `key=value`, "Form body with JSON content-type (mismatch)"},
		{"application/xml", `{"key":"value"}`, "JSON body with XML content-type (mismatch)"},
		{"text/html", `<script>alert(1)</script>`, "HTML with script tag"},
		{"application/javascript", `alert(1)`, "JavaScript content-type"},
		{"image/png", `not-a-real-image`, "Fake image content-type"},
		{"application/pdf", `not-a-real-pdf`, "Fake PDF content-type"},
		{"application/octet-stream", "\x00\x01\x02\x03", "Binary content-type"},
		{"multipart/form-data; boundary=BOUNDARY", "--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\n\r\n<?php echo 1;?>\r\n--BOUNDARY--", "Multipart with PHP file"},
		{"application/x-java-serialized-object", "\xac\xed\x00\x05", "Java serialized object"},
		{"", `{"key":"value"}`, "Empty content-type with JSON body"},
		{"application/vnd.api+json", `{"data":{"type":"users"}}`, "JSON:API content type"},
		{"application/graphql", `{ users { id email } }`, "GraphQL content type"},
	}

	paths := []string{"/", "/api/v1/users", "/login", "/admin"}

	for _, path := range paths {
		for _, ct := range contentTypes {
			headers := map[string]string{}
			if ct.ct != "" {
				headers["Content-Type"] = ct.ct
			}
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     headers,
				Body:        ct.body,
				BodyType:    ct.ct,
				Category:    "Fuzzing",
				SubCategory: "content-type",
				Description: fmt.Sprintf("Content-Type fuzz on %s: %s", path, ct.desc),
			})
		}
	}

	return reqs
}
