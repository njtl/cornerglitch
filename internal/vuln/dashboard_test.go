package vuln

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// DashboardShouldHandle
// ---------------------------------------------------------------------------

func TestDashboardShouldHandle(t *testing.T) {
	h := NewHandler()
	want := []string{
		"/vuln/dashboard/",
		"/vuln/dashboard/analytics",
		"/vuln/dashboard/system",
		"/vuln/dashboard/debug",
		"/vuln/dashboard/debug/env",
		"/vuln/dashboard/debug/routes",
		"/vuln/dashboard/debug/sql",
		"/vuln/dashboard/debug/sessions",
		"/vuln/dashboard/debug/cache",
		"/vuln/dashboard/phpinfo",
		"/vuln/dashboard/server-status",
		"/vuln/dashboard/api-keys",
		"/vuln/dashboard/api-keys/create",
		"/vuln/dashboard/api-keys/rotate",
		"/vuln/dashboard/users",
		"/vuln/dashboard/users/export",
		"/vuln/dashboard/users/invite",
		"/vuln/dashboard/backup/download",
		"/vuln/dashboard/backup/config",
		"/vuln/dashboard/export/users",
		"/vuln/settings/",
		"/vuln/settings/general",
		"/vuln/settings/security",
		"/vuln/settings/database",
		"/vuln/settings/email",
		"/vuln/settings/storage",
		"/vuln/settings/integrations",
		"/vuln/settings/update",
		"/vuln/settings/import",
		"/vuln/settings/webhook",
		"/vuln/settings/audit",
		"/vuln/settings/audit/export",
		"/vuln/settings/changelog",
		"/vuln/settings/flags",
		"/vuln/settings/flags/update",
		"/vuln/settings/credentials",
		"/vuln/settings/certificates",
		"/vuln/settings/tokens",
	}
	for _, p := range want {
		if !h.DashboardShouldHandle(p) {
			t.Errorf("DashboardShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestDashboardShouldHandle_Negative(t *testing.T) {
	h := NewHandler()
	reject := []string{"/", "/vuln/a01/", "/admin", "/api/v1/users", "/settings"}
	for _, p := range reject {
		if h.DashboardShouldHandle(p) {
			t.Errorf("DashboardShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper: perform GET via ServeDashboard
// ---------------------------------------------------------------------------

func dashGet(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeDashboard(rec, req)
	return rec
}

func dashPost(t *testing.T, h *Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeDashboard(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// All dashboard endpoints return 200
// ---------------------------------------------------------------------------

func TestDashboard_AllEndpoints200(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/dashboard/",
		"/vuln/dashboard/analytics",
		"/vuln/dashboard/system",
		"/vuln/dashboard/debug",
		"/vuln/dashboard/debug/env",
		"/vuln/dashboard/debug/routes",
		"/vuln/dashboard/debug/sql",
		"/vuln/dashboard/debug/sessions",
		"/vuln/dashboard/debug/cache",
		"/vuln/dashboard/phpinfo",
		"/vuln/dashboard/server-status",
		"/vuln/dashboard/api-keys",
		"/vuln/dashboard/api-keys/create",
		"/vuln/dashboard/api-keys/rotate",
		"/vuln/dashboard/users",
		"/vuln/dashboard/users/export",
		"/vuln/dashboard/users/invite",
		"/vuln/dashboard/backup/download",
		"/vuln/dashboard/backup/config",
		"/vuln/dashboard/export/users",
	}
	for _, p := range paths {
		rec := dashGet(t, h, p)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p, rec.Code)
		}
	}
}

func TestSettings_AllEndpoints200(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/settings/",
		"/vuln/settings/general",
		"/vuln/settings/security",
		"/vuln/settings/database",
		"/vuln/settings/email",
		"/vuln/settings/storage",
		"/vuln/settings/integrations",
		"/vuln/settings/update",
		"/vuln/settings/import",
		"/vuln/settings/webhook",
		"/vuln/settings/audit",
		"/vuln/settings/audit/export",
		"/vuln/settings/changelog",
		"/vuln/settings/flags",
		"/vuln/settings/flags/update",
		"/vuln/settings/credentials",
		"/vuln/settings/certificates",
		"/vuln/settings/tokens",
	}
	for _, p := range paths {
		rec := dashGet(t, h, p)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Debug endpoints include environment variables / sensitive data
// ---------------------------------------------------------------------------

func TestDebugEnv_ContainsSensitiveData(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug/env")
	body := rec.Body.String()

	required := []string{
		"DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"JWT_SECRET", "STRIPE_SECRET_KEY", "ADMIN_PASSWORD",
		"SENDGRID_API_KEY", "GITHUB_TOKEN", "REDIS_URL",
	}
	for _, s := range required {
		if !strings.Contains(body, s) {
			t.Errorf("debug/env missing %q", s)
		}
	}

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("debug/env Content-Type = %q, want application/json", ct)
	}
}

func TestDebugPanel_ContainsSecrets(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug")
	body := rec.Body.String()

	for _, s := range []string{"AWS_ACCESS_KEY_ID", "DATABASE_URL", "JWT_SECRET", "STRIPE_SECRET_KEY"} {
		if !strings.Contains(body, s) {
			t.Errorf("debug panel missing %q", s)
		}
	}
}

func TestDebugRoutes_ContainsInternalPaths(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug/routes")
	body := rec.Body.String()

	for _, s := range []string{"/api/internal/debug/pprof", "/api/v1/admin/users", "AdminController"} {
		if !strings.Contains(body, s) {
			t.Errorf("debug/routes missing %q", s)
		}
	}
}

func TestDebugSQL_ContainsQueries(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug/sql")
	body := rec.Body.String()

	for _, s := range []string{"SELECT", "password_hash", "users", "duration_ms"} {
		if !strings.Contains(body, s) {
			t.Errorf("debug/sql missing %q", s)
		}
	}
}

func TestDebugSessions_ContainsTokens(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug/sessions")
	body := rec.Body.String()

	for _, s := range []string{"session_id", "token", "eyJhbGci", "csrf_token"} {
		if !strings.Contains(body, s) {
			t.Errorf("debug/sessions missing %q", s)
		}
	}
}

func TestDebugCache_ContainsCachedTokens(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/debug/cache")
	body := rec.Body.String()

	for _, s := range []string{"access_token", "gho_", "auth_header", "Bearer"} {
		if !strings.Contains(body, s) {
			t.Errorf("debug/cache missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Settings pages expose credentials
// ---------------------------------------------------------------------------

func TestSettingsDatabase_ExposesCredentials(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/database")
	body := rec.Body.String()

	for _, s := range []string{"SuperSecretP4ss!", "db-master.internal", "postgresql://", "r3d1s_s3cret"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/database missing %q", s)
		}
	}
}

func TestSettingsEmail_ExposesCredentials(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/email")
	body := rec.Body.String()

	for _, s := range []string{"SG.", "smtp.sendgrid.net", "Webhook Signing Key"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/email missing %q", s)
		}
	}
}

func TestSettingsStorage_ExposesCredentials(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/storage")
	body := rec.Body.String()

	for _, s := range []string{"AKIA", "Secret Access Key", "private_key", "RSA PRIVATE KEY"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/storage missing %q", s)
		}
	}
}

func TestSettingsIntegrations_ExposesSecrets(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/integrations")
	body := rec.Body.String()

	for _, s := range []string{"Client Secret", "sk_live_", "whsec_", "xoxb-", "Auth Token"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/integrations missing %q", s)
		}
	}
}

func TestSettingsSecurity_ShowsInsecureConfig(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/security")
	body := rec.Body.String()

	for _, s := range []string{"Disabled", "weak", "infinite", "Allow All", "INSECURE", "MD5"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/security missing %q", s)
		}
	}
}

func TestSettingsCredentials_ExposesServicePasswords(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/credentials")
	body := rec.Body.String()

	for _, s := range []string{"Pg_S3rv1ce_", "R3d1s_", "3l4st1c_", "K4fk4_Pr0d_", "R4bb1t_", "M0ng0_"} {
		if !strings.Contains(body, s) {
			t.Errorf("settings/credentials missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// API key endpoints return key formats
// ---------------------------------------------------------------------------

func TestAPIKeys_ListContainsKeys(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/api-keys")
	body := rec.Body.String()

	if !strings.Contains(body, "sk_live_") {
		t.Error("api-keys page missing sk_live_ keys")
	}
	if !strings.Contains(body, "Production API Key") {
		t.Error("api-keys page missing key names")
	}
}

func TestAPIKeys_Create(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/api-keys/create")
	body := rec.Body.String()

	if !strings.Contains(body, "sk_live_") {
		t.Error("api-keys/create missing key")
	}
	if !strings.Contains(body, `"secret"`) {
		t.Error("api-keys/create missing secret field")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("api-keys/create Content-Type = %q, want application/json", ct)
	}
}

func TestAPIKeys_Rotate(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/api-keys/rotate")
	body := rec.Body.String()

	if !strings.Contains(body, "old_key") {
		t.Error("api-keys/rotate missing old_key")
	}
	if !strings.Contains(body, "new_key") {
		t.Error("api-keys/rotate missing new_key")
	}
	if !strings.Contains(body, "sk_live_") {
		t.Error("api-keys/rotate missing sk_live_ format")
	}
}

// ---------------------------------------------------------------------------
// Export endpoints return appropriate content types
// ---------------------------------------------------------------------------

func TestUsersExport_CSV(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/users/export")

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/csv") {
		t.Errorf("users/export Content-Type = %q, want text/csv", ct)
	}

	disp := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "attachment") {
		t.Errorf("users/export Content-Disposition = %q, want attachment", disp)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "password_hash") {
		t.Error("users/export CSV missing password_hash column")
	}
	if !strings.Contains(body, "$2a$10$") {
		t.Error("users/export CSV missing bcrypt hashes")
	}
}

func TestBackupDownload_SQL(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/backup/download")

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/sql") {
		t.Errorf("backup/download Content-Type = %q, want application/sql", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "CREATE TABLE") {
		t.Error("backup/download missing CREATE TABLE")
	}
	if !strings.Contains(body, "INSERT INTO") {
		t.Error("backup/download missing INSERT INTO")
	}
	if !strings.Contains(body, "password_hash") {
		t.Error("backup/download missing password_hash column")
	}
}

func TestExportUsersJSON(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/export/users")

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("export/users Content-Type = %q, want application/json", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "password_hash") {
		t.Error("export/users JSON missing password_hash")
	}
	if !strings.Contains(body, "ssn") {
		t.Error("export/users JSON missing ssn")
	}
}

func TestAuditExport_CSV(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/audit/export")

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/csv") {
		t.Errorf("audit/export Content-Type = %q, want text/csv", ct)
	}

	disp := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "attachment") {
		t.Errorf("audit/export missing attachment disposition")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "settings.update") {
		t.Error("audit/export missing action entries")
	}
}

// ---------------------------------------------------------------------------
// Missing security headers are verified
// ---------------------------------------------------------------------------

func TestDashboard_InsecureHeaders(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/dashboard/",
		"/vuln/dashboard/debug",
		"/vuln/settings/",
		"/vuln/settings/security",
	}
	for _, p := range paths {
		rec := dashGet(t, h, p)

		// Should have debug/verbose headers
		if rec.Header().Get("X-Debug-Mode") != "true" {
			t.Errorf("%s: missing X-Debug-Mode: true", p)
		}
		if rec.Header().Get("Server") == "" {
			t.Errorf("%s: missing verbose Server header", p)
		}
		if rec.Header().Get("X-Powered-By") == "" {
			t.Errorf("%s: missing X-Powered-By header", p)
		}
		if rec.Header().Get("X-Server-Version") == "" {
			t.Errorf("%s: missing X-Server-Version header", p)
		}

		// Should NOT have security headers
		if rec.Header().Get("X-Frame-Options") != "" {
			t.Errorf("%s: should not set X-Frame-Options", p)
		}
		if rec.Header().Get("X-Content-Type-Options") != "" {
			t.Errorf("%s: should not set X-Content-Type-Options", p)
		}
	}
}

func TestDashboard_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	cases := map[string]string{
		"/vuln/dashboard/":            "unauthenticated-access",
		"/vuln/dashboard/debug":       "information-disclosure",
		"/vuln/dashboard/api-keys":    "insecure-api-keys",
		"/vuln/dashboard/users":       "broken-access-control",
		"/vuln/settings/security":     "security-misconfiguration",
		"/vuln/settings/database":     "credential-exposure",
		"/vuln/settings/audit":        "audit-log-exposure",
		"/vuln/settings/flags":        "feature-flag-exposure",
		"/vuln/settings/update":       "mass-assignment",
		"/vuln/settings/credentials":  "credential-exposure",
		"/vuln/settings/certificates": "credential-exposure",
	}
	for path, wantVuln := range cases {
		rec := dashGet(t, h, path)
		got := rec.Header().Get("X-Glitch-Vuln-Type")
		if got != wantVuln {
			t.Errorf("%s: X-Glitch-Vuln-Type = %q, want %q", path, got, wantVuln)
		}
	}
}

// ---------------------------------------------------------------------------
// User management endpoints work without auth
// ---------------------------------------------------------------------------

func TestUserManagement_NoAuth(t *testing.T) {
	h := NewHandler()

	// Users list (GET, no auth)
	rec := dashGet(t, h, "/vuln/dashboard/users")
	if rec.Code != http.StatusOK {
		t.Errorf("users list: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Password Hint") {
		t.Error("users list missing password hints")
	}

	// Users export (GET, no auth, CSV)
	rec = dashGet(t, h, "/vuln/dashboard/users/export")
	if rec.Code != http.StatusOK {
		t.Errorf("users export: status %d, want 200", rec.Code)
	}

	// Users invite (POST, no auth)
	rec = dashPost(t, h, "/vuln/dashboard/users/invite", "email=attacker@evil.com&role=superadmin")
	if rec.Code != http.StatusOK {
		t.Errorf("users invite: status %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, "invited") {
		t.Error("users invite missing 'invited' status")
	}
}

// ---------------------------------------------------------------------------
// Audit log contains realistic entries
// ---------------------------------------------------------------------------

func TestAuditLog_RealisticEntries(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/audit")
	body := rec.Body.String()

	entries := []string{
		"settings.update",
		"user.delete",
		"api_key.create",
		"backup.download",
		"user.role_change",
		"auth.login",
		"export.users",
	}
	for _, e := range entries {
		if !strings.Contains(body, e) {
			t.Errorf("audit log missing action %q", e)
		}
	}

	// Should contain request bodies with sensitive data
	if !strings.Contains(body, "password_policy") {
		t.Error("audit log missing request body content")
	}
}

func TestChangelog_ShowsOldNewValues(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/changelog")
	body := rec.Body.String()

	for _, s := range []string{"Old Value", "New Value", "database.password", "jwt_secret", "debug_mode"} {
		if !strings.Contains(body, s) {
			t.Errorf("changelog missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// phpinfo and server-status
// ---------------------------------------------------------------------------

func TestPHPInfo_RealisticPage(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/phpinfo")
	body := rec.Body.String()

	for _, s := range []string{"PHP Version", "phpinfo()", "DATABASE_URL", "AWS_ACCESS_KEY_ID",
		"display_errors", "register_globals", "mysql.default_password"} {
		if !strings.Contains(body, s) {
			t.Errorf("phpinfo missing %q", s)
		}
	}
}

func TestServerStatus_ApacheStyle(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/server-status")
	body := rec.Body.String()

	for _, s := range []string{"Apache", "uptime", "Active Connections", "Scoreboard"} {
		if !strings.Contains(body, s) {
			t.Errorf("server-status missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

func TestFeatureFlags_ContainSecrets(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/flags")
	body := rec.Body.String()

	for _, s := range []string{"sk_live_", "AKIA", "sk-proj-"} {
		if !strings.Contains(body, s) {
			t.Errorf("feature flags missing %q", s)
		}
	}
}

func TestFeatureFlagsUpdate_NoAuth(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/flags/update")
	body := rec.Body.String()

	if !strings.Contains(body, "anonymous (no auth)") {
		t.Error("flags update missing anonymous indicator")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("flags/update Content-Type = %q, want application/json", ct)
	}
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

func TestCertificates_ContainsPrivateKey(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/certificates")
	body := rec.Body.String()

	if !strings.Contains(body, "BEGIN RSA PRIVATE KEY") {
		t.Error("certificates missing RSA private key")
	}
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Error("certificates missing certificate")
	}
}

// ---------------------------------------------------------------------------
// Configuration injection endpoints
// ---------------------------------------------------------------------------

func TestSettingsUpdate_MassAssignment(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/update")
	body := rec.Body.String()

	if !strings.Contains(body, "mass assignment") && !strings.Contains(body, "Mass assignment") {
		t.Error("settings/update missing mass assignment warning")
	}
	if !strings.Contains(body, "merged_config") {
		t.Error("settings/update missing merged_config")
	}
}

func TestSettingsImport_NoValidation(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/import")
	body := rec.Body.String()

	if !strings.Contains(body, "No validation") {
		t.Error("settings/import missing no-validation warning")
	}
}

func TestSettingsWebhook_SSRF(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/webhook")
	body := rec.Body.String()

	if !strings.Contains(body, "SSRF") {
		t.Error("settings/webhook missing SSRF indicator")
	}
	if !strings.Contains(body, "url") {
		t.Error("settings/webhook missing url field")
	}
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

func TestTokens_ContainsActiveTokens(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/settings/tokens")
	body := rec.Body.String()

	if !strings.Contains(body, "glitch_") {
		t.Error("tokens page missing glitch_ token prefix")
	}
	if !strings.Contains(body, "Never") {
		t.Error("tokens page missing non-expiring tokens")
	}
	if !strings.Contains(body, "admin") {
		t.Error("tokens page missing admin scope")
	}
}

// ---------------------------------------------------------------------------
// Dashboard home contains stats
// ---------------------------------------------------------------------------

func TestDashboardHome_HasStats(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/")
	body := rec.Body.String()

	for _, s := range []string{"Total Users", "Monthly Revenue", "Active Sessions", "Uptime", "Recent Activity"} {
		if !strings.Contains(body, s) {
			t.Errorf("dashboard home missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Analytics shows revenue data
// ---------------------------------------------------------------------------

func TestAnalytics_ShowsRevenue(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/analytics")
	body := rec.Body.String()

	for _, s := range []string{"Monthly Revenue", "Annual Revenue", "Conversion Rate", "ARPU", "Enterprise"} {
		if !strings.Contains(body, s) {
			t.Errorf("analytics missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

func TestSystemInfo_ExposesServerDetails(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/system")
	body := rec.Body.String()

	for _, s := range []string{"Kernel", "CPU", "Memory", "Open Ports", "Running Processes", "Installed Packages", "sshd", "redis-server"} {
		if !strings.Contains(body, s) {
			t.Errorf("system info missing %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Backup config exposes S3 credentials
// ---------------------------------------------------------------------------

func TestBackupConfig_ExposesCredentials(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/backup/config")
	body := rec.Body.String()

	for _, s := range []string{"AKIA", "secret_access_key", "acmecorp-prod-backups", "B4ckup_S3cret"} {
		if !strings.Contains(body, s) {
			t.Errorf("backup/config missing %q", s)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("backup/config Content-Type = %q, want application/json", ct)
	}
}

// ---------------------------------------------------------------------------
// Unknown dashboard subpath returns 404
// ---------------------------------------------------------------------------

func TestDashboard_UnknownPath404(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: status %d, want 404", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Deterministic responses
// ---------------------------------------------------------------------------

func TestDashboard_Deterministic(t *testing.T) {
	h := NewHandler()
	r1 := dashGet(t, h, "/vuln/dashboard/debug/env").Body.String()
	r2 := dashGet(t, h, "/vuln/dashboard/debug/env").Body.String()
	if r1 != r2 {
		t.Error("debug/env responses are not deterministic")
	}
}

// ---------------------------------------------------------------------------
// Dashboard sidebar contains navigation
// ---------------------------------------------------------------------------

func TestDashboard_SidebarNavigation(t *testing.T) {
	h := NewHandler()
	rec := dashGet(t, h, "/vuln/dashboard/")
	body := rec.Body.String()

	links := []string{
		"/vuln/dashboard/analytics",
		"/vuln/dashboard/debug",
		"/vuln/dashboard/api-keys",
		"/vuln/dashboard/users",
		"/vuln/settings/",
		"/vuln/settings/security",
		"/vuln/settings/credentials",
	}
	for _, l := range links {
		if !strings.Contains(body, l) {
			t.Errorf("sidebar missing link %q", l)
		}
	}

	if !strings.Contains(body, "Logged in as:") {
		t.Error("sidebar missing 'Logged in as:' indicator")
	}
	if !strings.Contains(body, "admin") {
		t.Error("sidebar missing admin user")
	}
}
