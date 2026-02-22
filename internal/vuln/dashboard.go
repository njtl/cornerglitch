package vuln

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Routing helpers
// ---------------------------------------------------------------------------

// DashboardShouldHandle returns true if the path should be handled by the
// dashboard/settings vulnerability emulator.
func (h *Handler) DashboardShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/dashboard/") ||
		strings.HasPrefix(path, "/vuln/dashboard") ||
		strings.HasPrefix(path, "/vuln/settings/") ||
		strings.HasPrefix(path, "/vuln/settings")
}

// ServeDashboard dispatches the request to the appropriate dashboard or
// settings vulnerability handler.  Returns the HTTP status code written.
func (h *Handler) ServeDashboard(w http.ResponseWriter, r *http.Request) int {
	// Insecure headers on every dashboard/settings response
	w.Header().Set("X-Debug-Mode", "true")
	w.Header().Set("Server", "Apache/2.4.29 (Ubuntu) OpenSSL/1.0.2g PHP/5.6.40")
	w.Header().Set("X-Powered-By", "PHP/5.6.40")
	w.Header().Set("X-Server-Version", "GlitchAdmin/3.8.1-internal")
	// Intentionally omit X-Frame-Options and X-Content-Type-Options

	path := r.URL.Path

	// ---- Dashboard routes ----
	switch path {
	case "/vuln/dashboard", "/vuln/dashboard/":
		return h.serveDashHome(w, r)
	case "/vuln/dashboard/analytics":
		return h.serveDashAnalytics(w, r)
	case "/vuln/dashboard/system":
		return h.serveDashSystem(w, r)
	case "/vuln/dashboard/debug":
		return h.serveDashDebug(w, r)
	case "/vuln/dashboard/debug/env":
		return h.serveDashDebugEnv(w, r)
	case "/vuln/dashboard/debug/routes":
		return h.serveDashDebugRoutes(w, r)
	case "/vuln/dashboard/debug/sql":
		return h.serveDashDebugSQL(w, r)
	case "/vuln/dashboard/debug/sessions":
		return h.serveDashDebugSessions(w, r)
	case "/vuln/dashboard/debug/cache":
		return h.serveDashDebugCache(w, r)
	case "/vuln/dashboard/phpinfo":
		return h.serveDashPHPInfo(w, r)
	case "/vuln/dashboard/server-status":
		return h.serveDashServerStatus(w, r)
	case "/vuln/dashboard/api-keys":
		return h.serveDashAPIKeys(w, r)
	case "/vuln/dashboard/api-keys/create":
		return h.serveDashAPIKeysCreate(w, r)
	case "/vuln/dashboard/api-keys/rotate":
		return h.serveDashAPIKeysRotate(w, r)
	case "/vuln/dashboard/users":
		return h.serveDashUsers(w, r)
	case "/vuln/dashboard/users/export":
		return h.serveDashUsersExport(w, r)
	case "/vuln/dashboard/users/invite":
		return h.serveDashUsersInvite(w, r)
	case "/vuln/dashboard/backup/download":
		return h.serveDashBackupDownload(w, r)
	case "/vuln/dashboard/backup/config":
		return h.serveDashBackupConfig(w, r)
	case "/vuln/dashboard/export/users":
		return h.serveDashExportUsers(w, r)

	// ---- Settings routes ----
	case "/vuln/settings", "/vuln/settings/":
		return h.serveSettingsHome(w, r)
	case "/vuln/settings/general":
		return h.serveSettingsGeneral(w, r)
	case "/vuln/settings/security":
		return h.serveSettingsSecurity(w, r)
	case "/vuln/settings/database":
		return h.serveSettingsDatabase(w, r)
	case "/vuln/settings/email":
		return h.serveSettingsEmail(w, r)
	case "/vuln/settings/storage":
		return h.serveSettingsStorage(w, r)
	case "/vuln/settings/integrations":
		return h.serveSettingsIntegrations(w, r)
	case "/vuln/settings/update":
		return h.serveSettingsUpdate(w, r)
	case "/vuln/settings/import":
		return h.serveSettingsImport(w, r)
	case "/vuln/settings/webhook":
		return h.serveSettingsWebhook(w, r)
	case "/vuln/settings/audit":
		return h.serveSettingsAudit(w, r)
	case "/vuln/settings/audit/export":
		return h.serveSettingsAuditExport(w, r)
	case "/vuln/settings/changelog":
		return h.serveSettingsChangelog(w, r)
	case "/vuln/settings/flags":
		return h.serveSettingsFlags(w, r)
	case "/vuln/settings/flags/update":
		return h.serveSettingsFlagsUpdate(w, r)
	case "/vuln/settings/credentials":
		return h.serveSettingsCredentials(w, r)
	case "/vuln/settings/certificates":
		return h.serveSettingsCertificates(w, r)
	case "/vuln/settings/tokens":
		return h.serveSettingsTokens(w, r)
	}

	// Unknown subpath
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, h.dashWrapHTML("Not Found", h.dashSidebar(path), "<p>Page not found.</p>"))
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Convenience helpers used only in this file
// ---------------------------------------------------------------------------

// seedFromPath returns a deterministic RNG seeded from the given path.
// It delegates to rngFromPath in owasp.go.
func (h *Handler) seedFromPath(path string) *rand.Rand {
	return h.rngFromPath(path)
}

// randomName returns "First Last" using the handler's name lists.
func (h *Handler) randomName(rng *rand.Rand) string {
	first := h.firstNames[rng.Intn(len(h.firstNames))]
	last := h.lastNames[rng.Intn(len(h.lastNames))]
	return strings.Title(first) + " " + strings.Title(last) //nolint:staticcheck
}

// randomEmail returns "first.last@domain" using the handler's lists.
func (h *Handler) randomEmail(rng *rand.Rand) string {
	first := h.firstNames[rng.Intn(len(h.firstNames))]
	last := h.lastNames[rng.Intn(len(h.lastNames))]
	domain := h.domains[rng.Intn(len(h.domains))]
	return fmt.Sprintf("%s.%s@%s", first, last, domain)
}

// randomIP returns a fake internal-ish IP address.
func (h *Handler) randomIP(rng *rand.Rand) string {
	return fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256))
}

// randomToken returns a hex token of the given length.
func (h *Handler) randomToken(rng *rand.Rand, n int) string {
	return h.randomHex(rng, n)
}

// randomDate returns a deterministic date in the recent past.
func (h *Handler) randomDate(rng *rand.Rand) string {
	t := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(
		-time.Duration(rng.Intn(365*24)) * time.Hour,
	)
	return t.Format("2006-01-02 15:04:05")
}

// randomRecentDate returns a date within the last 7 days.
func (h *Handler) randomRecentDate(rng *rand.Rand) string {
	t := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC).Add(
		-time.Duration(rng.Intn(7*24)) * time.Hour,
	)
	return t.Format("2006-01-02 15:04:05")
}

// ---------------------------------------------------------------------------
// Dashboard HTML wrapper
// ---------------------------------------------------------------------------

func (h *Handler) dashSidebar(activePath string) string {
	type link struct {
		Href  string
		Label string
	}

	sections := []struct {
		Title string
		Links []link
	}{
		{"Dashboard", []link{
			{"/vuln/dashboard/", "Overview"},
			{"/vuln/dashboard/analytics", "Analytics"},
			{"/vuln/dashboard/system", "System Info"},
		}},
		{"Debug", []link{
			{"/vuln/dashboard/debug", "Debug Panel"},
			{"/vuln/dashboard/debug/env", "Environment"},
			{"/vuln/dashboard/debug/routes", "Routes"},
			{"/vuln/dashboard/debug/sql", "SQL Queries"},
			{"/vuln/dashboard/debug/sessions", "Sessions"},
			{"/vuln/dashboard/debug/cache", "Cache"},
			{"/vuln/dashboard/phpinfo", "phpinfo()"},
			{"/vuln/dashboard/server-status", "Server Status"},
		}},
		{"API Keys", []link{
			{"/vuln/dashboard/api-keys", "Manage Keys"},
			{"/vuln/dashboard/api-keys/create", "Create Key"},
			{"/vuln/dashboard/api-keys/rotate", "Rotate All"},
		}},
		{"Users", []link{
			{"/vuln/dashboard/users", "User List"},
			{"/vuln/dashboard/users/export", "Export CSV"},
			{"/vuln/dashboard/users/invite", "Invite User"},
		}},
		{"Backups", []link{
			{"/vuln/dashboard/backup/download", "Download Backup"},
			{"/vuln/dashboard/backup/config", "Backup Config"},
			{"/vuln/dashboard/export/users", "Export Users JSON"},
		}},
		{"Settings", []link{
			{"/vuln/settings/", "General"},
			{"/vuln/settings/security", "Security"},
			{"/vuln/settings/database", "Database"},
			{"/vuln/settings/email", "Email / SMTP"},
			{"/vuln/settings/storage", "Storage"},
			{"/vuln/settings/integrations", "Integrations"},
		}},
		{"Config", []link{
			{"/vuln/settings/update", "Update Config"},
			{"/vuln/settings/import", "Import Config"},
			{"/vuln/settings/webhook", "Webhooks"},
		}},
		{"Audit", []link{
			{"/vuln/settings/audit", "Audit Log"},
			{"/vuln/settings/audit/export", "Export Audit"},
			{"/vuln/settings/changelog", "Changelog"},
		}},
		{"Feature Flags", []link{
			{"/vuln/settings/flags", "Flags"},
			{"/vuln/settings/flags/update", "Update Flags"},
		}},
		{"Credentials", []link{
			{"/vuln/settings/credentials", "Service Accounts"},
			{"/vuln/settings/certificates", "Certificates"},
			{"/vuln/settings/tokens", "API Tokens"},
		}},
	}

	var sb strings.Builder
	for _, sec := range sections {
		sb.WriteString(fmt.Sprintf(`<div class="sb-section">%s</div>`, sec.Title))
		for _, l := range sec.Links {
			cls := ""
			if l.Href == activePath {
				cls = ` class="active"`
			}
			sb.WriteString(fmt.Sprintf(`<a href="%s"%s>%s</a>`, l.Href, cls, l.Label))
		}
	}
	return sb.String()
}

func (h *Handler) dashWrapHTML(title, sidebar, content string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s - Admin Panel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; min-height: 100vh; }
    .sidebar { width: 240px; background: #161b22; border-right: 1px solid #30363d; padding: 16px 0; overflow-y: auto; flex-shrink: 0; }
    .sidebar .logo { padding: 12px 16px; font-size: 15px; font-weight: 700; color: #58a6ff; border-bottom: 1px solid #30363d; margin-bottom: 8px; }
    .sidebar .user-info { padding: 8px 16px; font-size: 12px; color: #8b949e; border-bottom: 1px solid #30363d; margin-bottom: 8px; }
    .sidebar .user-info strong { color: #f85149; }
    .sidebar .sb-section { padding: 10px 16px 4px; font-size: 11px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }
    .sidebar a { display: block; padding: 5px 16px 5px 24px; color: #c9d1d9; text-decoration: none; font-size: 13px; }
    .sidebar a:hover { background: #1f2937; color: #58a6ff; }
    .sidebar a.active { background: #1f6feb33; color: #58a6ff; border-left: 3px solid #58a6ff; padding-left: 21px; }
    .main { flex: 1; display: flex; flex-direction: column; }
    .topbar { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 24px; display: flex; align-items: center; justify-content: space-between; }
    .breadcrumb { font-size: 13px; color: #8b949e; }
    .breadcrumb a { color: #58a6ff; text-decoration: none; }
    .topbar .badge { background: #f8514933; color: #f85149; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
    .content { padding: 24px; flex: 1; overflow-y: auto; }
    h1 { font-size: 22px; color: #e6edf3; margin-bottom: 16px; }
    h2 { font-size: 17px; color: #e6edf3; margin: 18px 0 10px; }
    table { border-collapse: collapse; width: 100%%; margin: 12px 0; background: #161b22; border: 1px solid #30363d; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 13px; }
    th { background: #1c2333; color: #8b949e; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
    tr:hover { background: #1f293766; }
    pre, code { background: #161b22; border: 1px solid #30363d; border-radius: 6px; font-size: 12px; font-family: "SFMono-Regular", Consolas, monospace; }
    pre { padding: 14px; overflow-x: auto; margin: 10px 0; }
    code { padding: 2px 6px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 10px 0; }
    .stat { display: inline-block; text-align: center; padding: 16px 28px; margin: 6px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
    .stat .value { font-size: 28px; font-weight: 700; color: #58a6ff; }
    .stat .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
    .tag-green { background: #23863633; color: #3fb950; }
    .tag-red { background: #f8514933; color: #f85149; }
    .tag-yellow { background: #d2992233; color: #d29922; }
    .tag-blue { background: #1f6feb33; color: #58a6ff; }
    .footer { padding: 12px 24px; font-size: 11px; color: #484f58; border-top: 1px solid #30363d; text-align: center; }
    .warn { background: #f8514922; border: 1px solid #f85149; border-radius: 6px; padding: 10px 14px; margin: 10px 0; color: #f85149; font-size: 13px; }
  </style>
</head>
<body>
  <div class="sidebar">
    <div class="logo">Glitch Admin</div>
    <div class="user-info">Logged in as: <strong>admin</strong><br>Role: superadmin</div>
    %s
  </div>
  <div class="main">
    <div class="topbar">
      <div class="breadcrumb"><a href="/vuln/dashboard/">Dashboard</a> &raquo; %s</div>
      <div class="badge">DEBUG MODE</div>
    </div>
    <div class="content">
      <h1>%s</h1>
      %s
    </div>
    <div class="footer">GlitchAdmin v3.8.1-internal &bull; Server: Apache/2.4.29 &bull; PHP/5.6.40 &bull; OpenSSL/1.0.2g &bull; Uptime: 847 days</div>
  </div>
</body>
</html>`, title, sidebar, title, title, content)
}

// dashHTML is a shorthand to render a dashboard page.
func (h *Handler) dashHTML(w http.ResponseWriter, path, title, vulnType, content string) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Glitch-Vuln-Type", vulnType)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.dashWrapHTML(title, h.dashSidebar(path), content))
	return http.StatusOK
}

// dashJSON is a shorthand to render a JSON response.
func (h *Handler) dashJSON(w http.ResponseWriter, vulnType, json string) int {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Glitch-Vuln-Type", vulnType)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, json)
	return http.StatusOK
}

// ===========================================================================
// 1. Unauthenticated Dashboard Access
// ===========================================================================

func (h *Handler) serveDashHome(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/")
	body := fmt.Sprintf(`
<div class="warn">Warning: No authentication required. This dashboard is publicly accessible.</div>
<div style="display:flex;flex-wrap:wrap;">
  <div class="stat"><div class="value">%d</div><div class="label">Total Users</div></div>
  <div class="stat"><div class="value">$%d</div><div class="label">Monthly Revenue</div></div>
  <div class="stat"><div class="value">%d</div><div class="label">Active Sessions</div></div>
  <div class="stat"><div class="value">%.1f%%</div><div class="label">Uptime</div></div>
  <div class="stat"><div class="value">%d</div><div class="label">API Calls Today</div></div>
  <div class="stat"><div class="value">%d</div><div class="label">Errors (24h)</div></div>
</div>

<h2>Recent Activity</h2>
<table>
  <tr><th>Time</th><th>User</th><th>Action</th><th>IP</th></tr>
  <tr><td>%s</td><td>admin</td><td>Deleted user account #4892</td><td>%s</td></tr>
  <tr><td>%s</td><td>admin</td><td>Modified database settings</td><td>%s</td></tr>
  <tr><td>%s</td><td>%s</td><td>Exported user database</td><td>%s</td></tr>
  <tr><td>%s</td><td>admin</td><td>Rotated API keys</td><td>%s</td></tr>
  <tr><td>%s</td><td>%s</td><td>Changed SMTP password</td><td>%s</td></tr>
</table>

<h2>System Alerts</h2>
<div class="card">
  <p><span class="tag tag-red">CRITICAL</span> SSL certificate expires in 3 days</p>
  <p><span class="tag tag-yellow">WARNING</span> Disk usage at 87%%</p>
  <p><span class="tag tag-yellow">WARNING</span> 2FA disabled for admin accounts</p>
  <p><span class="tag tag-red">CRITICAL</span> Debug mode enabled in production</p>
</div>`,
		rng.Intn(40000)+10000,
		rng.Intn(500000)+100000,
		rng.Intn(3000)+500,
		99.0+float64(rng.Intn(100))/100.0,
		rng.Intn(900000)+100000,
		rng.Intn(500)+10,
		h.randomRecentDate(rng), h.randomIP(rng),
		h.randomRecentDate(rng), h.randomIP(rng),
		h.randomRecentDate(rng), h.randomName(rng), h.randomIP(rng),
		h.randomRecentDate(rng), h.randomIP(rng),
		h.randomRecentDate(rng), h.randomName(rng), h.randomIP(rng),
	)
	return h.dashHTML(w, "/vuln/dashboard/", "Admin Dashboard", "unauthenticated-access", body)
}

func (h *Handler) serveDashAnalytics(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/analytics")
	revenue := rng.Intn(500000) + 200000
	users := rng.Intn(50000) + 10000
	conversion := float64(rng.Intn(800)+200) / 100.0
	churn := float64(rng.Intn(500)+50) / 100.0
	arpu := float64(rng.Intn(8000)+1000) / 100.0
	body := fmt.Sprintf(`
<div style="display:flex;flex-wrap:wrap;">
  <div class="stat"><div class="value">$%d</div><div class="label">Monthly Revenue</div></div>
  <div class="stat"><div class="value">$%d</div><div class="label">Annual Revenue</div></div>
  <div class="stat"><div class="value">%d</div><div class="label">Paying Users</div></div>
  <div class="stat"><div class="value">%.2f%%</div><div class="label">Conversion Rate</div></div>
  <div class="stat"><div class="value">%.2f%%</div><div class="label">Churn Rate</div></div>
  <div class="stat"><div class="value">$%.2f</div><div class="label">ARPU</div></div>
</div>

<h2>Revenue by Plan</h2>
<table>
  <tr><th>Plan</th><th>Users</th><th>MRR</th><th>ARPU</th></tr>
  <tr><td>Free</td><td>%d</td><td>$0</td><td>$0.00</td></tr>
  <tr><td>Starter ($29/mo)</td><td>%d</td><td>$%d</td><td>$29.00</td></tr>
  <tr><td>Pro ($99/mo)</td><td>%d</td><td>$%d</td><td>$99.00</td></tr>
  <tr><td>Enterprise ($499/mo)</td><td>%d</td><td>$%d</td><td>$499.00</td></tr>
</table>

<h2>Top Customers</h2>
<table>
  <tr><th>Company</th><th>Plan</th><th>MRR</th><th>Users</th></tr>
  <tr><td>Acme Corp</td><td>Enterprise</td><td>$%d</td><td>%d</td></tr>
  <tr><td>Globex Industries</td><td>Enterprise</td><td>$%d</td><td>%d</td></tr>
  <tr><td>Initech Solutions</td><td>Pro</td><td>$%d</td><td>%d</td></tr>
  <tr><td>Umbrella Corp</td><td>Enterprise</td><td>$%d</td><td>%d</td></tr>
</table>`,
		revenue, revenue*12, users, conversion, churn, arpu,
		rng.Intn(20000)+5000,
		rng.Intn(3000)+1000, rng.Intn(90000)+30000,
		rng.Intn(2000)+500, rng.Intn(200000)+50000,
		rng.Intn(200)+50, rng.Intn(100000)+25000,
		rng.Intn(5000)+2000, rng.Intn(200)+50,
		rng.Intn(5000)+2000, rng.Intn(200)+50,
		rng.Intn(3000)+500, rng.Intn(100)+20,
		rng.Intn(5000)+2000, rng.Intn(200)+50,
	)
	return h.dashHTML(w, "/vuln/dashboard/analytics", "Analytics", "unauthenticated-access", body)
}

func (h *Handler) serveDashSystem(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/system")
	body := fmt.Sprintf(`
<h2>Server Information</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Hostname</td><td>prod-web-01.internal.acmecorp.net</td></tr>
  <tr><td>OS</td><td>Ubuntu 20.04.6 LTS</td></tr>
  <tr><td>Kernel</td><td>5.4.0-167-generic</td></tr>
  <tr><td>Architecture</td><td>x86_64</td></tr>
  <tr><td>CPU</td><td>Intel Xeon E5-2680 v4 @ 2.40GHz (8 cores)</td></tr>
  <tr><td>Memory</td><td>%d MB / 32768 MB (%.1f%% used)</td></tr>
  <tr><td>Disk</td><td>%d GB / 500 GB (%.1f%% used)</td></tr>
  <tr><td>Uptime</td><td>847 days, 14:22:36</td></tr>
  <tr><td>Load Average</td><td>%.2f, %.2f, %.2f</td></tr>
  <tr><td>Public IP</td><td>203.0.113.%d</td></tr>
  <tr><td>Private IP</td><td>10.0.1.%d</td></tr>
</table>

<h2>Running Processes (top 10)</h2>
<pre>PID   USER     %%CPU %%MEM  COMMAND
1     root      0.0  0.1  /sbin/init
847   root      0.0  0.2  /usr/sbin/sshd -D
1203  www-data  2.3  4.5  /usr/sbin/apache2 -k start
1204  www-data  1.8  4.2  /usr/sbin/apache2 -k start
1567  postgres  0.5 12.3  /usr/lib/postgresql/14/bin/postgres
1892  redis     0.3  2.1  /usr/bin/redis-server *:6379
2104  root      0.1  0.3  /usr/bin/containerd
2340  root      0.0  0.1  /usr/sbin/cron -f
3001  app       3.2  8.7  node /opt/app/server.js
3445  root      0.0  0.5  /usr/bin/dockerd -H fd://</pre>

<h2>Open Ports</h2>
<pre>Proto  Local Address     Foreign Address   State       PID/Program
tcp    0.0.0.0:22        0.0.0.0:*         LISTEN      847/sshd
tcp    0.0.0.0:80        0.0.0.0:*         LISTEN      1203/apache2
tcp    0.0.0.0:443       0.0.0.0:*         LISTEN      1203/apache2
tcp    0.0.0.0:3000      0.0.0.0:*         LISTEN      3001/node
tcp    0.0.0.0:5432      0.0.0.0:*         LISTEN      1567/postgres
tcp    0.0.0.0:6379      0.0.0.0:*         LISTEN      1892/redis-server
tcp    0.0.0.0:8080      0.0.0.0:*         LISTEN      3001/node
tcp    0.0.0.0:9090      0.0.0.0:*         LISTEN      2890/prometheus</pre>

<h2>Installed Packages (security-relevant)</h2>
<pre>openssl            1.0.2g-1ubuntu4.20
libssl1.0.0        1.0.2g-1ubuntu4.20
openssh-server     1:7.6p1-4ubuntu0.7
apache2            2.4.29-1ubuntu4.27
php5.6             5.6.40-1+ubuntu18.04
postgresql-14      14.10-1.pgdg20.04+1
redis-server       5:5.0.7-2
docker-ce          5:24.0.7-1~ubuntu.20.04</pre>`,
		rng.Intn(16000)+16000, float64(rng.Intn(400)+500)/10.0,
		rng.Intn(200)+250, float64(rng.Intn(400)+500)/10.0,
		float64(rng.Intn(300)+100)/100.0,
		float64(rng.Intn(200)+80)/100.0,
		float64(rng.Intn(150)+50)/100.0,
		rng.Intn(254)+1,
		rng.Intn(254)+1,
	)
	return h.dashHTML(w, "/vuln/dashboard/system", "System Information", "unauthenticated-access", body)
}

// ===========================================================================
// 2. Information Disclosure
// ===========================================================================

func (h *Handler) serveDashDebug(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/debug")
	body := fmt.Sprintf(`
<div class="warn">DEBUG MODE IS ENABLED IN PRODUCTION</div>
<h2>Environment Variables (excerpt)</h2>
<table>
  <tr><th>Variable</th><th>Value</th></tr>
  <tr><td>AWS_ACCESS_KEY_ID</td><td>AKIA%s</td></tr>
  <tr><td>AWS_SECRET_ACCESS_KEY</td><td>%s</td></tr>
  <tr><td>DATABASE_URL</td><td>postgresql://admin:SuperSecretP4ss!@db-master.internal:5432/production</td></tr>
  <tr><td>REDIS_URL</td><td>redis://:r3d1s_s3cret@redis.internal:6379/0</td></tr>
  <tr><td>API_SECRET_KEY</td><td>sk_live_%s</td></tr>
  <tr><td>STRIPE_SECRET_KEY</td><td>sk_live_%s</td></tr>
  <tr><td>JWT_SECRET</td><td>%s</td></tr>
  <tr><td>SENDGRID_API_KEY</td><td>SG.%s.%s</td></tr>
  <tr><td>GITHUB_TOKEN</td><td>ghp_%s</td></tr>
  <tr><td>SLACK_WEBHOOK_URL</td><td>https://hooks.slack.com/services/T%s/B%s/%s</td></tr>
</table>

<h2>Quick Links</h2>
<ul>
  <li><a href="/vuln/dashboard/debug/env">Full Environment Dump (JSON)</a></li>
  <li><a href="/vuln/dashboard/debug/routes">Route Table</a></li>
  <li><a href="/vuln/dashboard/debug/sql">Recent SQL Queries</a></li>
  <li><a href="/vuln/dashboard/debug/sessions">Active Sessions</a></li>
  <li><a href="/vuln/dashboard/debug/cache">Cache Contents</a></li>
</ul>`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 24),
		h.randomHex(rng, 24),
		h.randomHex(rng, 64),
		h.randomHex(rng, 22), h.randomHex(rng, 40),
		h.randomHex(rng, 36),
		h.randomHex(rng, 9), h.randomHex(rng, 9), h.randomHex(rng, 24),
	)
	return h.dashHTML(w, "/vuln/dashboard/debug", "Debug Panel", "information-disclosure", body)
}

func (h *Handler) serveDashDebugEnv(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/debug/env")
	envJSON := fmt.Sprintf(`{
  "NODE_ENV": "production",
  "PORT": "3000",
  "HOST": "0.0.0.0",
  "DATABASE_URL": "postgresql://admin:SuperSecretP4ss!@db-master.internal:5432/production",
  "DATABASE_REPLICA_URL": "postgresql://readonly:R3adOnly!@db-replica.internal:5432/production",
  "REDIS_URL": "redis://:r3d1s_s3cret@redis.internal:6379/0",
  "AWS_ACCESS_KEY_ID": "AKIA%s",
  "AWS_SECRET_ACCESS_KEY": "%s",
  "AWS_REGION": "us-east-1",
  "AWS_S3_BUCKET": "acmecorp-prod-assets",
  "API_SECRET_KEY": "sk_live_%s",
  "STRIPE_SECRET_KEY": "sk_live_%s",
  "STRIPE_WEBHOOK_SECRET": "whsec_%s",
  "JWT_SECRET": "%s",
  "JWT_REFRESH_SECRET": "%s",
  "SENDGRID_API_KEY": "SG.%s.%s",
  "GITHUB_TOKEN": "ghp_%s",
  "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T%s/B%s/%s",
  "SENTRY_DSN": "https://%s@o123456.ingest.sentry.io/789",
  "GOOGLE_CLIENT_SECRET": "GOCSPX-%s",
  "TWILIO_AUTH_TOKEN": "%s",
  "ELASTICSEARCH_URL": "http://elastic:3l4st1c_p4ss@es.internal:9200",
  "KAFKA_BROKER_URL": "kafka.internal:9092",
  "KAFKA_SASL_PASSWORD": "k4fk4_%s",
  "ENCRYPTION_KEY": "%s",
  "ADMIN_PASSWORD": "admin123!",
  "DEBUG": "true",
  "LOG_LEVEL": "trace",
  "ENABLE_PROFILING": "true",
  "CORS_ORIGIN": "*"
}`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 24),
		h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 22), h.randomHex(rng, 40),
		h.randomHex(rng, 36),
		h.randomHex(rng, 9), h.randomHex(rng, 9), h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 16),
		h.randomHex(rng, 32),
	)
	return h.dashJSON(w, "information-disclosure", envJSON)
}

func (h *Handler) serveDashDebugRoutes(w http.ResponseWriter, r *http.Request) int {
	routesJSON := `{
  "routes": [
    {"method": "GET",  "path": "/", "handler": "controllers.HomeController#index", "middleware": ["cors"]},
    {"method": "POST", "path": "/api/v1/auth/login", "handler": "controllers.AuthController#login", "middleware": ["cors","rate-limit"]},
    {"method": "POST", "path": "/api/v1/auth/register", "handler": "controllers.AuthController#register", "middleware": ["cors"]},
    {"method": "GET",  "path": "/api/v1/users", "handler": "controllers.UserController#list", "middleware": ["cors","auth"]},
    {"method": "GET",  "path": "/api/v1/users/:id", "handler": "controllers.UserController#show", "middleware": ["cors","auth"]},
    {"method": "PUT",  "path": "/api/v1/users/:id", "handler": "controllers.UserController#update", "middleware": ["cors","auth"]},
    {"method": "DELETE","path": "/api/v1/users/:id", "handler": "controllers.UserController#destroy", "middleware": ["cors","auth"]},
    {"method": "GET",  "path": "/api/v1/admin/users", "handler": "controllers.AdminController#users", "middleware": ["cors"]},
    {"method": "GET",  "path": "/api/v1/admin/settings", "handler": "controllers.AdminController#settings", "middleware": ["cors"]},
    {"method": "POST", "path": "/api/v1/admin/settings", "handler": "controllers.AdminController#updateSettings", "middleware": ["cors"]},
    {"method": "GET",  "path": "/api/v1/admin/backup", "handler": "controllers.AdminController#backup", "middleware": ["cors"]},
    {"method": "GET",  "path": "/api/internal/health", "handler": "controllers.HealthController#check", "middleware": []},
    {"method": "GET",  "path": "/api/internal/metrics", "handler": "controllers.MetricsController#prometheus", "middleware": []},
    {"method": "GET",  "path": "/api/internal/debug/pprof", "handler": "net/http/pprof.Index", "middleware": []},
    {"method": "GET",  "path": "/api/internal/debug/vars", "handler": "expvar.Handler", "middleware": []},
    {"method": "POST", "path": "/api/v1/payments/charge", "handler": "controllers.PaymentController#charge", "middleware": ["cors","auth"]},
    {"method": "POST", "path": "/api/v1/payments/refund", "handler": "controllers.PaymentController#refund", "middleware": ["cors","auth"]},
    {"method": "GET",  "path": "/api/v1/export/users", "handler": "controllers.ExportController#users", "middleware": ["cors"]},
    {"method": "GET",  "path": "/api/v1/export/orders", "handler": "controllers.ExportController#orders", "middleware": ["cors"]},
    {"method": "POST", "path": "/webhooks/stripe", "handler": "controllers.WebhookController#stripe", "middleware": []},
    {"method": "POST", "path": "/webhooks/github", "handler": "controllers.WebhookController#github", "middleware": []}
  ],
  "note": "Routes marked without 'auth' middleware are publicly accessible"
}`
	return h.dashJSON(w, "information-disclosure", routesJSON)
}

func (h *Handler) serveDashDebugSQL(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/debug/sql")
	var queries []string
	qTemplates := []struct {
		sql    string
		timeMs int
	}{
		{"SELECT id, email, password_hash, role, api_key FROM users WHERE email = 'admin@acmecorp.com'", 2},
		{"SELECT * FROM sessions WHERE token = 'sess_%s' AND expires_at > NOW()", 1},
		{"UPDATE users SET last_login = NOW(), login_count = login_count + 1 WHERE id = %d", 3},
		{"SELECT id, card_number, cvv, exp_date, billing_address FROM payment_methods WHERE user_id = %d", 5},
		{"SELECT * FROM orders JOIN users ON orders.user_id = users.id WHERE orders.total > 1000 ORDER BY created_at DESC LIMIT 50", 45},
		{"INSERT INTO audit_log (user_id, action, ip_address, request_body) VALUES (%d, 'settings.update', '10.0.1.5', '{\"password_policy\":\"none\"}')", 2},
		{"SELECT api_key, secret, permissions FROM api_keys WHERE revoked = false", 8},
		{"SELECT * FROM feature_flags WHERE environment = 'production'", 1},
		{"DELETE FROM sessions WHERE user_id = %d AND created_at < NOW() - INTERVAL '90 days'", 12},
		{"SELECT u.email, u.password_hash, r.name as role FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name IN ('admin', 'superadmin')", 6},
	}
	for _, q := range qTemplates {
		sql := q.sql
		if strings.Contains(sql, "'sess_") {
			sql = fmt.Sprintf(sql, h.randomHex(rng, 32))
		} else if strings.Contains(sql, "%d") {
			sql = fmt.Sprintf(sql, rng.Intn(9000)+1000)
		}
		queries = append(queries, fmt.Sprintf(`    {"query": %q, "duration_ms": %d, "rows_affected": %d, "timestamp": "%s"}`,
			sql, q.timeMs+rng.Intn(10), rng.Intn(100)+1, h.randomRecentDate(rng)))
	}
	json := "{\n  \"recent_queries\": [\n" + strings.Join(queries, ",\n") + "\n  ]\n}"
	return h.dashJSON(w, "information-disclosure", json)
}

func (h *Handler) serveDashDebugSessions(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/debug/sessions")
	var sessions []string
	for i := 0; i < 12; i++ {
		sessions = append(sessions, fmt.Sprintf(`    {
      "session_id": "sess_%s",
      "user_id": %d,
      "email": "%s",
      "role": "%s",
      "ip": "%s",
      "user_agent": "%s",
      "token": "eyJhbGciOiJIUzI1NiJ9.%s.%s",
      "csrf_token": "%s",
      "created_at": "%s",
      "last_active": "%s"
    }`,
			h.randomHex(rng, 32),
			rng.Intn(9000)+1000,
			h.randomEmail(rng),
			[]string{"user", "admin", "superadmin", "moderator"}[rng.Intn(4)],
			h.randomIP(rng),
			fakeUserAgent(rng),
			h.randomHex(rng, 40), h.randomHex(rng, 28),
			h.randomHex(rng, 32),
			h.randomDate(rng),
			h.randomRecentDate(rng),
		))
	}
	json := "{\n  \"active_sessions\": [\n" + strings.Join(sessions, ",\n") + "\n  ],\n  \"total\": 12\n}"
	return h.dashJSON(w, "information-disclosure", json)
}

func (h *Handler) serveDashDebugCache(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/debug/cache")
	json := fmt.Sprintf(`{
  "cache_stats": {
    "hits": %d,
    "misses": %d,
    "size_mb": %.1f,
    "max_size_mb": 512
  },
  "entries": [
    {
      "key": "user:1001:profile",
      "ttl": 3600,
      "value": {"id": 1001, "email": "admin@acmecorp.com", "role": "superadmin", "api_key": "sk_live_%s"}
    },
    {
      "key": "api:stripe:customer:cus_%s",
      "ttl": 1800,
      "value": {"customer_id": "cus_%s", "email": "billing@acmecorp.com", "payment_method": "pm_%s", "card_last4": "4242"}
    },
    {
      "key": "oauth:token:github",
      "ttl": 7200,
      "value": {"access_token": "gho_%s", "refresh_token": "ghr_%s", "scope": "repo,admin:org"}
    },
    {
      "key": "api:response:/api/v1/admin/users",
      "ttl": 300,
      "value": {"cached_at": "%s", "auth_header": "Bearer eyJhbGciOiJIUzI1NiJ9.%s.%s"}
    },
    {
      "key": "session:admin:csrf",
      "ttl": 86400,
      "value": {"csrf_token": "%s", "session_id": "sess_%s"}
    }
  ]
}`,
		rng.Intn(900000)+100000,
		rng.Intn(90000)+10000,
		float64(rng.Intn(4000)+1000)/10.0,
		h.randomHex(rng, 24),
		h.randomHex(rng, 14), h.randomHex(rng, 14), h.randomHex(rng, 24),
		h.randomHex(rng, 36), h.randomHex(rng, 36),
		h.randomRecentDate(rng), h.randomHex(rng, 40), h.randomHex(rng, 28),
		h.randomHex(rng, 32), h.randomHex(rng, 32),
	)
	return h.dashJSON(w, "information-disclosure", json)
}

func (h *Handler) serveDashPHPInfo(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Glitch-Vuln-Type", "information-disclosure")
	w.WriteHeader(http.StatusOK)
	// Full phpinfo()-style page
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>phpinfo()</title>
<style>
body { background: #fff; color: #000; font-family: sans-serif; }
h1 { font-size: 150%; background: #9999cc; padding: 10px; }
h2 { font-size: 120%; background: #9999cc; padding: 5px; }
table { border-collapse: collapse; width: 600px; margin: 10px auto; }
td, th { border: 1px solid #666; padding: 4px 8px; font-size: 13px; }
.e { background: #ccccff; font-weight: bold; }
.v { background: #ddd; max-width: 300px; word-break: break-all; }
.h { background: #9999cc; }
hr { width: 600px; }
</style></head><body>
<h1>PHP Version 5.6.40</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux prod-web-01 5.4.0-167-generic #184-Ubuntu SMP x86_64</td></tr>
<tr><td class="e">Build Date</td><td class="v">Jan 20 2019 06:28:13</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/5.6/apache2/php.ini</td></tr>
<tr><td class="e">Document Root</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">Server Admin</td><td class="v">admin@acmecorp.com</td></tr>
<tr><td class="e">DOCUMENT_ROOT</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">SCRIPT_FILENAME</td><td class="v">/var/www/html/info.php</td></tr>
<tr><td class="e">REMOTE_PORT</td><td class="v">54321</td></tr>
<tr><td class="e">SERVER_NAME</td><td class="v">prod-web-01.internal.acmecorp.net</td></tr>
<tr><td class="e">SERVER_PORT</td><td class="v">443</td></tr>
<tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.29 (Ubuntu)</td></tr>
</table>
<h2>Environment</h2>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">PATH</td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin</td></tr>
<tr><td class="e">HOSTNAME</td><td class="v">prod-web-01</td></tr>
<tr><td class="e">DATABASE_URL</td><td class="v">postgresql://admin:SuperSecretP4ss!@db-master.internal:5432/production</td></tr>
<tr><td class="e">REDIS_URL</td><td class="v">redis://:r3d1s_s3cret@redis.internal:6379/0</td></tr>
<tr><td class="e">AWS_ACCESS_KEY_ID</td><td class="v">AKIAIOSFODNN7EXAMPLE</td></tr>
<tr><td class="e">AWS_SECRET_ACCESS_KEY</td><td class="v">wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>
<tr><td class="e">JWT_SECRET</td><td class="v">super-secret-jwt-key-do-not-share-2024</td></tr>
<tr><td class="e">API_KEY</td><td class="v">sk_live_51234567890abcdefghijk</td></tr>
<tr><td class="e">ADMIN_PASSWORD</td><td class="v">admin123!</td></tr>
<tr><td class="e">DEBUG</td><td class="v">true</td></tr>
</table>
<h2>PHP Core</h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">On</td><td class="v">Off</td></tr>
<tr><td class="e">display_errors</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">display_startup_errors</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">expose_php</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">file_uploads</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">100M</td><td class="v">2M</td></tr>
<tr><td class="e">max_execution_time</td><td class="v">0</td><td class="v">30</td></tr>
<tr><td class="e">open_basedir</td><td class="v">no value</td><td class="v">no value</td></tr>
<tr><td class="e">disable_functions</td><td class="v">no value</td><td class="v">no value</td></tr>
<tr><td class="e">safe_mode</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">register_globals</td><td class="v">On</td><td class="v">Off</td></tr>
</table>
<h2>mysql</h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">mysql.default_host</td><td class="v">db-master.internal</td><td class="v">no value</td></tr>
<tr><td class="e">mysql.default_password</td><td class="v">SuperSecretP4ss!</td><td class="v">no value</td></tr>
<tr><td class="e">mysql.default_port</td><td class="v">3306</td><td class="v">no value</td></tr>
<tr><td class="e">mysql.default_user</td><td class="v">admin</td><td class="v">no value</td></tr>
</table>
<h2>session</h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">session.cookie_httponly</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.cookie_secure</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.use_strict_mode</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.use_only_cookies</td><td class="v">0</td><td class="v">0</td></tr>
</table>
</body></html>`)
	return http.StatusOK
}

func (h *Handler) serveDashServerStatus(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/server-status")

	var rows strings.Builder
	for i := 0; i < 15; i++ {
		method := []string{"GET", "POST", "GET", "GET", "PUT"}[rng.Intn(5)]
		paths := []string{
			"/api/v1/users", "/api/v1/admin/settings", "/api/internal/metrics",
			"/api/v1/payments/charge", "/api/v1/auth/login", "/webhooks/stripe",
			"/api/v1/export/users", "/", "/api/v1/orders",
		}
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%d-%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s %s HTTP/1.1</td>
</tr>
`, rng.Intn(10), rng.Intn(99999), rng.Intn(50000)+1000, h.randomIP(rng),
			[]string{"Reading", "Writing", "Waiting", "Keepalive"}[rng.Intn(4)],
			method, paths[rng.Intn(len(paths))]))
	}

	body := fmt.Sprintf(`
<h2>Apache Server Status</h2>
<div class="card">
<p><strong>Server Version:</strong> Apache/2.4.29 (Ubuntu) OpenSSL/1.0.2g PHP/5.6.40</p>
<p><strong>Server MPM:</strong> prefork</p>
<p><strong>Server Built:</strong> 2019-04-03T13:22:37</p>
<p><strong>Current Time:</strong> %s</p>
<p><strong>Restart Time:</strong> 2023-03-15 08:00:00</p>
<p><strong>Server uptime:</strong> 847 days 14 hours 22 minutes 36 seconds</p>
<p><strong>Total accesses:</strong> %d - Total Traffic: %d GB</p>
<p><strong>CPU Usage:</strong> u%.2f s%.2f cu0 cs0</p>
<p><strong>%d requests/sec - %.1f kB/request</strong></p>
<p><strong>%d requests currently being processed, %d idle workers</strong></p>
</div>

<h2>Active Connections</h2>
<table>
<tr><th>Srv-Child</th><th>PID</th><th>Client IP</th><th>State</th><th>Request</th></tr>
%s
</table>

<h2>Scoreboard</h2>
<pre>WWWWWW_KKK_RRRRR__WWWW_KK_RR_W_K_R____WWWW__K_RR_WW___KK__RR</pre>
<p>Key: W=Writing R=Reading K=Keepalive _=Waiting</p>`,
		h.randomRecentDate(rng),
		rng.Intn(90000000)+10000000, rng.Intn(5000)+500,
		float64(rng.Intn(400))/100.0, float64(rng.Intn(200))/100.0,
		rng.Intn(1000)+100, float64(rng.Intn(500)+100)/10.0,
		rng.Intn(50)+5, rng.Intn(200)+50,
		rows.String(),
	)
	return h.dashHTML(w, "/vuln/dashboard/server-status", "Server Status", "information-disclosure", body)
}

// ===========================================================================
// 3. Insecure API Keys Management
// ===========================================================================

func (h *Handler) serveDashAPIKeys(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/api-keys")
	var rows strings.Builder
	keys := []struct {
		name  string
		perms string
	}{
		{"Production API Key", "read, write, admin"},
		{"Staging API Key", "read, write"},
		{"CI/CD Deploy Key", "deploy, read"},
		{"Monitoring Service", "read, metrics"},
		{"Partner Integration", "read, write"},
		{"Mobile App Key", "read, write, push"},
		{"Backup Service", "read, export, backup"},
		{"Analytics Pipeline", "read, analytics"},
	}
	for _, k := range keys {
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%s</td>
<td><code>sk_live_%s</code></td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td><span class="tag tag-green">Active</span></td>
</tr>
`, k.name, h.randomHex(rng, 32), k.perms, h.randomDate(rng), h.randomRecentDate(rng)))
	}

	body := fmt.Sprintf(`
<div class="warn">API keys are displayed in plaintext. Rotate immediately if compromised.</div>
<table>
<tr><th>Name</th><th>Key</th><th>Permissions</th><th>Created</th><th>Last Used</th><th>Status</th></tr>
%s
</table>
<p><a href="/vuln/dashboard/api-keys/create">Create New Key</a> | <a href="/vuln/dashboard/api-keys/rotate">Rotate All Keys</a></p>`, rows.String())
	return h.dashHTML(w, "/vuln/dashboard/api-keys", "API Key Management", "insecure-api-keys", body)
}

func (h *Handler) serveDashAPIKeysCreate(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/api-keys/create")
	newKey := fmt.Sprintf("sk_live_%s", h.randomHex(rng, 32))
	newSecret := h.randomHex(rng, 64)
	json := fmt.Sprintf(`{
  "status": "created",
  "api_key": {
    "id": "key_%s",
    "key": "%s",
    "secret": "%s",
    "permissions": ["read", "write", "admin"],
    "created_at": "%s",
    "created_by": "admin",
    "note": "Store this secret securely. It will not be shown again."
  }
}`, h.randomHex(rng, 12), newKey, newSecret, h.randomRecentDate(rng))
	return h.dashJSON(w, "insecure-api-keys", json)
}

func (h *Handler) serveDashAPIKeysRotate(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/api-keys/rotate")
	var keys []string
	names := []string{"Production API Key", "Staging API Key", "CI/CD Deploy Key", "Monitoring Service", "Partner Integration"}
	for _, name := range names {
		keys = append(keys, fmt.Sprintf(`    {
      "name": %q,
      "old_key": "sk_live_%s",
      "new_key": "sk_live_%s",
      "new_secret": "%s",
      "rotated_at": "%s"
    }`, name, h.randomHex(rng, 32), h.randomHex(rng, 32), h.randomHex(rng, 64), h.randomRecentDate(rng)))
	}
	json := "{\n  \"status\": \"rotated\",\n  \"keys\": [\n" + strings.Join(keys, ",\n") + "\n  ]\n}"
	return h.dashJSON(w, "insecure-api-keys", json)
}

// ===========================================================================
// 4. User Management Without Auth
// ===========================================================================

func (h *Handler) serveDashUsers(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/users")
	var rows strings.Builder
	for i := 0; i < 20; i++ {
		name := h.randomName(rng)
		email := h.randomEmail(rng)
		role := []string{"user", "user", "admin", "moderator", "editor", "superadmin"}[rng.Intn(6)]
		twoFA := []string{"Disabled", "Disabled", "Enabled", "Disabled"}[rng.Intn(4)]
		hint := []string{"pet name", "birthday year", "favorite color", "mother maiden name", "first car", "street name"}[rng.Intn(6)]
		tagClass := "tag-green"
		if twoFA == "Disabled" {
			tagClass = "tag-red"
		}
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%d</td><td>%s</td><td>%s</td><td><span class="tag tag-blue">%s</span></td>
<td>%s</td><td><span class="tag %s">%s</span></td><td>%s</td>
</tr>
`, rng.Intn(9000)+1000, name, email, role, h.randomDate(rng), tagClass, twoFA, hint))
	}

	body := fmt.Sprintf(`
<div class="warn">User management accessible without authentication. No RBAC enforced.</div>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Last Login</th><th>2FA</th><th>Password Hint</th></tr>
%s
</table>
<p><a href="/vuln/dashboard/users/export">Export All Users (CSV)</a> | <a href="/vuln/dashboard/users/invite">Invite New User</a></p>`, rows.String())
	return h.dashHTML(w, "/vuln/dashboard/users", "User Management", "broken-access-control", body)
}

func (h *Handler) serveDashUsersExport(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/users/export")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=users_export.csv")
	w.Header().Set("X-Glitch-Vuln-Type", "broken-access-control")
	w.WriteHeader(http.StatusOK)

	var sb strings.Builder
	sb.WriteString("id,name,email,role,password_hash,2fa_enabled,last_login,password_hint,api_key\n")
	for i := 0; i < 25; i++ {
		name := h.randomName(rng)
		email := h.randomEmail(rng)
		role := []string{"user", "admin", "moderator", "editor", "superadmin"}[rng.Intn(5)]
		sb.WriteString(fmt.Sprintf("%d,%s,%s,%s,$2a$10$%s,%v,%s,%s,sk_%s\n",
			rng.Intn(9000)+1000, name, email, role,
			h.randomHex(rng, 44),
			rng.Intn(2) == 1,
			h.randomDate(rng),
			[]string{"pet name", "birthday", "fav color"}[rng.Intn(3)],
			h.randomHex(rng, 24),
		))
	}
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveDashUsersInvite(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/users/invite")
	email := r.FormValue("email")
	role := r.FormValue("role")
	if email == "" {
		email = h.randomEmail(rng)
	}
	if role == "" {
		role = "admin"
	}
	json := fmt.Sprintf(`{
  "status": "invited",
  "invitation": {
    "email": %q,
    "role": %q,
    "invite_token": "%s",
    "invite_url": "https://app.acmecorp.com/invite?token=%s",
    "expires_at": "%s",
    "invited_by": "admin (unauthenticated)"
  }
}`, email, role, h.randomHex(rng, 32), h.randomHex(rng, 32), h.randomDate(rng))
	return h.dashJSON(w, "broken-access-control", json)
}

// ===========================================================================
// 5. Backup & Data Export
// ===========================================================================

func (h *Handler) serveDashBackupDownload(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/backup/download")
	w.Header().Set("Content-Type", "application/sql")
	w.Header().Set("Content-Disposition", "attachment; filename=backup_production.sql")
	w.Header().Set("X-Glitch-Vuln-Type", "data-exposure")
	w.WriteHeader(http.StatusOK)

	var sb strings.Builder
	sb.WriteString("-- PostgreSQL database dump\n")
	sb.WriteString("-- Host: db-master.internal:5432\n")
	sb.WriteString("-- Database: production\n")
	sb.WriteString(fmt.Sprintf("-- Dump date: %s\n\n", h.randomRecentDate(rng)))
	sb.WriteString("SET statement_timeout = 0;\nSET lock_timeout = 0;\nSET client_encoding = 'UTF8';\n\n")

	sb.WriteString("CREATE TABLE users (\n")
	sb.WriteString("  id SERIAL PRIMARY KEY,\n  email VARCHAR(255) NOT NULL UNIQUE,\n")
	sb.WriteString("  password_hash VARCHAR(255) NOT NULL,\n  role VARCHAR(50) DEFAULT 'user',\n")
	sb.WriteString("  api_key VARCHAR(255),\n  ssn VARCHAR(20),\n  created_at TIMESTAMP DEFAULT NOW()\n);\n\n")

	for i := 0; i < 10; i++ {
		name := h.randomName(rng)
		email := h.randomEmail(rng)
		role := []string{"user", "admin", "superadmin"}[rng.Intn(3)]
		sb.WriteString(fmt.Sprintf("INSERT INTO users (id, email, password_hash, role, api_key, ssn) VALUES (%d, '%s', '$2a$10$%s', '%s', 'sk_%s', '%03d-%02d-%04d');\n",
			rng.Intn(9000)+1000, email, h.randomHex(rng, 44), role,
			h.randomHex(rng, 24),
			rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000))
		_ = name // name used implicitly via randomEmail consuming rng state
	}

	sb.WriteString("\nCREATE TABLE payment_methods (\n  id SERIAL PRIMARY KEY,\n  user_id INTEGER REFERENCES users(id),\n")
	sb.WriteString("  card_number VARCHAR(20),\n  cvv VARCHAR(4),\n  exp_date VARCHAR(7),\n  billing_zip VARCHAR(10)\n);\n\n")

	for i := 0; i < 5; i++ {
		sb.WriteString(fmt.Sprintf("INSERT INTO payment_methods (user_id, card_number, cvv, exp_date, billing_zip) VALUES (%d, '%04d-%04d-%04d-%04d', '%03d', '%02d/%02d', '%05d');\n",
			rng.Intn(9000)+1000,
			rng.Intn(9000)+1000, rng.Intn(10000), rng.Intn(10000), rng.Intn(10000),
			rng.Intn(1000),
			rng.Intn(12)+1, rng.Intn(5)+25,
			rng.Intn(90000)+10000))
	}

	sb.WriteString("\n-- End of dump\n")
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveDashBackupConfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/backup/config")
	json := fmt.Sprintf(`{
  "backup_config": {
    "enabled": true,
    "schedule": "0 2 * * *",
    "retention_days": 30,
    "storage": {
      "provider": "s3",
      "bucket": "acmecorp-prod-backups",
      "region": "us-east-1",
      "access_key_id": "AKIA%s",
      "secret_access_key": "%s",
      "encryption": false,
      "path_prefix": "db-backups/"
    },
    "database": {
      "host": "db-master.internal",
      "port": 5432,
      "username": "backup_user",
      "password": "B4ckup_S3cret!2024",
      "database": "production",
      "ssl_mode": "disable"
    },
    "notifications": {
      "email": "ops@acmecorp.com",
      "slack_webhook": "https://hooks.slack.com/services/T%s/B%s/%s"
    },
    "last_backup": "%s",
    "last_backup_size_mb": %d,
    "status": "healthy"
  }
}`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 9), h.randomHex(rng, 9), h.randomHex(rng, 24),
		h.randomRecentDate(rng),
		rng.Intn(5000)+500,
	)
	return h.dashJSON(w, "data-exposure", json)
}

func (h *Handler) serveDashExportUsers(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/dashboard/export/users")
	var users []string
	for i := 0; i < 15; i++ {
		name := h.randomName(rng)
		email := h.randomEmail(rng)
		role := []string{"user", "admin", "moderator", "superadmin"}[rng.Intn(4)]
		users = append(users, fmt.Sprintf(`    {
      "id": %d,
      "name": %q,
      "email": %q,
      "role": %q,
      "password_hash": "$2a$10$%s",
      "api_key": "sk_%s",
      "ssn": "%03d-%02d-%04d",
      "phone": "+1-%03d-%03d-%04d",
      "address": "%d Oak Street, Anytown, ST %05d",
      "last_login": "%s",
      "2fa_enabled": %v
    }`,
			rng.Intn(9000)+1000, name, email, role,
			h.randomHex(rng, 44),
			h.randomHex(rng, 24),
			rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000,
			rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(9000)+1000,
			rng.Intn(9000)+100, rng.Intn(90000)+10000,
			h.randomDate(rng),
			rng.Intn(2) == 1,
		))
	}
	json := "{\n  \"users\": [\n" + strings.Join(users, ",\n") + "\n  ],\n  \"total\": 15,\n  \"exported_at\": \"" + h.randomRecentDate(rng) + "\"\n}"
	return h.dashJSON(w, "data-exposure", json)
}

// ===========================================================================
// 6. Insecure Configuration (Settings pages)
// ===========================================================================

func (h *Handler) serveSettingsHome(w http.ResponseWriter, r *http.Request) int {
	body := `
<div class="warn">All settings are editable without authentication. No CSRF protection.</div>
<h2>Configuration Sections</h2>
<div class="card">
<ul style="list-style:none;padding:0;line-height:2.2;">
  <li><a href="/vuln/settings/general">General Settings</a> - Site URL, admin email, timezone</li>
  <li><a href="/vuln/settings/security">Security Settings</a> - Authentication, password policy, CORS</li>
  <li><a href="/vuln/settings/database">Database Settings</a> - Connection strings, credentials</li>
  <li><a href="/vuln/settings/email">Email / SMTP Settings</a> - Mail server credentials</li>
  <li><a href="/vuln/settings/storage">Cloud Storage</a> - S3, GCS credentials and buckets</li>
  <li><a href="/vuln/settings/integrations">Integrations</a> - OAuth, webhooks, third-party APIs</li>
  <li><a href="/vuln/settings/update">Update Config</a> - POST to modify any setting</li>
  <li><a href="/vuln/settings/import">Import Config</a> - Import config file</li>
  <li><a href="/vuln/settings/webhook">Webhook Settings</a> - Configure webhook endpoints</li>
</ul>
</div>`
	return h.dashHTML(w, "/vuln/settings/", "Settings", "security-misconfiguration", body)
}

func (h *Handler) serveSettingsGeneral(w http.ResponseWriter, r *http.Request) int {
	body := `
<h2>General Settings</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Site Name</td><td>AcmeCorp Platform</td></tr>
  <tr><td>Site URL</td><td>https://app.acmecorp.com</td></tr>
  <tr><td>Admin Email</td><td>admin@acmecorp.com</td></tr>
  <tr><td>Support Email</td><td>support@acmecorp.com</td></tr>
  <tr><td>Default Timezone</td><td>America/New_York</td></tr>
  <tr><td>Default Language</td><td>en-US</td></tr>
  <tr><td>Maintenance Mode</td><td><span class="tag tag-red">Disabled</span></td></tr>
  <tr><td>User Registration</td><td><span class="tag tag-green">Open</span></td></tr>
  <tr><td>Max Upload Size</td><td>100 MB</td></tr>
  <tr><td>API Rate Limit</td><td>Unlimited</td></tr>
  <tr><td>Debug Mode</td><td><span class="tag tag-red">Enabled</span></td></tr>
  <tr><td>Error Reporting</td><td>E_ALL (verbose)</td></tr>
</table>
</div>
<p style="color:#8b949e;font-size:12px;">All settings can be modified via POST to <code>/vuln/settings/update</code> without authentication.</p>`
	return h.dashHTML(w, "/vuln/settings/general", "General Settings", "security-misconfiguration", body)
}

func (h *Handler) serveSettingsSecurity(w http.ResponseWriter, r *http.Request) int {
	body := `
<h2>Security Configuration</h2>
<div class="warn">Multiple critical security settings are disabled or weakened.</div>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th><th>Recommended</th><th>Status</th></tr>
  <tr><td>Two-Factor Authentication</td><td>Disabled</td><td>Required</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Password Policy</td><td>weak (min 4 chars)</td><td>strong (12+ chars, mixed)</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Session Timeout</td><td>0 (infinite)</td><td>900 seconds</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>CORS Policy</td><td>Allow All Origins (*)</td><td>Specific origins only</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Content Security Policy</td><td>Disabled</td><td>Strict</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Rate Limiting</td><td>Disabled</td><td>100 req/min</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>CSRF Protection</td><td>Disabled</td><td>Enabled</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Secure Cookies</td><td>Disabled</td><td>Enabled</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>HSTS</td><td>Disabled</td><td>Enabled (max-age: 31536000)</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>X-Frame-Options</td><td>Not Set</td><td>DENY</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>X-Content-Type-Options</td><td>Not Set</td><td>nosniff</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Login Brute-Force Protection</td><td>Disabled</td><td>Lock after 5 attempts</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>Password Hashing</td><td>MD5</td><td>bcrypt/argon2</td><td><span class="tag tag-red">INSECURE</span></td></tr>
  <tr><td>API Authentication</td><td>None required</td><td>OAuth 2.0 / JWT</td><td><span class="tag tag-red">INSECURE</span></td></tr>
</table>
</div>`
	return h.dashHTML(w, "/vuln/settings/security", "Security Settings", "security-misconfiguration", body)
}

func (h *Handler) serveSettingsDatabase(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/database")
	body := fmt.Sprintf(`
<h2>Database Connection Settings</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Host</td><td>db-master.internal</td></tr>
  <tr><td>Port</td><td>5432</td></tr>
  <tr><td>Database</td><td>production</td></tr>
  <tr><td>Username</td><td>admin</td></tr>
  <tr><td>Password</td><td><code>SuperSecretP4ss!</code></td></tr>
  <tr><td>SSL Mode</td><td>disable</td></tr>
  <tr><td>Connection Pool Size</td><td>50</td></tr>
  <tr><td>Connection String</td><td><code>postgresql://admin:SuperSecretP4ss!@db-master.internal:5432/production?sslmode=disable</code></td></tr>
</table>
</div>

<h2>Read Replica</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Host</td><td>db-replica.internal</td></tr>
  <tr><td>Port</td><td>5432</td></tr>
  <tr><td>Username</td><td>readonly</td></tr>
  <tr><td>Password</td><td><code>R3adOnly!2024</code></td></tr>
  <tr><td>Connection String</td><td><code>postgresql://readonly:R3adOnly!2024@db-replica.internal:5432/production</code></td></tr>
</table>
</div>

<h2>Redis Cache</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Host</td><td>redis.internal</td></tr>
  <tr><td>Port</td><td>6379</td></tr>
  <tr><td>Password</td><td><code>r3d1s_s3cret_%s</code></td></tr>
  <tr><td>Database</td><td>0</td></tr>
  <tr><td>Connection String</td><td><code>redis://:r3d1s_s3cret_%s@redis.internal:6379/0</code></td></tr>
</table>
</div>`, h.randomHex(rng, 8), h.randomHex(rng, 8))
	return h.dashHTML(w, "/vuln/settings/database", "Database Settings", "credential-exposure", body)
}

func (h *Handler) serveSettingsEmail(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/email")
	body := fmt.Sprintf(`
<h2>SMTP Settings</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>SMTP Host</td><td>smtp.sendgrid.net</td></tr>
  <tr><td>SMTP Port</td><td>587</td></tr>
  <tr><td>SMTP Username</td><td>apikey</td></tr>
  <tr><td>SMTP Password</td><td><code>SG.%s.%s</code></td></tr>
  <tr><td>From Address</td><td>noreply@acmecorp.com</td></tr>
  <tr><td>From Name</td><td>AcmeCorp</td></tr>
  <tr><td>Encryption</td><td>STARTTLS</td></tr>
</table>
</div>

<h2>Transactional Email API</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Provider</td><td>SendGrid</td></tr>
  <tr><td>API Key</td><td><code>SG.%s.%s</code></td></tr>
  <tr><td>Webhook Signing Key</td><td><code>whk_%s</code></td></tr>
</table>
</div>

<h2>Mailgun (Backup)</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Domain</td><td>mg.acmecorp.com</td></tr>
  <tr><td>API Key</td><td><code>key-%s</code></td></tr>
  <tr><td>SMTP Password</td><td><code>%s</code></td></tr>
</table>
</div>`,
		h.randomHex(rng, 22), h.randomHex(rng, 40),
		h.randomHex(rng, 22), h.randomHex(rng, 40),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
	)
	return h.dashHTML(w, "/vuln/settings/email", "Email / SMTP Settings", "credential-exposure", body)
}

func (h *Handler) serveSettingsStorage(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/storage")
	body := fmt.Sprintf(`
<h2>AWS S3</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Bucket</td><td>acmecorp-prod-assets</td></tr>
  <tr><td>Region</td><td>us-east-1</td></tr>
  <tr><td>Access Key ID</td><td><code>AKIA%s</code></td></tr>
  <tr><td>Secret Access Key</td><td><code>%s</code></td></tr>
  <tr><td>CDN URL</td><td>https://cdn.acmecorp.com</td></tr>
  <tr><td>Public Access</td><td><span class="tag tag-red">Enabled</span></td></tr>
</table>
</div>

<h2>Google Cloud Storage</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Bucket</td><td>acmecorp-analytics-data</td></tr>
  <tr><td>Project ID</td><td>acmecorp-prod-12345</td></tr>
  <tr><td>Service Account Key</td><td><pre>{
  "type": "service_account",
  "project_id": "acmecorp-prod-12345",
  "private_key_id": "%s",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA%s...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "storage@acmecorp-prod-12345.iam.gserviceaccount.com",
  "client_id": "%d"
}</pre></td></tr>
</table>
</div>

<h2>Backblaze B2 (Archives)</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Bucket</td><td>acmecorp-archives</td></tr>
  <tr><td>Key ID</td><td><code>%s</code></td></tr>
  <tr><td>Application Key</td><td><code>%s</code></td></tr>
</table>
</div>`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 24),
		h.randomHex(rng, 40),
		rng.Int63n(900000000000)+100000000000,
		h.randomHex(rng, 12),
		h.randomHex(rng, 31),
	)
	return h.dashHTML(w, "/vuln/settings/storage", "Cloud Storage Settings", "credential-exposure", body)
}

func (h *Handler) serveSettingsIntegrations(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/integrations")
	body := fmt.Sprintf(`
<h2>GitHub OAuth</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Client ID</td><td><code>Iv1.%s</code></td></tr>
  <tr><td>Client Secret</td><td><code>%s</code></td></tr>
  <tr><td>Callback URL</td><td>https://app.acmecorp.com/auth/github/callback</td></tr>
</table>
</div>

<h2>Stripe</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Publishable Key</td><td><code>pk_live_%s</code></td></tr>
  <tr><td>Secret Key</td><td><code>sk_live_%s</code></td></tr>
  <tr><td>Webhook Secret</td><td><code>whsec_%s</code></td></tr>
</table>
</div>

<h2>Slack</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Bot Token</td><td><code>xoxb-%s</code></td></tr>
  <tr><td>Signing Secret</td><td><code>%s</code></td></tr>
  <tr><td>Webhook URL</td><td><code>https://hooks.slack.com/services/T%s/B%s/%s</code></td></tr>
</table>
</div>

<h2>Twilio</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Account SID</td><td><code>AC%s</code></td></tr>
  <tr><td>Auth Token</td><td><code>%s</code></td></tr>
  <tr><td>From Number</td><td>+1-555-0100</td></tr>
</table>
</div>

<h2>Datadog</h2>
<div class="card">
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>API Key</td><td><code>%s</code></td></tr>
  <tr><td>App Key</td><td><code>%s</code></td></tr>
</table>
</div>`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 24),
		h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 9), h.randomHex(rng, 9), h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 40),
	)
	return h.dashHTML(w, "/vuln/settings/integrations", "Integration Settings", "credential-exposure", body)
}

// ===========================================================================
// 7. Configuration Injection
// ===========================================================================

func (h *Handler) serveSettingsUpdate(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/update")
	json := fmt.Sprintf(`{
  "status": "updated",
  "message": "Configuration updated successfully. No validation performed.",
  "merged_config": {
    "site_name": "AcmeCorp Platform",
    "debug": true,
    "admin_email": "admin@acmecorp.com",
    "database_url": "postgresql://admin:SuperSecretP4ss!@db-master.internal:5432/production",
    "jwt_secret": "%s",
    "cors_origin": "*",
    "rate_limit_enabled": false,
    "csrf_protection": false,
    "password_policy": "none",
    "session_timeout": 0,
    "admin_role": "superadmin",
    "api_key": "sk_live_%s",
    "stripe_secret": "sk_live_%s"
  },
  "warning": "Mass assignment: all submitted fields were merged without filtering"
}`,
		h.randomHex(rng, 64),
		h.randomHex(rng, 24),
		h.randomHex(rng, 24),
	)
	return h.dashJSON(w, "mass-assignment", json)
}

func (h *Handler) serveSettingsImport(w http.ResponseWriter, r *http.Request) int {
	json := `{
  "status": "ready",
  "message": "POST a JSON or YAML configuration file to import. No validation is performed on the input.",
  "accepted_formats": ["json", "yaml", "toml", "ini"],
  "warning": "Imported configuration will overwrite existing values without confirmation.",
  "example": {
    "database_url": "postgresql://attacker:owned@evil.com:5432/exfil",
    "webhook_url": "https://evil.com/collect",
    "admin_email": "attacker@evil.com",
    "debug": true
  }
}`
	return h.dashJSON(w, "config-injection", json)
}

func (h *Handler) serveSettingsWebhook(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/webhook")
	webhookURL := r.FormValue("url")
	if webhookURL == "" {
		webhookURL = "https://hooks.slack.com/services/T" + h.randomHex(rng, 9) + "/B" + h.randomHex(rng, 9) + "/" + h.randomHex(rng, 24)
	}
	json := fmt.Sprintf(`{
  "status": "configured",
  "webhook": {
    "url": %q,
    "events": ["user.created", "user.deleted", "payment.received", "settings.changed", "backup.completed"],
    "secret": "%s",
    "active": true,
    "last_triggered": "%s",
    "note": "Webhook URL is not validated. SSRF via configuration is possible."
  }
}`, webhookURL, h.randomHex(rng, 32), h.randomRecentDate(rng))
	return h.dashJSON(w, "ssrf-via-config", json)
}

// ===========================================================================
// 8. Audit Log Exposure
// ===========================================================================

func (h *Handler) serveSettingsAudit(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/audit")
	var rows strings.Builder
	actions := []struct {
		action string
		body   string
	}{
		{"settings.update", `{"password_policy":"none","csrf":"disabled"}`},
		{"user.delete", `{"user_id":4892,"email":"john.smith@example.com"}`},
		{"api_key.create", `{"name":"backdoor","permissions":"admin"}`},
		{"backup.download", `{"format":"sql","include_passwords":true}`},
		{"user.role_change", `{"user_id":1001,"old_role":"user","new_role":"superadmin"}`},
		{"settings.update", `{"cors_origin":"*","debug":true}`},
		{"webhook.create", `{"url":"https://attacker.com/exfil"}`},
		{"export.users", `{"format":"csv","fields":"all","include_passwords":true}`},
		{"auth.login", `{"email":"admin@acmecorp.com","password":"admin123!","ip":"203.0.113.42"}`},
		{"config.import", `{"source":"external","validation":"disabled"}`},
		{"certificate.view", `{"cert_id":"prod-tls-2024"}`},
		{"database.test_connection", `{"host":"db-master.internal","password":"SuperSecretP4ss!"}`},
	}
	for _, a := range actions {
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%s</td><td>admin</td><td>%s</td><td>%s</td>
<td><code style="font-size:11px;">%s</code></td>
<td>%s</td>
</tr>
`, h.randomRecentDate(rng), a.action, h.randomIP(rng), fakeUserAgent(rng), a.body))
	}

	body := fmt.Sprintf(`
<div class="warn">Audit log is publicly accessible and contains full request bodies including credentials.</div>
<table>
<tr><th>Timestamp</th><th>User</th><th>Action</th><th>IP</th><th>User Agent</th><th>Request Body</th></tr>
%s
</table>
<p><a href="/vuln/settings/audit/export">Export Audit Log (CSV)</a></p>`, rows.String())
	return h.dashHTML(w, "/vuln/settings/audit", "Audit Log", "audit-log-exposure", body)
}

func (h *Handler) serveSettingsAuditExport(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/audit/export")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_log.csv")
	w.Header().Set("X-Glitch-Vuln-Type", "audit-log-exposure")
	w.WriteHeader(http.StatusOK)

	var sb strings.Builder
	sb.WriteString("timestamp,user,action,ip,user_agent,request_body\n")
	entries := []struct {
		action string
		body   string
	}{
		{"settings.update", "{\"password_policy\":\"none\"}"},
		{"user.delete", "{\"user_id\":4892}"},
		{"api_key.create", "{\"permissions\":\"admin\"}"},
		{"auth.login", "{\"email\":\"admin@acmecorp.com\",\"password\":\"admin123!\"}"},
		{"backup.download", "{\"include_passwords\":true}"},
		{"user.role_change", "{\"new_role\":\"superadmin\"}"},
		{"export.users", "{\"format\":\"csv\",\"fields\":\"all\"}"},
		{"webhook.create", "{\"url\":\"https://attacker.com/exfil\"}"},
		{"config.import", "{\"validation\":\"disabled\"}"},
		{"database.test", "{\"password\":\"SuperSecretP4ss!\"}"},
	}
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("%s,admin,%s,%s,%s,\"%s\"\n",
			h.randomRecentDate(rng), e.action, h.randomIP(rng),
			fakeUserAgent(rng), e.body))
	}
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveSettingsChangelog(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/changelog")
	var rows strings.Builder
	changes := []struct {
		setting  string
		oldValue string
		newValue string
	}{
		{"database.password", "OldP4ssw0rd!", "SuperSecretP4ss!"},
		{"smtp.password", "SG.oldkey123.oldsecret", "SG.newkey456.newsecret"},
		{"jwt_secret", "old-jwt-secret-2023", "new-jwt-secret-2024-" + h.randomHex(rng, 16)},
		{"cors_origin", "https://app.acmecorp.com", "*"},
		{"password_policy", "strong", "weak"},
		{"2fa_required", "true", "false"},
		{"session_timeout", "900", "0"},
		{"debug_mode", "false", "true"},
		{"rate_limit.enabled", "true", "false"},
		{"api_key.production", "sk_old_" + h.randomHex(rng, 16), "sk_live_" + h.randomHex(rng, 16)},
		{"aws.secret_key", h.randomHex(rng, 20), h.randomHex(rng, 40)},
		{"stripe.secret_key", "sk_live_old_" + h.randomHex(rng, 12), "sk_live_" + h.randomHex(rng, 24)},
	}
	for _, c := range changes {
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%s</td><td>admin</td><td>%s</td>
<td><code>%s</code></td><td><code>%s</code></td>
</tr>
`, h.randomRecentDate(rng), c.setting, c.oldValue, c.newValue))
	}

	body := fmt.Sprintf(`
<div class="warn">Configuration changelog exposes old and new values of sensitive settings.</div>
<table>
<tr><th>Timestamp</th><th>Changed By</th><th>Setting</th><th>Old Value</th><th>New Value</th></tr>
%s
</table>`, rows.String())
	return h.dashHTML(w, "/vuln/settings/changelog", "Configuration Changelog", "audit-log-exposure", body)
}

// ===========================================================================
// 9. Feature Flags with Secrets
// ===========================================================================

func (h *Handler) serveSettingsFlags(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/flags")
	body := fmt.Sprintf(`
<h2>Feature Flags</h2>
<table>
<tr><th>Flag</th><th>Status</th><th>Environment</th><th>Value</th></tr>
<tr><td>enable_new_dashboard</td><td><span class="tag tag-green">Enabled</span></td><td>production</td><td>true</td></tr>
<tr><td>beta_api_v2</td><td><span class="tag tag-yellow">Beta</span></td><td>staging</td><td>true</td></tr>
<tr><td>stripe_integration_key</td><td><span class="tag tag-green">Enabled</span></td><td>production</td><td><code>sk_live_%s</code></td></tr>
<tr><td>analytics_api_token</td><td><span class="tag tag-green">Enabled</span></td><td>production</td><td><code>%s</code></td></tr>
<tr><td>enable_debug_endpoints</td><td><span class="tag tag-red">Enabled</span></td><td>production</td><td>true</td></tr>
<tr><td>aws_lambda_key</td><td><span class="tag tag-green">Enabled</span></td><td>production</td><td><code>AKIA%s</code></td></tr>
<tr><td>experimental_ai_model</td><td><span class="tag tag-yellow">Beta</span></td><td>staging</td><td><code>sk-proj-%s</code></td></tr>
<tr><td>rate_limit_bypass</td><td><span class="tag tag-red">Enabled</span></td><td>production</td><td>true</td></tr>
<tr><td>internal_monitoring_key</td><td><span class="tag tag-green">Enabled</span></td><td>production</td><td><code>dd-%s</code></td></tr>
<tr><td>maintenance_mode</td><td><span class="tag tag-green">Disabled</span></td><td>production</td><td>false</td></tr>
</table>
<p>Update flags via POST to <a href="/vuln/settings/flags/update">/vuln/settings/flags/update</a> (no auth required).</p>`,
		h.randomHex(rng, 24),
		h.randomHex(rng, 32),
		h.randomHex(rng, 16),
		h.randomHex(rng, 48),
		h.randomHex(rng, 32),
	)
	return h.dashHTML(w, "/vuln/settings/flags", "Feature Flags", "feature-flag-exposure", body)
}

func (h *Handler) serveSettingsFlagsUpdate(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/flags/update")
	json := fmt.Sprintf(`{
  "status": "updated",
  "message": "Feature flags updated without authentication or validation.",
  "flags": {
    "enable_new_dashboard": true,
    "beta_api_v2": true,
    "stripe_integration_key": "sk_live_%s",
    "enable_debug_endpoints": true,
    "rate_limit_bypass": true,
    "maintenance_mode": false
  },
  "updated_by": "anonymous (no auth)",
  "updated_at": "%s"
}`, h.randomHex(rng, 24), h.randomRecentDate(rng))
	return h.dashJSON(w, "feature-flag-exposure", json)
}

// ===========================================================================
// 10. Service Accounts & Credentials
// ===========================================================================

func (h *Handler) serveSettingsCredentials(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/credentials")
	body := fmt.Sprintf(`
<h2>Service Account Credentials</h2>
<div class="warn">All service account passwords are displayed in plaintext.</div>

<h2>PostgreSQL</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Host</td><td>db-master.internal:5432</td></tr>
  <tr><td>Username</td><td>app_service</td></tr>
  <tr><td>Password</td><td><code>Pg_S3rv1ce_%s</code></td></tr>
  <tr><td>Database</td><td>production</td></tr>
</table>
</div>

<h2>Redis</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Host</td><td>redis.internal:6379</td></tr>
  <tr><td>Password</td><td><code>R3d1s_%s</code></td></tr>
  <tr><td>Database</td><td>0</td></tr>
</table>
</div>

<h2>Elasticsearch</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Host</td><td>es.internal:9200</td></tr>
  <tr><td>Username</td><td>elastic</td></tr>
  <tr><td>Password</td><td><code>3l4st1c_%s</code></td></tr>
</table>
</div>

<h2>Apache Kafka</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Broker</td><td>kafka.internal:9092</td></tr>
  <tr><td>SASL Username</td><td>kafka_producer</td></tr>
  <tr><td>SASL Password</td><td><code>K4fk4_Pr0d_%s</code></td></tr>
  <tr><td>Schema Registry</td><td>http://schema.internal:8081</td></tr>
</table>
</div>

<h2>RabbitMQ</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Host</td><td>rabbitmq.internal:5672</td></tr>
  <tr><td>Username</td><td>app_worker</td></tr>
  <tr><td>Password</td><td><code>R4bb1t_%s</code></td></tr>
  <tr><td>Vhost</td><td>/production</td></tr>
  <tr><td>Management URL</td><td>http://rabbitmq.internal:15672</td></tr>
</table>
</div>

<h2>MongoDB</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Host</td><td>mongo.internal:27017</td></tr>
  <tr><td>Username</td><td>mongo_admin</td></tr>
  <tr><td>Password</td><td><code>M0ng0_%s</code></td></tr>
  <tr><td>Auth Database</td><td>admin</td></tr>
  <tr><td>Connection String</td><td><code>mongodb://mongo_admin:M0ng0_%s@mongo.internal:27017/production?authSource=admin</code></td></tr>
</table>
</div>`,
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
		h.randomHex(rng, 12),
	)
	return h.dashHTML(w, "/vuln/settings/credentials", "Service Account Credentials", "credential-exposure", body)
}

func (h *Handler) serveSettingsCertificates(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/certificates")
	body := fmt.Sprintf(`
<h2>TLS Certificate (Production)</h2>
<div class="warn">Private key is exposed. If this were real, the certificate would need immediate revocation.</div>

<h2>Certificate</h2>
<pre>-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIUN%sMAwGA1UECgwFQWNtZUNvcnAwHhcNMjQwMTAxMDAw
MDAwWhcNMjUwMTAxMDAwMDAwWjBhMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3
IFlvcmsxETAPBgNVBAcMCE5ldyBZb3JrMREwDwYDVQQKDAhBY21lQ29ycDEZMBcG
A1UEAwwQKi5hY21lY29ycC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC%sxC9f
%s
%s
-----END CERTIFICATE-----</pre>

<h2>Private Key</h2>
<pre>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA%s
%s
%s
%s
%s
%s
-----END RSA PRIVATE KEY-----</pre>

<h2>Certificate Details</h2>
<div class="card">
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Subject</td><td>CN=*.acmecorp.com, O=AcmeCorp, L=New York, ST=New York, C=US</td></tr>
  <tr><td>Issuer</td><td>CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US</td></tr>
  <tr><td>Serial Number</td><td>%s</td></tr>
  <tr><td>Valid From</td><td>2024-01-01 00:00:00 UTC</td></tr>
  <tr><td>Valid To</td><td>2025-01-01 00:00:00 UTC</td></tr>
  <tr><td>Fingerprint (SHA-256)</td><td>%s</td></tr>
  <tr><td>Key Size</td><td>2048 bit</td></tr>
  <tr><td>Signature Algorithm</td><td>SHA256-RSA</td></tr>
</table>
</div>`,
		h.randomHex(rng, 16),
		h.randomHex(rng, 60),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 60),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 64),
		h.randomHex(rng, 32),
		h.randomHex(rng, 64),
	)
	return h.dashHTML(w, "/vuln/settings/certificates", "TLS Certificates", "credential-exposure", body)
}

func (h *Handler) serveSettingsTokens(w http.ResponseWriter, r *http.Request) int {
	rng := h.seedFromPath("/vuln/settings/tokens")
	var rows strings.Builder
	tokens := []struct {
		name   string
		scope  string
		expiry string
	}{
		{"CI/CD Pipeline", "deploy, read, write", "2025-12-31"},
		{"Monitoring Agent", "read, metrics", "2025-06-30"},
		{"Backup Service", "read, export, backup", "2025-09-30"},
		{"Analytics Pipeline", "read, analytics", "2025-12-31"},
		{"Admin Panel", "admin, read, write, delete", "Never"},
		{"Mobile App", "read, write, push", "2025-08-15"},
		{"Partner API", "read, partner", "2025-12-31"},
		{"Internal Tools", "admin, read, write", "Never"},
	}
	for _, t := range tokens {
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%s</td><td><code>glitch_%s</code></td><td>%s</td>
<td>%s</td><td>%s</td><td><span class="tag tag-green">Active</span></td>
</tr>
`, t.name, h.randomHex(rng, 32), t.scope, t.expiry, h.randomRecentDate(rng)))
	}

	body := fmt.Sprintf(`
<h2>Active API Tokens</h2>
<div class="warn">All tokens displayed in plaintext. Tokens with "Never" expiry present a persistent risk.</div>
<table>
<tr><th>Name</th><th>Token</th><th>Scope</th><th>Expires</th><th>Last Used</th><th>Status</th></tr>
%s
</table>`, rows.String())
	return h.dashHTML(w, "/vuln/settings/tokens", "API Tokens", "credential-exposure", body)
}
