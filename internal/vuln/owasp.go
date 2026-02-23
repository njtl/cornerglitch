package vuln

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Handler emulates OWASP Top 10 (2021) vulnerabilities with realistic-looking
// "compromised" responses. All data is synthetic and deterministically seeded
// from request paths. This is for educational/research purposes only.
type Handler struct {
	firstNames []string
	lastNames  []string
	domains    []string
}

// NewHandler creates a new OWASP vulnerability emulator.
func NewHandler() *Handler {
	return &Handler{
		firstNames: []string{
			"james", "mary", "robert", "patricia", "john", "jennifer",
			"michael", "linda", "david", "elizabeth", "william", "barbara",
			"richard", "susan", "joseph", "jessica", "thomas", "sarah",
			"charles", "karen", "daniel", "lisa", "matthew", "nancy",
			"anthony", "betty", "mark", "margaret", "donald", "sandra",
		},
		lastNames: []string{
			"smith", "johnson", "williams", "brown", "jones", "garcia",
			"miller", "davis", "rodriguez", "martinez", "hernandez", "lopez",
			"gonzalez", "wilson", "anderson", "thomas", "taylor", "moore",
			"jackson", "martin", "lee", "perez", "thompson", "white",
			"harris", "sanchez", "clark", "ramirez", "lewis", "robinson",
		},
		domains: []string{
			"example.com", "testcorp.io", "acmeinc.org", "globex.net",
			"initech.com", "internal.dev", "staging.local", "demo.test",
		},
	}
}

// ShouldHandle returns true if the given path should be handled by the OWASP
// vulnerability emulator (including advanced and dashboard/settings vulns).
func (h *Handler) ShouldHandle(path string) bool {
	if strings.HasPrefix(path, "/vuln/") || path == "/vuln" {
		return true
	}
	switch path {
	case "/admin/users", "/logs/access.log", "/proxy":
		return true
	}
	return false
}

// ServeHTTP handles the request and writes a simulated vulnerable response.
// Returns the HTTP status code used.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Honeypot", "true")
	path := r.URL.Path

	// Overlap paths that map to specific categories
	switch path {
	case "/admin/users":
		return h.serveA01Users(w, r)
	case "/logs/access.log":
		return h.serveA09AccessLog(w, r)
	case "/proxy":
		return h.serveA10Proxy(w, r)
	}

	// Route /vuln/aNN/ paths
	if strings.HasPrefix(path, "/vuln/a01") {
		return h.serveA01(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a02") {
		return h.serveA02(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a03") {
		return h.serveA03(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a04") {
		return h.serveA04(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a05") {
		return h.serveA05(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a06") {
		return h.serveA06(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a07") {
		return h.serveA07(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a08") {
		return h.serveA08(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a09") {
		return h.serveA09(w, r)
	}
	if strings.HasPrefix(path, "/vuln/a10") {
		return h.serveA10(w, r)
	}

	// OWASP API Security Top 10 (2023)
	if h.APIShouldHandle(path) {
		return h.ServeAPISecurity(w, r)
	}

	// Advanced vulnerability categories (CORS, redirect, XXE, SSTI, etc.)
	if h.AdvancedShouldHandle(path) {
		return h.ServeAdvanced(w, r)
	}

	// Modern OWASP categories (LLM Top 10, CI/CD Top 10, Cloud-Native Top 10)
	if h.ModernShouldHandle(path) {
		return h.ServeModern(w, r)
	}

	// OWASP Mobile Top 10, Privacy Top 10, Client-Side Top 10
	if h.MobileShouldHandle(path) {
		return h.ServeMobile(w, r)
	}

	// Dashboard/settings vulnerability emulations
	if h.DashboardShouldHandle(path) {
		return h.ServeDashboard(w, r)
	}

	// Fallback: /vuln/ index page
	if path == "/vuln/" || path == "/vuln" {
		return h.serveIndex(w, r)
	}

	// Unknown /vuln/ subpath
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown vulnerability demo path.</p>"))
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Index page
// ---------------------------------------------------------------------------

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<style>
  .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .dash-card { background: #fff; border: 1px solid var(--border-light); border-radius: var(--radius-lg); padding: 20px; transition: box-shadow 0.15s, border-color 0.15s; text-decoration: none; color: inherit; display: block; }
  .dash-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-color: var(--brand-primary); text-decoration: none; }
  .dash-card .card-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-bottom: 14px; }
  .dash-card .card-icon svg { width: 20px; height: 20px; }
  .dash-card h3 { font-size: 14px; font-weight: 600; margin: 0 0 6px; color: var(--text-primary); }
  .dash-card p { font-size: 12.5px; color: var(--text-muted); margin: 0; line-height: 1.5; }
  .dash-card .card-meta { display: flex; align-items: center; gap: 8px; margin-top: 12px; font-size: 11px; color: var(--text-muted); }
  .dash-card .card-meta .dot { width: 6px; height: 6px; border-radius: 50%; }
  .icon-blue { background: #dbeafe; color: #2563eb; }
  .icon-green { background: #d1fae5; color: #059669; }
  .icon-purple { background: #ede9fe; color: #7c3aed; }
  .icon-amber { background: #fef3c7; color: #d97706; }
  .icon-red { background: #fee2e2; color: #dc2626; }
  .icon-cyan { background: #cffafe; color: #0891b2; }
  .icon-indigo { background: #e0e7ff; color: #4f46e5; }
  .icon-rose { background: #ffe4e6; color: #e11d48; }
  .section-heading { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-muted); margin: 28px 0 14px; display: flex; align-items: center; gap: 8px; }
  .section-heading::after { content: ''; flex: 1; height: 1px; background: var(--border-light); }
  .two-col { display: grid; grid-template-columns: 1fr 360px; gap: 20px; margin-top: 8px; }
  @media (max-width: 960px) { .two-col { grid-template-columns: 1fr; } }
  .activity-list { list-style: none; padding: 0; margin: 0; }
  .activity-list li { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border-light); font-size: 13px; align-items: flex-start; }
  .activity-list li:last-child { border-bottom: none; }
  .activity-dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 6px; flex-shrink: 0; }
  .activity-time { color: var(--text-muted); font-size: 11px; white-space: nowrap; margin-left: auto; flex-shrink: 0; }
  .activity-text { color: var(--text-secondary); flex: 1; }
  .activity-text strong { color: var(--text-primary); font-weight: 550; }
  .status-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .status-item { background: var(--sidebar-bg); border: 1px solid var(--border-light); border-radius: var(--radius); padding: 12px 14px; }
  .status-item .status-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 4px; }
  .status-item .status-value { font-size: 16px; font-weight: 650; color: var(--text-primary); display: flex; align-items: center; gap: 6px; }
  .status-item .status-value .indicator { width: 8px; height: 8px; border-radius: 50%; }
  .status-item .status-value .indicator.green { background: #059669; }
  .status-item .status-value .indicator.yellow { background: #d97706; }
  .status-item .status-value .indicator.red { background: #dc2626; }
  .stat-bar { display: flex; gap: 0; height: 32px; border-radius: 6px; overflow: hidden; margin-top: 16px; }
  .stat-bar > div { display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 600; color: #fff; }
</style>

<div class="section-heading">Quick Access</div>
<div class="dashboard-grid">
  <a href="/vuln/a01/" class="dash-card">
    <div class="card-icon icon-blue">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
    </div>
    <h3>User Management</h3>
    <p>Manage user accounts, permissions, and role assignments across the organization.</p>
    <div class="card-meta"><span class="dot" style="background:#059669"></span> 248 active users</div>
  </a>
  <a href="/vuln/a02/" class="dash-card">
    <div class="card-icon icon-green">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
    </div>
    <h3>Credential Store</h3>
    <p>Service credentials, encryption keys, and certificate management for production systems.</p>
    <div class="card-meta"><span class="dot" style="background:#d97706"></span> 3 expiring soon</div>
  </a>
  <a href="/vuln/a03/" class="dash-card">
    <div class="card-icon icon-purple">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
    </div>
    <h3>Data Browser</h3>
    <p>Query and inspect production data stores. Execute SQL, search records, and export results.</p>
    <div class="card-meta"><span class="dot" style="background:#059669"></span> Connected</div>
  </a>
  <a href="/vuln/a05/" class="dash-card">
    <div class="card-icon icon-amber">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
    </div>
    <h3>Configuration</h3>
    <p>Server settings, environment variables, feature flags, and runtime configuration.</p>
    <div class="card-meta"><span class="dot" style="background:#059669"></span> 12 modules loaded</div>
  </a>
  <a href="/vuln/a07/" class="dash-card">
    <div class="card-icon icon-red">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <h3>Authentication</h3>
    <p>SSO configuration, session management, password policies, and MFA enrollment settings.</p>
    <div class="card-meta"><span class="dot" style="background:#dc2626"></span> MFA not enforced</div>
  </a>
  <a href="/vuln/a06/" class="dash-card">
    <div class="card-icon icon-cyan">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
    </div>
    <h3>Components</h3>
    <p>Third-party libraries, system dependencies, and framework version tracking.</p>
    <div class="card-meta"><span class="dot" style="background:#dc2626"></span> 6 critical updates</div>
  </a>
  <a href="/vuln/a09/" class="dash-card">
    <div class="card-icon icon-indigo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
    </div>
    <h3>Reports &amp; Logs</h3>
    <p>Access logs, security events, audit trail, and compliance monitoring dashboards.</p>
    <div class="card-meta"><span class="dot" style="background:#059669"></span> Real-time</div>
  </a>
  <a href="/vuln/a10/" class="dash-card">
    <div class="card-icon icon-rose">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
    </div>
    <h3>Network &amp; Proxy</h3>
    <p>Internal service routing, reverse proxy configuration, and outbound request policies.</p>
    <div class="card-meta"><span class="dot" style="background:#d97706"></span> 2 rules pending</div>
  </a>
</div>

<div class="two-col">
  <div>
    <div class="card">
      <div class="card-header">
        <h3>Recent Activity</h3>
        <a href="/vuln/settings/audit" style="font-size:12px;">View all</a>
      </div>
      <ul class="activity-list">
        <li>
          <span class="activity-dot" style="background:#dc2626"></span>
          <span class="activity-text"><strong>admin@acme.com</strong> exported user database via <a href="/vuln/dashboard/users/export">CSV export</a></span>
          <span class="activity-time">2 min ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#d97706"></span>
          <span class="activity-text"><strong>svc-deploy</strong> rotated <a href="/vuln/dashboard/api-keys">API key</a> for production service</span>
          <span class="activity-time">14 min ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#059669"></span>
          <span class="activity-text"><strong>j.martinez</strong> updated <a href="/vuln/settings/database">database connection</a> pool settings</span>
          <span class="activity-time">28 min ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#dc2626"></span>
          <span class="activity-text">Failed login attempt for <strong>root</strong> from 203.0.113.42 &mdash; <a href="/vuln/a07/">review</a></span>
          <span class="activity-time">43 min ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#2563eb"></span>
          <span class="activity-text"><strong>admin@acme.com</strong> modified <a href="/vuln/a01/admin-panel">role permissions</a> for "Developer" group</span>
          <span class="activity-time">1 hr ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#d97706"></span>
          <span class="activity-text"><strong>system</strong> detected outdated <a href="/vuln/a06/">component versions</a> during scheduled scan</span>
          <span class="activity-time">2 hrs ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#059669"></span>
          <span class="activity-text"><strong>k.chen</strong> uploaded new <a href="/vuln/settings/certificates">TLS certificate</a> for api.acme.com</span>
          <span class="activity-time">3 hrs ago</span>
        </li>
        <li>
          <span class="activity-dot" style="background:#2563eb"></span>
          <span class="activity-text"><strong>svc-backup</strong> completed <a href="/vuln/dashboard/backup/download">database backup</a> (4.2 GB)</span>
          <span class="activity-time">4 hrs ago</span>
        </li>
      </ul>
    </div>
  </div>

  <div>
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3>System Status</h3>
        <span class="tag tag-success">Operational</span>
      </div>
      <div class="status-grid">
        <div class="status-item">
          <div class="status-label">Application</div>
          <div class="status-value"><span class="indicator green"></span> Healthy</div>
        </div>
        <div class="status-item">
          <div class="status-label">Database</div>
          <div class="status-value"><span class="indicator green"></span> Connected</div>
        </div>
        <div class="status-item">
          <div class="status-label">Cache</div>
          <div class="status-value"><span class="indicator yellow"></span> 87%% hit</div>
        </div>
        <div class="status-item">
          <div class="status-label">Queue</div>
          <div class="status-value"><span class="indicator green"></span> 12 pending</div>
        </div>
      </div>
      <div class="stat-bar">
        <div style="width:72%;background:#059669">72%% OK</div>
        <div style="width:18%;background:#d97706">18%% Warn</div>
        <div style="width:10%;background:#dc2626">10%% Err</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3>Quick Links</h3>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        <a href="/vuln/dashboard/debug" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          Debug Console
        </a>
        <a href="/vuln/dashboard/phpinfo" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          Server Info
        </a>
        <a href="/vuln/dashboard/server-status" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Service Health
        </a>
        <a href="/vuln/settings/integrations" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          Integrations
        </a>
        <a href="/vuln/settings/tokens" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
          API Tokens
        </a>
        <a href="/vuln/dashboard/backup/download" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Backup &amp; Restore
        </a>
        <a href="/vuln/api-sec/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          API Security Top 10
        </a>
        <a href="/vuln/llm/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4m0 14v4M4.22 4.22l2.83 2.83m9.9 9.9l2.83 2.83M1 12h4m14 0h4M4.22 19.78l2.83-2.83m9.9-9.9l2.83-2.83"/></svg>
          LLM Top 10
        </a>
        <a href="/vuln/cicd/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          CI/CD Top 10
        </a>
        <a href="/vuln/cloud/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/></svg>
          Cloud-Native Top 10
        </a>
        <a href="/vuln/mobile/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
          Mobile Top 10
        </a>
        <a href="/vuln/privacy-risks/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          Privacy Top 10
        </a>
        <a href="/vuln/client-side/" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:6px;font-size:13px;color:var(--text-secondary);transition:background 0.1s;text-decoration:none;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          Client-Side Top 10
        </a>
      </div>
    </div>
  </div>
</div>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Portal Home", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A01: Broken Access Control
// ---------------------------------------------------------------------------

func (h *Handler) serveA01(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A01")
	path := r.URL.Path

	switch {
	case path == "/vuln/a01/" || path == "/vuln/a01":
		return h.serveA01Overview(w, r)
	case path == "/vuln/a01/admin-panel":
		return h.serveA01AdminPanel(w, r)
	case strings.HasPrefix(path, "/vuln/a01/users/"):
		return h.serveA01Users(w, r)
	case path == "/vuln/a01/traversal":
		return h.serveA01Traversal(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A01 - Not Found", "<p>Unknown A01 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA01Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A01:2021 - Broken Access Control</h2>
<p>Access control enforces policy such that users cannot act outside of their intended permissions.
Failures typically lead to unauthorized information disclosure, modification, or destruction of data,
or performing a business function outside the user's limits.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a01/admin-panel">Admin Panel</a> - Accessible without authentication</li>
  <li><a href="/vuln/a01/users/1">User Profile (ID=1)</a> - IDOR: change the ID to view other users</li>
  <li><a href="/vuln/a01/users/2">User Profile (ID=2)</a></li>
  <li><a href="/vuln/a01/users/42">User Profile (ID=42)</a></li>
  <li><a href="/vuln/a01/traversal?file=../../etc/passwd">Directory Traversal</a> - Path traversal to read system files</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A01 - Broken Access Control", body))
	return http.StatusOK
}

func (h *Handler) serveA01AdminPanel(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rng := h.rngFromPath("/vuln/a01/admin-panel")
	users := fakeUsers(25, rng, h.firstNames, h.lastNames, h.domains)

	var rows strings.Builder
	for _, u := range users {
		rows.WriteString(fmt.Sprintf("<tr><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td></tr>\n",
			u["id"], u["name"], u["email"], u["role"], u["password_hash"], u["created_at"]))
	}

	body := fmt.Sprintf(`<h2>Admin Panel</h2>
<p class="warning">WARNING: This admin panel is accessible without authentication!</p>
<div class="admin-bar">
  <span>Logged in as: <strong>admin</strong></span> |
  <a href="/vuln/a01/admin-panel?action=export">Export Users</a> |
  <a href="/vuln/a01/admin-panel?action=delete-all">Delete All</a> |
  <a href="/vuln/a01/admin-panel?action=reset-passwords">Reset All Passwords</a>
</div>
<h3>User Management (%d users)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Password Hash</th><th>Created</th></tr>
%s</table>
<h3>System Actions</h3>
<ul>
  <li><a href="/vuln/a01/admin-panel?action=backup">Download Database Backup</a></li>
  <li><a href="/vuln/a01/admin-panel?action=logs">View System Logs</a></li>
  <li><a href="/vuln/a01/admin-panel?action=config">Edit Configuration</a></li>
</ul>`, len(users), rows.String())

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Admin Panel - No Auth Required", body))
	return http.StatusOK
}

func (h *Handler) serveA01Users(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Glitch-Vuln", "A01")

	// Extract user ID from path
	userID := "1"
	parts := strings.Split(r.URL.Path, "/")
	for i, p := range parts {
		if p == "users" && i+1 < len(parts) {
			userID = parts[i+1]
			break
		}
	}

	rng := h.rngFromPath("/vuln/a01/users/" + userID)
	users := fakeUsers(1, rng, h.firstNames, h.lastNames, h.domains)
	if len(users) == 0 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"user not found"}`)
		return http.StatusNotFound
	}

	user := users[0]
	user["id"] = userID
	user["ssn"] = fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000)
	user["credit_card"] = fmt.Sprintf("%04d-%04d-%04d-%04d", rng.Intn(9000)+1000, rng.Intn(10000), rng.Intn(10000), rng.Intn(10000))
	user["api_key"] = fmt.Sprintf("sk_%s", h.randomHex(rng, 32))
	user["internal_notes"] = "Account flagged for review - DO NOT SHARE WITH USER"

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(user))
	return http.StatusOK
}

func (h *Handler) serveA01Traversal(w http.ResponseWriter, r *http.Request) int {
	fileParam := r.URL.Query().Get("file")
	if fileParam == "" {
		fileParam = "../../etc/passwd"
	}

	w.Header().Set("Content-Type", "text/plain")

	// If it looks like a passwd traversal, show fake passwd
	if strings.Contains(fileParam, "passwd") {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakePasswd())
		return http.StatusOK
	}

	// If it looks like shadow file
	if strings.Contains(fileParam, "shadow") {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakeShadow())
		return http.StatusOK
	}

	// Generic file "contents"
	rng := h.rngFromPath(fileParam)
	w.WriteHeader(http.StatusOK)
	lines := rng.Intn(20) + 5
	for i := 0; i < lines; i++ {
		fmt.Fprintf(w, "# Configuration line %d\n", i+1)
		fmt.Fprintf(w, "setting_%d = value_%s\n", i, h.randomHex(rng, 8))
	}
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A02: Cryptographic Failures
// ---------------------------------------------------------------------------

func (h *Handler) serveA02(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A02")
	path := r.URL.Path

	// Set insecure cookies on all A02 responses
	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
		Path:  "/",
		// Intentionally missing Secure and HttpOnly flags
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "user_token",
		Value: "dXNlcjpwYXNzd29yZA==",
		Path:  "/",
	})

	switch {
	case path == "/vuln/a02/" || path == "/vuln/a02":
		return h.serveA02Overview(w, r)
	case path == "/vuln/a02/export":
		return h.serveA02Export(w, r)
	case path == "/vuln/a02/config":
		return h.serveA02Config(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A02 - Not Found", "<p>Unknown A02 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA02Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A02:2021 - Cryptographic Failures</h2>
<p>Previously known as "Sensitive Data Exposure," this category focuses on failures related
to cryptography (or lack thereof), which often lead to exposure of sensitive data.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a02/export">Database Export</a> - Base64-encoded credentials in export</li>
  <li><a href="/vuln/a02/config">Configuration File</a> - Plaintext passwords in config</li>
</ul>
<h3>Cookie Issues</h3>
<p>Check your browser cookies - session_id and user_token are set without Secure or HttpOnly flags.</p>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A02 - Cryptographic Failures", body))
	return http.StatusOK
}

func (h *Handler) serveA02Export(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath("/vuln/a02/export")
	users := fakeUsers(10, rng, h.firstNames, h.lastNames, h.domains)

	type exportEntry struct {
		name     string
		email    string
		password string
		encoded  string
	}

	var entries []map[string]interface{}
	for _, u := range users {
		pwd := fmt.Sprintf("P@ss%s%d!", h.firstNames[rng.Intn(len(h.firstNames))], rng.Intn(999)+1)
		encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%s", u["email"], pwd)))
		entries = append(entries, map[string]interface{}{
			"id":                  u["id"],
			"name":                u["name"],
			"email":               u["email"],
			"password_plaintext":  pwd,
			"password_base64":     encoded,
			"password_hash":       u["password_hash"],
			"api_key":             fmt.Sprintf("sk_live_%s", h.randomHex(rng, 24)),
			"encryption_key":      h.randomHex(rng, 32),
			"last_login":          u["created_at"],
			"two_factor_disabled": true,
		})
	}

	resp := map[string]interface{}{
		"export_date": time.Now().Format(time.RFC3339),
		"format":      "plaintext_v1",
		"warning":     "INTERNAL USE ONLY - Contains unencrypted credentials",
		"records":     entries,
		"db_connection": map[string]interface{}{
			"host":     "db-prod-01.internal.corp",
			"port":     5432,
			"database": "users_production",
			"username": "db_admin",
			"password": "Pr0d_DB!2024#admin",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA02Config(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	config := `# Application Configuration - PRODUCTION
# Last modified: 2024-11-15 by admin

[database]
host = db-prod-primary.internal.corp
port = 5432
name = glitchapp_production
user = app_service_account
password = xK9#mP2$vL5nQ8wR!
ssl_mode = disable
max_connections = 100

[redis]
host = redis-01.internal.corp
port = 6379
password = r3d!s_Pr0d_2024
database = 0

[aws]
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
s3_bucket = glitchapp-prod-data

[smtp]
host = smtp.internal.corp
port = 587
username = notifications@glitchapp.com
password = Sm7p_N0t!fy#2024

[jwt]
secret = super_secret_jwt_key_do_not_share_2024
expiry_hours = 720
algorithm = HS256

[api_keys]
stripe_secret = sk_live_4eC39HqLyjWDarjtT1zdp7dc
sendgrid_key = SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
twilio_sid = ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
twilio_token = your_auth_token_here

[admin]
default_username = admin
default_password = admin123
super_admin_password = Ch@ng3M3!N0t
`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, config)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A03: Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveA03(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A03")
	path := r.URL.Path

	switch {
	case path == "/vuln/a03/" || path == "/vuln/a03":
		return h.serveA03Overview(w, r)
	case path == "/vuln/a03/search":
		return h.serveA03Search(w, r)
	case path == "/vuln/a03/login":
		return h.serveA03Login(w, r)
	case path == "/vuln/a03/users":
		return h.serveA03Users(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A03 - Not Found", "<p>Unknown A03 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA03Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A03:2021 - Injection</h2>
<p>An application is vulnerable to injection when user-supplied data is not validated,
filtered, or sanitized by the application. Hostile data is used directly within
interpreter queries or commands.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a03/search?q=test">Search (XSS)</a> - Query parameter reflected in response</li>
  <li><a href="/vuln/a03/search?q=%3Cscript%3Ealert('xss')%3C/script%3E">Search (XSS payload)</a></li>
  <li><a href="/vuln/a03/users?id=1">SQL Injection - Normal</a></li>
  <li><a href="/vuln/a03/users?id=1%20OR%201%3D1">SQL Injection - OR 1=1</a></li>
  <li>POST /vuln/a03/login - SQL error with query fragment</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A03 - Injection", body))
	return http.StatusOK
}

func (h *Handler) serveA03Search(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	query := r.URL.Query().Get("q")
	if query == "" {
		query = "example"
	}

	rng := h.rngFromPath("/vuln/a03/search/" + query)

	// Intentionally reflect query without sanitization (XSS demo)
	var results strings.Builder
	numResults := rng.Intn(8) + 3
	for i := 0; i < numResults; i++ {
		firstName := h.firstNames[rng.Intn(len(h.firstNames))]
		lastName := h.lastNames[rng.Intn(len(h.lastNames))]
		results.WriteString(fmt.Sprintf(`<div class="result">
  <h3><a href="/vuln/a03/search?q=%s+%s">%s %s's Profile</a></h3>
  <p>Matching result for "<strong>%s</strong>" in user records...</p>
</div>`, firstName, lastName, strings.Title(firstName), strings.Title(lastName), query))
	}

	// The query is reflected unsanitized - this is the XSS vulnerability demo
	body := fmt.Sprintf(`<h2>Search Results</h2>
<form action="/vuln/a03/search" method="GET">
  <input type="text" name="q" value="%s" style="width:300px">
  <button type="submit">Search</button>
</form>
<p>Showing results for: %s</p>
<p>Found %d results</p>
%s`, query, query, numResults, results.String())

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Search: "+query, body))
	return http.StatusOK
}

func (h *Handler) serveA03Login(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := `<h2>Login</h2>
<form action="/vuln/a03/login" method="POST">
  <label>Username: <input type="text" name="username"></label><br><br>
  <label>Password: <input type="password" name="password"></label><br><br>
  <button type="submit">Login</button>
</form>`
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, h.wrapHTML("Login", body))
		return http.StatusOK
	}

	// POST: simulate SQL error with visible query fragment
	username := r.FormValue("username")
	if username == "" {
		username = "admin"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	errorResp := fmt.Sprintf(`{
  "error": "DatabaseError",
  "message": "Error 1064 (42000): You have an error in your SQL syntax near ''%s'' at line 1",
  "query": "SELECT * FROM users WHERE username='%s' AND password='***' LIMIT 1",
  "database": "glitchapp_production",
  "table": "users",
  "timestamp": "%s",
  "stack": [
    "at Database.query (db/connection.go:142)",
    "at AuthService.validateCredentials (services/auth.go:89)",
    "at LoginHandler.handle (handlers/login.go:34)",
    "at Router.dispatch (server/router.go:201)"
  ]
}`, username, username, time.Now().Format(time.RFC3339))
	fmt.Fprint(w, errorResp)
	return http.StatusInternalServerError
}

func (h *Handler) serveA03Users(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	idParam := r.URL.Query().Get("id")
	if idParam == "" {
		idParam = "1"
	}

	rng := h.rngFromPath("/vuln/a03/users")

	// If the id contains SQL injection patterns, return "all users"
	isSQLi := strings.Contains(idParam, "OR") ||
		strings.Contains(idParam, "or") ||
		strings.Contains(idParam, "1=1") ||
		strings.Contains(idParam, "--") ||
		strings.Contains(idParam, ";") ||
		strings.Contains(idParam, "UNION")

	var numUsers int
	if isSQLi {
		numUsers = 50 // "Leaked" all users
	} else {
		numUsers = 1
	}

	users := fakeUsers(numUsers, rng, h.firstNames, h.lastNames, h.domains)

	resp := map[string]interface{}{
		"query":       fmt.Sprintf("SELECT * FROM users WHERE id=%s", idParam),
		"result_count": len(users),
		"data":        users,
	}

	if isSQLi {
		resp["debug"] = fmt.Sprintf("WARNING: Query returned %d rows (expected 1). Possible injection in parameter: id=%s", numUsers, idParam)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A04: Insecure Design
// ---------------------------------------------------------------------------

func (h *Handler) serveA04(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A04")
	path := r.URL.Path

	switch {
	case path == "/vuln/a04/" || path == "/vuln/a04":
		return h.serveA04Overview(w, r)
	case path == "/vuln/a04/reset":
		return h.serveA04Reset(w, r)
	case path == "/vuln/a04/verify":
		return h.serveA04Verify(w, r)
	case path == "/vuln/a04/users":
		return h.serveA04Users(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A04 - Not Found", "<p>Unknown A04 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA04Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A04:2021 - Insecure Design</h2>
<p>Insecure design focuses on risks related to design and architectural flaws. It calls for
more use of threat modeling, secure design patterns, and reference architectures.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a04/reset?email=user@example.com">Password Reset</a> - Predictable reset tokens</li>
  <li><a href="/vuln/a04/verify?token=0001">Token Verification</a> - Sequential tokens accepted</li>
  <li><a href="/vuln/a04/users">User Listing</a> - Sequential user IDs</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A04 - Insecure Design", body))
	return http.StatusOK
}

func (h *Handler) serveA04Reset(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	email := r.URL.Query().Get("email")
	if email == "" {
		email = "user@example.com"
	}

	// Generate predictable sequential token from email
	sum := sha256.Sum256([]byte(email))
	tokenNum := int(binary.BigEndian.Uint16(sum[:2])) % 10000

	resp := map[string]interface{}{
		"status":     "success",
		"message":    fmt.Sprintf("Password reset link sent to %s", email),
		"reset_token": fmt.Sprintf("%04d", tokenNum),
		"reset_url":  fmt.Sprintf("/vuln/a04/verify?token=%04d", tokenNum),
		"expires_in": "24h",
		"debug_info": map[string]interface{}{
			"token_algorithm": "sequential_counter",
			"token_space":     10000,
			"entropy_bits":    13,
			"note":            "Token generation uses predictable sequential counter",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA04Verify(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	token := r.URL.Query().Get("token")
	if token == "" {
		token = "0001"
	}

	// Accept any 4-digit token (insecure by design)
	valid := len(token) <= 4

	resp := map[string]interface{}{
		"token":    token,
		"valid":    valid,
		"message":  "Token accepted. Password has been reset to: TempPass123!",
		"new_password": "TempPass123!",
		"warning":  "Password sent in response body (insecure design)",
	}

	if !valid {
		resp["valid"] = false
		resp["message"] = "Invalid token format"
		delete(resp, "new_password")
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA04Users(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath("/vuln/a04/users")
	users := fakeUsers(20, rng, h.firstNames, h.lastNames, h.domains)

	// Override IDs to be sequential (insecure design)
	for i := range users {
		users[i]["id"] = i + 1
		users[i]["account_number"] = fmt.Sprintf("ACC-%05d", i+1)
		users[i]["api_key"] = fmt.Sprintf("key_%04d", i+1)
	}

	resp := map[string]interface{}{
		"users":      users,
		"total":      len(users),
		"pagination": map[string]interface{}{
			"page":     1,
			"per_page": 20,
			"next":     "/vuln/a04/users?page=2",
		},
		"note": "User IDs, account numbers, and API keys use sequential numbering",
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A05: Security Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveA05(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A05")
	w.Header().Set("X-Powered-By", "PHP/7.4.3")
	w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
	w.Header().Set("X-Debug-Info", "env=production, node=web-03, version=3.2.1-rc4, debug=true")
	w.Header().Set("X-AspNet-Version", "4.0.30319")
	w.Header().Set("X-Runtime", "0.042359")
	path := r.URL.Path

	switch {
	case path == "/vuln/a05/" || path == "/vuln/a05":
		return h.serveA05Overview(w, r)
	case path == "/vuln/a05/error":
		return h.serveA05Error(w, r)
	case path == "/vuln/a05/phpinfo":
		return h.serveA05PhpInfo(w, r)
	case path == "/vuln/a05/config":
		return h.serveA05Config(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A05 - Not Found", "<p>Unknown A05 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA05Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A05:2021 - Security Misconfiguration</h2>
<p>The application might be vulnerable if it is missing appropriate security hardening,
has improperly configured permissions, has unnecessary features enabled, or uses default accounts.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a05/error">Error Page</a> - Stack trace in error response</li>
  <li><a href="/vuln/a05/phpinfo">PHP Info</a> - phpinfo() output page</li>
  <li><a href="/vuln/a05/config">Configuration</a> - Default credentials visible</li>
</ul>
<h3>Response Headers</h3>
<p>Check the HTTP response headers for this page. Verbose server information is exposed.</p>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A05 - Security Misconfiguration", body))
	return http.StatusOK
}

func (h *Handler) serveA05Error(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	trace := fakeStackTrace()
	body := fmt.Sprintf(`<h2>Internal Server Error</h2>
<div class="error-detail">
<h3>Unhandled Exception</h3>
<pre class="stacktrace">%s</pre>
<h3>Request Details</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><td>Method</td><td>%s</td></tr>
<tr><td>Path</td><td>%s</td></tr>
<tr><td>Remote Addr</td><td>%s</td></tr>
<tr><td>User-Agent</td><td>%s</td></tr>
<tr><td>Server</td><td>web-03.prod.internal</td></tr>
<tr><td>Go Version</td><td>go1.21.5</td></tr>
<tr><td>Build</td><td>2024-11-15T14:23:01Z</td></tr>
<tr><td>DB Host</td><td>db-prod-primary.internal.corp:5432</td></tr>
<tr><td>Redis Host</td><td>redis-01.internal.corp:6379</td></tr>
</table>
<h3>Environment Variables</h3>
<pre>
APP_ENV=production
DATABASE_URL=postgres://app_user:s3cur3P@ss!@db-prod-primary:5432/glitchapp
REDIS_URL=redis://:r3d!s_key@redis-01:6379/0
SECRET_KEY_BASE=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DEBUG=true
</pre>
</div>`, trace, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())

	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, h.wrapHTML("500 Internal Server Error", body))
	return http.StatusInternalServerError
}

func (h *Handler) serveA05PhpInfo(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, fakePhpinfo())
	return http.StatusOK
}

func (h *Handler) serveA05Config(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"application": map[string]interface{}{
			"name":        "GlitchApp",
			"version":     "3.2.1",
			"environment": "production",
			"debug":       true,
		},
		"database": map[string]interface{}{
			"host":     "db-prod-primary.internal.corp",
			"port":     5432,
			"name":     "glitchapp_production",
			"username": "root",
			"password": "root",
		},
		"admin_panel": map[string]interface{}{
			"enabled":          true,
			"default_username": "admin",
			"default_password": "admin",
			"require_2fa":      false,
		},
		"features": map[string]interface{}{
			"debug_toolbar":     true,
			"stack_traces":      true,
			"verbose_errors":    true,
			"cors_allow_all":    true,
			"rate_limiting":     false,
			"csrf_protection":   false,
			"input_validation":  false,
		},
		"default_accounts": []map[string]interface{}{
			{"username": "admin", "password": "admin", "role": "superadmin"},
			{"username": "test", "password": "test123", "role": "admin"},
			{"username": "demo", "password": "demo", "role": "user"},
			{"username": "support", "password": "support2024", "role": "moderator"},
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A06: Vulnerable and Outdated Components
// ---------------------------------------------------------------------------

func (h *Handler) serveA06(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A06")
	w.Header().Set("Server", "Apache/2.4.29")
	w.Header().Set("X-Powered-By", "PHP/5.6.0")
	path := r.URL.Path

	switch {
	case path == "/vuln/a06/" || path == "/vuln/a06":
		return h.serveA06Overview(w, r)
	case path == "/vuln/a06/versions":
		return h.serveA06Versions(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A06 - Not Found", "<p>Unknown A06 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA06Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A06:2021 - Vulnerable and Outdated Components</h2>
<p>You are likely vulnerable if you do not know the versions of all components you use,
if the software is vulnerable, unsupported, or out of date.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a06/versions">Component Versions</a> - Installed components with known-vulnerable versions</li>
</ul>
<h3>Response Headers</h3>
<p>Check the response headers - Server and X-Powered-By expose outdated versions.</p>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A06 - Vulnerable Components", body))
	return http.StatusOK
}

func (h *Handler) serveA06Versions(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	components := fakeComponents()

	resp := map[string]interface{}{
		"scan_date":    time.Now().Format(time.RFC3339),
		"total":        len(components),
		"critical":     7,
		"high":         5,
		"medium":       4,
		"components":   components,
		"recommendation": "Immediately update all critical and high severity components",
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A07: Identification and Authentication Failures
// ---------------------------------------------------------------------------

func (h *Handler) serveA07(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A07")

	// Set long-lived cookies with no expiry
	http.SetCookie(w, &http.Cookie{
		Name:  "auth_session",
		Value: "sess_00000001_admin_permanent",
		Path:  "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "remember_me",
		Value: "user_admin_forever",
		Path:  "/",
	})

	path := r.URL.Path

	switch {
	case path == "/vuln/a07/" || path == "/vuln/a07":
		return h.serveA07Overview(w, r)
	case path == "/vuln/a07/login":
		return h.serveA07Login(w, r)
	case path == "/vuln/a07/dashboard":
		return h.serveA07Dashboard(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A07 - Not Found", "<p>Unknown A07 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA07Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A07:2021 - Identification and Authentication Failures</h2>
<p>Confirmation of the user's identity, authentication, and session management is critical
to protect against authentication-related attacks.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a07/login?session=abc123">Login with Session in URL</a> - Session token in query string</li>
  <li><a href="/vuln/a07/dashboard?sid=sess_0001">Dashboard</a> - Predictable session ID in URL</li>
  <li><a href="/vuln/a07/dashboard?sid=sess_0002">Dashboard (different session)</a></li>
</ul>
<h3>Cookie Issues</h3>
<p>Check your cookies - auth_session and remember_me are set with no expiry and no security flags.</p>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A07 - Authentication Failures", body))
	return http.StatusOK
}

func (h *Handler) serveA07Login(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session := r.URL.Query().Get("session")
	if session == "" {
		session = "abc123"
	}

	body := fmt.Sprintf(`<h2>Login Successful</h2>
<p>Welcome back, admin!</p>
<div class="warning">
<h3>Security Issues Detected:</h3>
<ul>
  <li>Session token visible in URL: <code>session=%s</code></li>
  <li>Session token will appear in browser history</li>
  <li>Session token will appear in server access logs</li>
  <li>Session token will appear in Referer header if user clicks external link</li>
  <li>No session rotation after login</li>
  <li>No brute-force protection</li>
</ul>
</div>
<h3>User Session Details</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><td>Session ID</td><td>%s</td></tr>
<tr><td>User</td><td>admin</td></tr>
<tr><td>Role</td><td>superadmin</td></tr>
<tr><td>Login Time</td><td>%s</td></tr>
<tr><td>Expiry</td><td>Never (no expiration set)</td></tr>
<tr><td>IP Lock</td><td>Disabled</td></tr>
<tr><td>2FA</td><td>Not Required</td></tr>
</table>
<p><a href="/vuln/a07/dashboard?sid=%s">Go to Dashboard</a></p>`, session, session, time.Now().Format(time.RFC3339), session)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Login - Session in URL", body))
	return http.StatusOK
}

func (h *Handler) serveA07Dashboard(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	sid := r.URL.Query().Get("sid")
	if sid == "" {
		sid = "sess_0001"
	}

	rng := h.rngFromPath("/vuln/a07/dashboard/" + sid)

	body := fmt.Sprintf(`<h2>Admin Dashboard</h2>
<p>Session: <code>%s</code> (predictable, sequential session ID)</p>
<div class="warning">
<p>Try changing the session ID: sess_0001, sess_0002, sess_0003...</p>
</div>
<h3>Recent Activity</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Time</th><th>Action</th><th>User</th><th>IP</th></tr>`, sid)

	for i := 0; i < 10; i++ {
		actions := []string{"login", "view_users", "export_data", "change_settings", "delete_record", "reset_password"}
		firstName := h.firstNames[rng.Intn(len(h.firstNames))]
		body += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d.%d.%d.%d</td></tr>\n",
			time.Now().Add(-time.Duration(rng.Intn(3600))*time.Second).Format("15:04:05"),
			actions[rng.Intn(len(actions))],
			firstName,
			rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1)
	}

	body += `</table>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Dashboard - Predictable Session", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A08: Software and Data Integrity Failures
// ---------------------------------------------------------------------------

func (h *Handler) serveA08(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A08")
	path := r.URL.Path

	switch {
	case path == "/vuln/a08/" || path == "/vuln/a08":
		return h.serveA08Overview(w, r)
	case path == "/vuln/a08/token":
		return h.serveA08Token(w, r)
	case path == "/vuln/a08/deserialize":
		return h.serveA08Deserialize(w, r)
	case path == "/vuln/a08/update":
		return h.serveA08Update(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A08 - Not Found", "<p>Unknown A08 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA08Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A08:2021 - Software and Data Integrity Failures</h2>
<p>Software and data integrity failures relate to code and infrastructure that does not
protect against integrity violations. This includes insecure deserialization.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a08/token">JWT Token</a> - Unsigned JWT with alg:none</li>
  <li><a href="/vuln/a08/deserialize">Deserialization</a> - Accepts base64 payloads (try POST with payload param)</li>
  <li><a href="/vuln/a08/update">Update Endpoint</a> - No signature verification on payloads</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A08 - Data Integrity Failures", body))
	return http.StatusOK
}

func (h *Handler) serveA08Token(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	claims := map[string]interface{}{
		"sub":   "1234567890",
		"name":  "Admin User",
		"email": "admin@glitchapp.internal",
		"role":  "superadmin",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(720 * time.Hour).Unix(),
		"iss":   "glitchapp",
		"permissions": []string{
			"read:all", "write:all", "delete:all", "admin:all",
		},
	}

	token := fakeJWT(claims)

	resp := map[string]interface{}{
		"token":       token,
		"token_type":  "Bearer",
		"expires_in":  2592000,
		"algorithm":   "none",
		"warning":     "JWT issued with alg:none - no signature verification",
		"decoded": map[string]interface{}{
			"header": map[string]interface{}{
				"alg": "none",
				"typ": "JWT",
			},
			"payload": claims,
			"signature": "",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA08Deserialize(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	payload := r.URL.Query().Get("payload")
	if r.Method == http.MethodPost {
		payload = r.FormValue("payload")
	}

	if payload == "" {
		// Provide a default base64 payload
		defaultObj := `{"class":"User","id":1,"name":"admin","role":"superadmin","cmd":"os.execute('id')"}`
		payload = base64.StdEncoding.EncodeToString([]byte(defaultObj))
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	var decodedStr string
	if err != nil {
		decodedStr = "(failed to decode: " + err.Error() + ")"
	} else {
		decodedStr = string(decoded)
	}

	resp := map[string]interface{}{
		"status":        "deserialized",
		"input_base64":  payload,
		"decoded_object": decodedStr,
		"result": map[string]interface{}{
			"class":         "User",
			"deserialized":  true,
			"execution_env": "production",
			"warning":       "Object deserialized without type checking or validation",
		},
		"server_info": map[string]interface{}{
			"hostname":   "web-03.prod.internal",
			"pid":        12847,
			"runtime":    "go1.21.5",
			"os":         "linux/amd64",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA08Update(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	resp := map[string]interface{}{
		"status":  "accepted",
		"message": "Update payload accepted without signature verification",
		"update": map[string]interface{}{
			"version":          "3.2.2",
			"source":           "https://updates.glitchapp.internal/latest",
			"signature":        "not_verified",
			"integrity_check":  false,
			"checksum_verified": false,
		},
		"warning":  "No HMAC/signature verification performed on update payload",
		"pipeline": map[string]interface{}{
			"ci_cd":           "Jenkins (unauthenticated)",
			"artifact_source": "http://artifacts.internal:8080 (HTTP, no TLS)",
			"auto_deploy":     true,
			"approval_required": false,
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A09: Security Logging and Monitoring Failures
// ---------------------------------------------------------------------------

func (h *Handler) serveA09(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A09")
	path := r.URL.Path

	switch {
	case path == "/vuln/a09/" || path == "/vuln/a09":
		return h.serveA09Overview(w, r)
	case path == "/vuln/a09/logs":
		return h.serveA09AccessLog(w, r)
	case path == "/vuln/a09/errors":
		return h.serveA09ErrorLog(w, r)
	case path == "/vuln/a09/audit":
		return h.serveA09AuditLog(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A09 - Not Found", "<p>Unknown A09 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA09Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A09:2021 - Security Logging and Monitoring Failures</h2>
<p>Without logging and monitoring, breaches cannot be detected. Insufficient logging,
detection, monitoring, and active response occurs any time auditable events are not logged.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a09/logs">Access Logs</a> - Raw Apache-format access logs (200 lines)</li>
  <li><a href="/vuln/a09/errors">Error Logs</a> - Error log with stack traces and sensitive paths</li>
  <li><a href="/vuln/a09/audit">Audit Log</a> - User action audit trail</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A09 - Logging Failures", body))
	return http.StatusOK
}

func (h *Handler) serveA09AccessLog(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	rng := h.rngFromPath("/vuln/a09/logs")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, fakeAccessLog(200, rng, h.firstNames))
	return http.StatusOK
}

func (h *Handler) serveA09ErrorLog(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	rng := h.rngFromPath("/vuln/a09/errors")

	var sb strings.Builder
	for i := 0; i < 50; i++ {
		ts := time.Now().Add(-time.Duration(rng.Intn(86400)) * time.Second)
		level := []string{"ERROR", "FATAL", "CRITICAL", "WARNING"}[rng.Intn(4)]
		pid := rng.Intn(30000) + 1000

		switch rng.Intn(5) {
		case 0:
			sb.WriteString(fmt.Sprintf("[%s] [%s] [pid %d] database connection failed: "+
				"postgres://app_user:s3cur3P@ss!@db-prod-primary:5432/glitchapp - Connection refused\n",
				ts.Format("2006-01-02 15:04:05"), level, pid))
		case 1:
			sb.WriteString(fmt.Sprintf("[%s] [%s] [pid %d] failed to read config: "+
				"/opt/glitchapp/config/production.yml - permission denied\n"+
				"  Stack: main.loadConfig() at /opt/glitchapp/src/config/loader.go:42\n"+
				"         main.init() at /opt/glitchapp/src/main.go:18\n",
				ts.Format("2006-01-02 15:04:05"), level, pid))
		case 2:
			email := fmt.Sprintf("%s@%s", h.firstNames[rng.Intn(len(h.firstNames))], h.domains[rng.Intn(len(h.domains))])
			sb.WriteString(fmt.Sprintf("[%s] [%s] [pid %d] authentication failed for user '%s' "+
				"from IP %d.%d.%d.%d - invalid password (attempt %d of 3)\n"+
				"  Password hash: $2a$10$%s\n",
				ts.Format("2006-01-02 15:04:05"), level, pid,
				email,
				rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1,
				rng.Intn(3)+1,
				h.randomHex(rng, 22)))
		case 3:
			sb.WriteString(fmt.Sprintf("[%s] [%s] [pid %d] SSL certificate verification failed: "+
				"/opt/glitchapp/certs/server.key exposed at world-readable permissions (0644)\n"+
				"  Certificate path: /opt/glitchapp/certs/server.crt\n"+
				"  Private key path: /opt/glitchapp/certs/server.key\n",
				ts.Format("2006-01-02 15:04:05"), level, pid))
		case 4:
			sb.WriteString(fmt.Sprintf("[%s] [%s] [pid %d] unhandled exception in request handler:\n%s\n",
				ts.Format("2006-01-02 15:04:05"), level, pid, fakeStackTrace()))
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveA09AuditLog(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath("/vuln/a09/audit")

	actions := []string{
		"user.login", "user.logout", "user.password_change", "user.role_change",
		"admin.user_create", "admin.user_delete", "admin.config_change",
		"admin.export_data", "admin.view_logs", "admin.reset_password",
		"data.export", "data.delete", "data.bulk_update",
		"api.key_create", "api.key_revoke",
		"system.backup_create", "system.restart", "system.config_update",
	}

	var entries []map[string]interface{}
	for i := 0; i < 100; i++ {
		firstName := h.firstNames[rng.Intn(len(h.firstNames))]
		lastName := h.lastNames[rng.Intn(len(h.lastNames))]
		entries = append(entries, map[string]interface{}{
			"id":        i + 1,
			"timestamp": time.Now().Add(-time.Duration(rng.Intn(86400)) * time.Second).Format(time.RFC3339),
			"action":    actions[rng.Intn(len(actions))],
			"user":      fmt.Sprintf("%s.%s", firstName, lastName),
			"ip":        fmt.Sprintf("%d.%d.%d.%d", rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1),
			"user_agent": fakeUserAgent(rng),
			"result":    []string{"success", "success", "success", "failure", "denied"}[rng.Intn(5)],
			"details":   fmt.Sprintf("Resource: /api/v1/%s, Method: %s", []string{"users", "config", "data", "sessions", "keys"}[rng.Intn(5)], []string{"GET", "POST", "PUT", "DELETE"}[rng.Intn(4)]),
		})
	}

	resp := map[string]interface{}{
		"audit_log": entries,
		"total":     len(entries),
		"warning":   "Audit log accessible without authentication - contains sensitive user actions",
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// A10: Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------

func (h *Handler) serveA10(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "A10")
	path := r.URL.Path

	switch {
	case path == "/vuln/a10/" || path == "/vuln/a10":
		return h.serveA10Overview(w, r)
	case path == "/vuln/a10/fetch":
		return h.serveA10Fetch(w, r)
	case path == "/vuln/a10/proxy":
		return h.serveA10Proxy(w, r)
	case path == "/vuln/a10/webhook":
		return h.serveA10Webhook(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, h.wrapHTML("A10 - Not Found", "<p>Unknown A10 demo endpoint.</p>"))
		return http.StatusNotFound
	}
}

func (h *Handler) serveA10Overview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>A10:2021 - Server-Side Request Forgery (SSRF)</h2>
<p>SSRF flaws occur whenever a web application fetches a remote resource without validating
the user-supplied URL. It allows an attacker to coerce the application to send a crafted
request to an unexpected destination.</p>
<h3>Demo Endpoints</h3>
<ul>
  <li><a href="/vuln/a10/fetch?url=http://internal-api.corp/secrets">Fetch URL</a> - Fetches content from user-supplied URL</li>
  <li><a href="/vuln/a10/proxy?target=http://169.254.169.254/latest/meta-data/">Proxy</a> - Proxies requests to cloud metadata service</li>
  <li><a href="/vuln/a10/webhook?callback=http://evil.com/steal-data">Webhook</a> - Sends data to user-controlled callback URL</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("A10 - Server-Side Request Forgery", body))
	return http.StatusOK
}

func (h *Handler) serveA10Fetch(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		targetURL = "http://internal-api.corp/secrets"
	}

	// Simulate fetching internal resources based on URL patterns
	var content string
	statusCode := 200

	switch {
	case strings.Contains(targetURL, "169.254.169.254"):
		content = fakeAWSMetadata()
	case strings.Contains(targetURL, "internal") || strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "127.0.0.1"):
		content = `{"internal_service":"secrets-manager","api_keys":["sk_prod_a1b2c3d4","sk_prod_e5f6g7h8"],"database_url":"postgres://admin:P@ssw0rd@db-01:5432/production","status":"running"}`
	case strings.Contains(targetURL, "10.") || strings.Contains(targetURL, "172.16.") || strings.Contains(targetURL, "192.168."):
		content = fmt.Sprintf(`{"network":"internal","host":"%s","services":["ssh:22","http:80","postgres:5432","redis:6379"],"status":"accessible"}`, targetURL)
	default:
		content = fmt.Sprintf(`{"fetched_from":"%s","status":"ok","content":"<html><body>External content fetched successfully</body></html>"}`, targetURL)
	}

	resp := map[string]interface{}{
		"requested_url": targetURL,
		"status_code":   statusCode,
		"content":       content,
		"server_ip":     "10.0.1.42",
		"note":          "Server fetched this URL without any validation or allowlist",
		"request_headers_sent": map[string]interface{}{
			"User-Agent":    "GlitchApp/3.2.1 (Internal Fetcher)",
			"Authorization": "Bearer internal-service-token-abc123",
			"X-Internal":    "true",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveA10Proxy(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Glitch-Vuln", "A10")
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "http://169.254.169.254/latest/meta-data/"
	}

	if strings.Contains(target, "169.254.169.254") {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakeAWSMetadata())
		return http.StatusOK
	}

	// Generic proxied response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Proxied response from: %s\n\n", target)
	fmt.Fprint(w, "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Proxied content from internal network</body></html>\n")
	return http.StatusOK
}

func (h *Handler) serveA10Webhook(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	callback := r.URL.Query().Get("callback")
	if callback == "" {
		callback = "http://evil.com/steal-data"
	}

	resp := map[string]interface{}{
		"status":     "webhook_sent",
		"callback":   callback,
		"message":    "Webhook successfully sent to callback URL",
		"payload_sent": map[string]interface{}{
			"event":          "data_export",
			"timestamp":      time.Now().Format(time.RFC3339),
			"records":        1547,
			"include_pii":    true,
			"server_identity": "web-03.prod.internal",
			"auth_token":     "Bearer internal-webhook-token-xyz789",
		},
		"warning": "Webhook sent to unvalidated external URL without allowlist check",
		"dns_resolution": map[string]interface{}{
			"resolved_ip": "203.0.113.42",
			"note":        "No DNS rebinding protection",
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Fake Data Generators
// ---------------------------------------------------------------------------

// fakeUsers generates n synthetic user records.
func fakeUsers(n int, rng *rand.Rand, firstNames, lastNames, domains []string) []map[string]interface{} {
	users := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		first := firstNames[rng.Intn(len(firstNames))]
		last := lastNames[rng.Intn(len(lastNames))]
		domain := domains[rng.Intn(len(domains))]
		roles := []string{"user", "user", "user", "admin", "moderator", "editor", "superadmin"}
		users[i] = map[string]interface{}{
			"id":            rng.Intn(90000) + 10000,
			"name":          strings.Title(first) + " " + strings.Title(last),
			"email":         fmt.Sprintf("%s.%s@%s", first, last, domain),
			"password_hash": fmt.Sprintf("$2a$10$%s", randomHexStatic(rng, 44)),
			"role":          roles[rng.Intn(len(roles))],
			"created_at":    time.Now().Add(-time.Duration(rng.Intn(365*24*3)) * time.Hour).Format(time.RFC3339),
		}
	}
	return users
}

// fakePasswd returns a realistic /etc/passwd file content.
func fakePasswd() string {
	return `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
messagebus:x:105:111::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
glitchapp:x:1000:1000:GlitchApp Service,,,:/home/glitchapp:/bin/bash
deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash
postgres:x:112:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:113:121::/var/lib/redis:/usr/sbin/nologin
`
}

// fakeShadow returns a fake /etc/shadow file content.
func fakeShadow() string {
	return `root:$6$rounds=656000$fakesalt1234$fakehashabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678:19500:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
sys:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
glitchapp:$6$rounds=656000$appusrsalt$hashedpasswordforappuser1234567890abcdef1234567890abcdef1234567890abcdef1234:19450:0:99999:7:::
deploy:$6$rounds=656000$dplysalt00$deployuserhashedpassword1234567890abcdef1234567890abcdef1234567890abcdef12345:19400:0:99999:7:::
postgres:$6$rounds=656000$pgsqlsalt$postgrespasswordhash1234567890abcdef1234567890abcdef1234567890abcdef123456789:19300:0:99999:7:::
`
}

// fakeStackTrace returns a realistic Go stack trace.
func fakeStackTrace() string {
	return `goroutine 847 [running]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:24 +0x5e
runtime/debug.PrintStack()
	/usr/local/go/src/runtime/debug/stack.go:16 +0x1a
main.panicHandler.func1()
	/opt/glitchapp/src/middleware/recovery.go:28 +0x82
panic({0xc000142000?, 0xc0004a6000?})
	/usr/local/go/src/runtime/panic.go:770 +0x132
database/sql.(*DB).connDBI(0xc0001e6000, {0x1a4f880, 0xc0003ba000})
	/usr/local/go/src/database/sql/sql.go:1384 +0x3ce
database/sql.(*DB).conn(0xc0001e6000, {0x1a4f880, 0xc0003ba000}, 0x1)
	/usr/local/go/src/database/sql/sql.go:1300 +0x125
database/sql.(*DB).query(0xc0001e6000, {0x1a4f880, 0xc0003ba000}, {0xc000292000, 0x3f}, {0xc0004a8040, 0x2, 0x2})
	/usr/local/go/src/database/sql/sql.go:1740 +0x98
database/sql.(*DB).QueryContext(0xc0001e6000, {0x1a4f880, 0xc0003ba000}, {0xc000292000, 0x3f}, {0xc0004a8040, 0x2, 0x2})
	/usr/local/go/src/database/sql/sql.go:1722 +0xd3
github.com/glitchapp/internal/repository.(*UserRepo).FindByEmail(0xc0002d4000, {0x1a4f880, 0xc0003ba000}, {0xc0004a2120, 0x1a})
	/opt/glitchapp/src/internal/repository/user_repo.go:87 +0x10e
github.com/glitchapp/internal/service.(*AuthService).ValidateCredentials(0xc0002dc000, {0x1a4f880, 0xc0003ba000}, {0xc0004a2120, 0x1a}, {0xc0004a2140, 0x8})
	/opt/glitchapp/src/internal/service/auth.go:142 +0x89
github.com/glitchapp/internal/handler.(*LoginHandler).Handle(0xc0002e0000, {0x1a52560, 0xc000134000}, 0xc000488300)
	/opt/glitchapp/src/internal/handler/login.go:34 +0x248
net/http.HandlerFunc.ServeHTTP(0xc000134000?, {0x1a52560?, 0xc000134000?}, 0xc000488300?)
	/usr/local/go/src/net/http/server.go:2166 +0x29
github.com/glitchapp/internal/middleware.(*AuthMiddleware).Handle.func1({0x1a52560, 0xc000134000}, 0xc000488300)
	/opt/glitchapp/src/internal/middleware/auth.go:51 +0x1ce
net/http.HandlerFunc.ServeHTTP(0xc000134000?, {0x1a52560?, 0xc000134000?}, 0xc000488300?)
	/usr/local/go/src/net/http/server.go:2166 +0x29
net/http.(*ServeMux).ServeHTTP(0xc0001ec0c0?, {0x1a52560, 0xc000134000}, 0xc000488300)
	/usr/local/go/src/net/http/server.go:2694 +0xf5
net/http.serverHandler.ServeHTTP({0xc0001f6000?}, {0x1a52560, 0xc000134000}, 0xc000488300)
	/usr/local/go/src/net/http/server.go:3137 +0x8e
net/http.(*conn).serve(0xc0003c4a20, {0x1a4f880, 0xc0003ba000})
	/usr/local/go/src/net/http/server.go:2039 +0x5b8
created by net/http.(*Server).Serve in goroutine 1
	/usr/local/go/src/net/http/server.go:3285 +0x4b8
`
}

// fakeAccessLog generates n lines of Apache Combined Log Format entries.
func fakeAccessLog(n int, rng *rand.Rand, firstNames []string) string {
	var sb strings.Builder
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	paths := []string{
		"/", "/index.html", "/login", "/api/v1/users", "/api/v1/data",
		"/admin", "/admin/users", "/admin/settings", "/dashboard",
		"/api/v1/auth/token", "/api/v1/export", "/static/app.js",
		"/static/style.css", "/images/logo.png", "/favicon.ico",
		"/api/v2/graphql", "/health", "/metrics", "/status",
		"/wp-login.php", "/wp-admin/", "/.env", "/.git/config",
		"/backup/db.sql.gz", "/phpmyadmin/", "/api/v1/users/1",
		"/api/v1/users/2", "/search?q=admin", "/config.yml",
	}
	statuses := []int{200, 200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 404, 500, 502, 503}
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"python-requests/2.31.0",
		"curl/8.4.0",
		"Go-http-client/1.1",
		"sqlmap/1.7.12#stable",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	}

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1)
		ts := time.Now().Add(-time.Duration(rng.Intn(86400)) * time.Second)
		method := methods[rng.Intn(len(methods))]
		path := paths[rng.Intn(len(paths))]
		status := statuses[rng.Intn(len(statuses))]
		size := rng.Intn(50000) + 200
		ua := uas[rng.Intn(len(uas))]
		user := "-"
		if rng.Intn(10) == 0 {
			user = firstNames[rng.Intn(len(firstNames))]
		}

		sb.WriteString(fmt.Sprintf("%s - %s [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n",
			ip, user, ts.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, size, ua))
	}
	return sb.String()
}

// fakeJWT creates an unsigned JWT token (alg: none) from claims.
func fakeJWT(claims map[string]interface{}) string {
	header := `{"alg":"none","typ":"JWT"}`
	payload := toJSON(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// alg:none means empty signature
	return headerB64 + "." + payloadB64 + "."
}

// fakeAWSMetadata returns fake EC2 instance metadata.
func fakeAWSMetadata() string {
	return `ami-id: ami-0abcdef1234567890
ami-launch-index: 0
ami-manifest-path: (unknown)
hostname: ip-10-0-1-42.ec2.internal
instance-action: none
instance-id: i-0abcdef1234567890
instance-life-cycle: on-demand
instance-type: m5.xlarge
local-hostname: ip-10-0-1-42.ec2.internal
local-ipv4: 10.0.1.42
mac: 02:42:ac:11:00:02
network/interfaces/macs/02:42:ac:11:00:02/vpc-id: vpc-0abc123def456
placement/availability-zone: us-east-1a
placement/region: us-east-1
profile: default
public-hostname: ec2-203-0-113-42.compute-1.amazonaws.com
public-ipv4: 203.0.113.42
security-groups: glitchapp-prod-sg
services/domain: amazonaws.com

# IAM Role Credentials (SSRF target)
iam/security-credentials/glitchapp-prod-role:
{
  "Code": "Success",
  "LastUpdated": "2024-11-20T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAXXXXXXXXXEXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBAaDHqa0AP6TfSBrng0oyLIAdKpRCuYcsVQX3mSbGXp...(truncated)",
  "Expiration": "2024-11-20T18:00:00Z"
}

# User Data (often contains bootstrap scripts with secrets)
user-data:
#!/bin/bash
export DB_PASSWORD="Pr0d_DB!2024#admin"
export API_SECRET="sk_live_4eC39HqLyjWDarjtT1zdp7dc"
export REDIS_AUTH="r3d!s_Pr0d_2024"
aws s3 cp s3://glitchapp-config/production.env /opt/glitchapp/.env
`
}

// fakePhpinfo returns a realistic phpinfo() HTML page.
func fakePhpinfo() string {
	return `<!DOCTYPE html>
<html>
<head><title>phpinfo()</title>
<style>
body {background-color: #fff; color: #222; font-family: sans-serif;}
pre {margin: 0; font-family: monospace;}
a:link {color: #009; text-decoration: none;}
a:hover {text-decoration: underline;}
table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}
.center {text-align: center;}
.center table {margin: 1em auto; text-align: left;}
.center th {text-align: center !important;}
td, th {border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}
th {position: sticky; top: 0; background: inherit;}
h1 {font-size: 150%;}
h2 {font-size: 125%;}
.p {text-align: left;}
.e {background-color: #ccf; width: 300px; font-weight: bold;}
.h {background-color: #99c; font-weight: bold;}
.v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
.v i {color: #999;}
img {float: right; border: 0;}
hr {width: 934px; background-color: #ccc; border: 0; height: 1px;}
</style>
</head>
<body>
<div class="center">
<table>
<tr class="h"><td>
<a href="http://www.php.net/"><img border="0" src="/phpinfo.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42" alt="PHP logo" /></a>
<h1 class="p">PHP Version 5.6.40</h1>
</td></tr>
</table>
<table>
<tr><td class="e">System</td><td class="v">Linux web-03.prod.internal 5.4.0-135-generic #152-Ubuntu SMP x86_64</td></tr>
<tr><td class="e">Build Date</td><td class="v">Jan 12 2019 13:28:09</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Virtual Directory Support</td><td class="v">disabled</td></tr>
<tr><td class="e">Configuration File (php.ini) Path</td><td class="v">/etc/php/5.6/apache2</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/5.6/apache2/php.ini</td></tr>
<tr><td class="e">PHP API</td><td class="v">20131106</td></tr>
<tr><td class="e">PHP Extension</td><td class="v">20131226</td></tr>
<tr><td class="e">Zend Extension</td><td class="v">220131226</td></tr>
<tr><td class="e">Zend Extension Build</td><td class="v">API220131226,NTS</td></tr>
<tr><td class="e">PHP Extension Build</td><td class="v">API20131226,NTS</td></tr>
<tr><td class="e">Debug Build</td><td class="v">no</td></tr>
<tr><td class="e">Thread Safety</td><td class="v">disabled</td></tr>
<tr><td class="e">Document Root</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">Server Root</td><td class="v">/etc/apache2</td></tr>
<tr><td class="e">DOCUMENT_ROOT</td><td class="v">/var/www/html</td></tr>
<tr><td class="e">SERVER_ADMIN</td><td class="v">admin@glitchapp.com</td></tr>
<tr><td class="e">REMOTE_PORT</td><td class="v">54321</td></tr>
<tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.29 (Ubuntu)</td></tr>
</table>
<h2>Environment</h2>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">HOSTNAME</td><td class="v">web-03.prod.internal</td></tr>
<tr><td class="e">DB_HOST</td><td class="v">db-prod-primary.internal.corp</td></tr>
<tr><td class="e">DB_PORT</td><td class="v">5432</td></tr>
<tr><td class="e">DB_NAME</td><td class="v">glitchapp_production</td></tr>
<tr><td class="e">DB_USER</td><td class="v">app_service_account</td></tr>
<tr><td class="e">DB_PASSWORD</td><td class="v">xK9#mP2$vL5nQ8wR!</td></tr>
<tr><td class="e">REDIS_URL</td><td class="v">redis://:r3d!s_Pr0d_2024@redis-01.internal.corp:6379/0</td></tr>
<tr><td class="e">SECRET_KEY</td><td class="v">super_secret_jwt_key_do_not_share_2024</td></tr>
<tr><td class="e">AWS_ACCESS_KEY_ID</td><td class="v">AKIAIOSFODNN7EXAMPLE</td></tr>
<tr><td class="e">AWS_SECRET_ACCESS_KEY</td><td class="v">wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>
<tr><td class="e">APP_ENV</td><td class="v">production</td></tr>
<tr><td class="e">DEBUG</td><td class="v">1</td></tr>
<tr><td class="e">SMTP_PASSWORD</td><td class="v">Sm7p_N0t!fy#2024</td></tr>
<tr><td class="e">STRIPE_SECRET_KEY</td><td class="v">sk_live_4eC39HqLyjWDarjtT1zdp7dc</td></tr>
<tr><td class="e">PATH</td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</td></tr>
</table>
<h2>PHP Credits</h2>
<table>
<tr class="h"><th colspan="2">PHP Authors</th></tr>
<tr><td class="e">PHP Group</td><td class="v">Thies C. Arntzen, Stig Bakken, Shane Caraveo, Andi Gutmans, ...</td></tr>
</table>
<h2>Loaded Extensions</h2>
<table>
<tr class="h"><th>Extension</th><th>Version</th></tr>
<tr><td class="e">mysql</td><td class="v">1.0 (DEPRECATED)</td></tr>
<tr><td class="e">mysqli</td><td class="v">0.1</td></tr>
<tr><td class="e">openssl</td><td class="v">OpenSSL 1.0.2g 1 Mar 2016 (VULNERABLE - Heartbleed patched but outdated)</td></tr>
<tr><td class="e">curl</td><td class="v">7.47.0</td></tr>
<tr><td class="e">json</td><td class="v">1.2.1</td></tr>
<tr><td class="e">xml</td><td class="v">2.9.3 (XXE enabled by default)</td></tr>
<tr><td class="e">mcrypt</td><td class="v">2.5.8 (DEPRECATED)</td></tr>
<tr><td class="e">session</td><td class="v">enabled</td></tr>
</table>
<h2>session</h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">session.cookie_httponly</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.cookie_secure</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.use_strict_mode</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.use_only_cookies</td><td class="v">0</td><td class="v">0</td></tr>
</table>
</div>
</body>
</html>`
}

// fakeComponents returns a list of "installed" components with known-vulnerable versions.
func fakeComponents() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "Apache HTTP Server", "version": "2.4.29", "latest": "2.4.62", "severity": "critical", "cves": []string{"CVE-2021-44790", "CVE-2021-41773", "CVE-2021-42013"}},
		{"name": "PHP", "version": "5.6.40", "latest": "8.3.14", "severity": "critical", "cves": []string{"CVE-2019-11043", "CVE-2024-4577"}},
		{"name": "OpenSSL", "version": "1.0.2g", "latest": "3.2.0", "severity": "critical", "cves": []string{"CVE-2016-2107", "CVE-2022-3602", "CVE-2022-3786"}},
		{"name": "jQuery", "version": "1.12.4", "latest": "3.7.1", "severity": "high", "cves": []string{"CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358"}},
		{"name": "Bootstrap", "version": "3.3.7", "latest": "5.3.2", "severity": "medium", "cves": []string{"CVE-2019-8331", "CVE-2018-14042"}},
		{"name": "Log4j", "version": "2.14.1", "latest": "2.22.0", "severity": "critical", "cves": []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}},
		{"name": "Spring Framework", "version": "5.2.8", "latest": "6.1.2", "severity": "critical", "cves": []string{"CVE-2022-22965", "CVE-2022-22950"}},
		{"name": "Jackson Databind", "version": "2.9.10", "latest": "2.16.1", "severity": "high", "cves": []string{"CVE-2020-36518", "CVE-2019-14540"}},
		{"name": "Lodash", "version": "4.17.15", "latest": "4.17.21", "severity": "high", "cves": []string{"CVE-2020-28500", "CVE-2021-23337"}},
		{"name": "Node.js", "version": "14.17.0", "latest": "21.5.0", "severity": "high", "cves": []string{"CVE-2023-44487", "CVE-2023-32002"}},
		{"name": "PostgreSQL", "version": "11.4", "latest": "16.1", "severity": "medium", "cves": []string{"CVE-2023-5868", "CVE-2023-5869"}},
		{"name": "Redis", "version": "5.0.7", "latest": "7.2.3", "severity": "medium", "cves": []string{"CVE-2022-35977", "CVE-2023-28856"}},
		{"name": "Nginx", "version": "1.14.0", "latest": "1.25.3", "severity": "high", "cves": []string{"CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516"}},
		{"name": "Moment.js", "version": "2.24.0", "latest": "2.30.1", "severity": "medium", "cves": []string{"CVE-2022-24785", "CVE-2022-31129"}},
		{"name": "Django", "version": "2.2.12", "latest": "5.0.1", "severity": "critical", "cves": []string{"CVE-2023-46695", "CVE-2023-43665"}},
		{"name": "Express.js", "version": "4.17.1", "latest": "4.18.2", "severity": "medium", "cves": []string{"CVE-2022-24999"}},
	}
}

// fakeUserAgent returns a random user agent string.
func fakeUserAgent(rng *rand.Rand) string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"python-requests/2.31.0",
		"curl/8.4.0",
	}
	return uas[rng.Intn(len(uas))]
}

// ---------------------------------------------------------------------------
// Helper: deterministic RNG from path
// ---------------------------------------------------------------------------

func (h *Handler) rngFromPath(path string) *rand.Rand {
	sum := sha256.Sum256([]byte(path))
	seed := int64(binary.BigEndian.Uint64(sum[:8]))
	return rand.New(rand.NewSource(seed))
}

// randomHex generates n hex characters from the given RNG.
func (h *Handler) randomHex(rng *rand.Rand, n int) string {
	return randomHexStatic(rng, n)
}

func randomHexStatic(rng *rand.Rand, n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[rng.Intn(len(hexChars))]
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Helper: HTML wrapper
// ---------------------------------------------------------------------------

func (h *Handler) wrapHTML(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s | Acme Corp Portal</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%%3E%%3Crect width='32' height='32' rx='6' fill='%%231a73e8'/%%3E%%3Ctext x='50%%%%' y='55%%%%' dominant-baseline='middle' text-anchor='middle' font-family='Arial' font-weight='700' font-size='18' fill='white'%%3EA%%3C/text%%3E%%3C/svg%%3E">
  <style>
    :root {
      --brand-primary: #1a73e8;
      --brand-dark: #1557b0;
      --brand-light: #e8f0fe;
      --nav-bg: #1e293b;
      --nav-hover: #334155;
      --sidebar-bg: #f8fafc;
      --sidebar-border: #e2e8f0;
      --sidebar-hover: #f1f5f9;
      --sidebar-active-bg: #e8f0fe;
      --sidebar-active-text: #1a73e8;
      --content-bg: #ffffff;
      --page-bg: #f1f5f9;
      --text-primary: #1e293b;
      --text-secondary: #475569;
      --text-muted: #94a3b8;
      --border-light: #e2e8f0;
      --border-medium: #cbd5e1;
      --success: #059669;
      --warning: #d97706;
      --danger: #dc2626;
      --info: #0284c7;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
      --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.05);
      --radius: 6px;
      --radius-lg: 8px;
    }
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: var(--page-bg); color: var(--text-primary); line-height: 1.6; font-size: 14px; -webkit-font-smoothing: antialiased; }

    /* ---- Top Navigation ---- */
    .topnav { background: var(--nav-bg); color: #fff; padding: 0 24px; display: flex; align-items: center; height: 52px; box-shadow: 0 1px 3px rgba(0,0,0,0.2); position: sticky; top: 0; z-index: 100; }
    .topnav .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; margin-right: 36px; color: #fff; text-decoration: none; letter-spacing: -0.3px; }
    .topnav .brand .brand-icon { width: 28px; height: 28px; background: var(--brand-primary); border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 15px; font-weight: 800; color: #fff; }
    .topnav .nav-links { display: flex; align-items: center; height: 100%%; gap: 2px; }
    .topnav .nav-links a { color: #94a3b8; text-decoration: none; padding: 0 14px; font-size: 13px; font-weight: 500; height: 52px; display: flex; align-items: center; transition: color 0.15s, background 0.15s; border-bottom: 2px solid transparent; position: relative; }
    .topnav .nav-links a:hover { color: #e2e8f0; background: var(--nav-hover); }
    .topnav .nav-links a.active { color: #fff; border-bottom-color: var(--brand-primary); }
    .topnav .nav-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
    .topnav .nav-right .nav-icon { color: #94a3b8; padding: 6px; border-radius: 6px; cursor: pointer; position: relative; transition: color 0.15s, background 0.15s; }
    .topnav .nav-right .nav-icon:hover { color: #e2e8f0; background: var(--nav-hover); }
    .topnav .nav-right .nav-icon .badge { position: absolute; top: 2px; right: 2px; width: 8px; height: 8px; background: #ef4444; border-radius: 50%%; border: 2px solid var(--nav-bg); }
    .topnav .user-menu { display: flex; align-items: center; gap: 8px; padding: 4px 12px 4px 4px; border-radius: 6px; cursor: pointer; transition: background 0.15s; position: relative; }
    .topnav .user-menu:hover { background: var(--nav-hover); }
    .topnav .user-menu .avatar { width: 30px; height: 30px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 50%%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600; color: #fff; }
    .topnav .user-menu .user-info { line-height: 1.3; }
    .topnav .user-menu .user-name { font-size: 13px; color: #e2e8f0; font-weight: 500; }
    .topnav .user-menu .user-role { font-size: 11px; color: #94a3b8; }
    .topnav .user-dropdown { display: none; position: absolute; top: 100%%; right: 0; background: #fff; border: 1px solid var(--border-light); border-radius: var(--radius-lg); box-shadow: var(--shadow-md); min-width: 200px; padding: 4px 0; z-index: 200; }
    .topnav .user-menu:hover .user-dropdown { display: block; }
    .topnav .user-dropdown a { display: flex; align-items: center; gap: 8px; padding: 8px 16px; color: var(--text-secondary); font-size: 13px; text-decoration: none; transition: background 0.1s; }
    .topnav .user-dropdown a:hover { background: var(--sidebar-hover); color: var(--text-primary); }
    .topnav .user-dropdown .divider { height: 1px; background: var(--border-light); margin: 4px 0; }
    .topnav .user-dropdown a.danger { color: var(--danger); }
    .topnav .user-dropdown a.danger:hover { background: #fef2f2; }

    /* ---- Layout ---- */
    .layout { display: flex; min-height: calc(100vh - 52px); }

    /* ---- Sidebar ---- */
    .sidebar { width: 240px; background: var(--sidebar-bg); border-right: 1px solid var(--sidebar-border); padding: 16px 0; flex-shrink: 0; overflow-y: auto; }
    .sidebar .section-label { padding: 18px 20px 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); font-weight: 600; }
    .sidebar .section-label:first-child { padding-top: 4px; }
    .sidebar .nav-item { display: flex; align-items: center; gap: 10px; padding: 8px 20px; color: var(--text-secondary); text-decoration: none; font-size: 13px; font-weight: 450; transition: all 0.12s; border-left: 3px solid transparent; margin: 1px 0; }
    .sidebar .nav-item:hover { background: var(--sidebar-hover); color: var(--text-primary); }
    .sidebar .nav-item.active { background: var(--sidebar-active-bg); color: var(--sidebar-active-text); border-left-color: var(--brand-primary); font-weight: 550; }
    .sidebar .nav-item .icon { width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; font-size: 14px; opacity: 0.7; }
    .sidebar .nav-item .item-badge { margin-left: auto; background: #fef3c7; color: #92400e; font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 10px; }
    .sidebar .nav-item .item-badge.info { background: #dbeafe; color: #1e40af; }
    .sidebar .nav-item .item-badge.success { background: #d1fae5; color: #065f46; }

    /* ---- Main Content ---- */
    .main-content { flex: 1; padding: 24px 32px; min-width: 0; }
    .breadcrumbs { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-muted); margin-bottom: 20px; }
    .breadcrumbs a { color: var(--text-secondary); text-decoration: none; transition: color 0.1s; }
    .breadcrumbs a:hover { color: var(--brand-primary); text-decoration: underline; }
    .breadcrumbs .sep { color: var(--border-medium); font-size: 11px; }
    .page-header { margin-bottom: 24px; }
    .page-header h1 { font-size: 22px; font-weight: 650; color: var(--text-primary); letter-spacing: -0.3px; }
    .page-header .subtitle { font-size: 14px; color: var(--text-muted); margin-top: 4px; }

    /* ---- Typography ---- */
    h1, h2, h3, h4 { color: var(--text-primary); }
    h1 { font-size: 22px; font-weight: 650; margin-bottom: 16px; letter-spacing: -0.3px; }
    h2 { font-size: 17px; font-weight: 600; margin: 24px 0 12px; }
    h3 { font-size: 15px; font-weight: 600; margin: 18px 0 8px; }
    a { color: var(--brand-primary); text-decoration: none; }
    a:hover { text-decoration: underline; }
    p { margin-bottom: 12px; color: var(--text-secondary); }

    /* ---- Tables ---- */
    table { width: 100%%; border-collapse: collapse; margin: 12px 0; background: var(--content-bg); border-radius: var(--radius-lg); overflow: hidden; box-shadow: var(--shadow-sm); border: 1px solid var(--border-light); }
    td, th { border: none; border-bottom: 1px solid var(--border-light); padding: 10px 14px; text-align: left; font-size: 13px; }
    th { background: var(--sidebar-bg); color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f8fafc; }

    /* ---- Code ---- */
    pre, code { background: #f8fafc; padding: 2px 6px; border-radius: 4px; font-size: 12.5px; overflow-x: auto; font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', 'Cascadia Code', Consolas, monospace; color: var(--text-primary); }
    pre { padding: 16px; display: block; border: 1px solid var(--border-light); border-radius: var(--radius-lg); line-height: 1.7; }

    /* ---- Cards ---- */
    .card { background: var(--content-bg); border-radius: var(--radius-lg); padding: 20px; box-shadow: var(--shadow-sm); border: 1px solid var(--border-light); margin-bottom: 16px; }
    .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-light); }
    .card-header h3 { margin: 0; font-size: 14px; font-weight: 600; }

    /* ---- Alerts ---- */
    .warning { background: #fffbeb; border: 1px solid #fde68a; border-left: 4px solid var(--warning); padding: 12px 16px; margin: 12px 0; border-radius: 0 var(--radius) var(--radius) 0; color: #92400e; font-size: 13px; }
    .admin-bar { background: var(--content-bg); padding: 12px 16px; margin: 12px 0; border: 1px solid var(--border-light); border-radius: var(--radius-lg); }
    .error-detail { background: var(--content-bg); padding: 16px; border: 1px solid var(--border-light); border-radius: var(--radius-lg); }
    .stacktrace { color: var(--danger); font-size: 12px; white-space: pre-wrap; }

    /* ---- Misc ---- */
    .result { border-bottom: 1px solid var(--border-light); padding: 12px 0; }
    ul { line-height: 1.8; padding-left: 20px; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .tag-success { background: #d1fae5; color: #065f46; }
    .tag-warning { background: #fef3c7; color: #92400e; }
    .tag-danger { background: #fee2e2; color: #991b1b; }
    .tag-info { background: #dbeafe; color: #1e40af; }

    /* ---- Footer ---- */
    .footer { background: var(--nav-bg); color: #94a3b8; padding: 20px 32px; font-size: 12px; }
    .footer-inner { max-width: 1280px; }
    .footer-top { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 16px; border-bottom: 1px solid #334155; margin-bottom: 12px; }
    .footer-brand { font-size: 14px; font-weight: 600; color: #e2e8f0; margin-bottom: 4px; }
    .footer-tagline { font-size: 12px; color: #64748b; }
    .footer-links { display: flex; gap: 20px; flex-wrap: wrap; }
    .footer-links a { color: #94a3b8; text-decoration: none; font-size: 12px; transition: color 0.1s; }
    .footer-links a:hover { color: #e2e8f0; }
    .footer-bottom { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
    .footer-copy { color: #64748b; }
    .footer-version { color: #475569; font-family: monospace; font-size: 11px; }

    /* ---- Responsive ---- */
    @media (max-width: 1024px) {
      .sidebar { width: 200px; }
      .main-content { padding: 20px 24px; }
    }
    @media (max-width: 768px) {
      .sidebar { display: none; }
      .main-content { padding: 16px; }
      .topnav .nav-links a { padding: 0 8px; font-size: 12px; }
    }
  </style>
</head>
<body>
  <!-- Top Navigation -->
  <nav class="topnav">
    <a href="/vuln/" class="brand">
      <span class="brand-icon">A</span>
      Acme Corp
    </a>
    <div class="nav-links">
      <a href="/vuln/dashboard/">Dashboard</a>
      <a href="/vuln/a01/">Users</a>
      <a href="/vuln/settings/">Settings</a>
      <a href="/vuln/a09/">Reports</a>
      <a href="/vuln/dashboard/api-keys">API Docs</a>
    </div>
    <div class="nav-right">
      <span class="nav-icon" title="Notifications">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
        <span class="badge"></span>
      </span>
      <span class="nav-icon" title="Help">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      </span>
      <div class="user-menu">
        <span class="avatar">AD</span>
        <div class="user-info">
          <div class="user-name">admin@acme.com</div>
          <div class="user-role">Administrator</div>
        </div>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
        <div class="user-dropdown">
          <a href="/vuln/a01/users/1">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            My Profile
          </a>
          <a href="/vuln/settings/">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            Account Settings
          </a>
          <a href="/vuln/settings/audit">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            Audit Log
          </a>
          <div class="divider"></div>
          <a href="/vuln/a07/" class="danger">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Sign Out
          </a>
        </div>
      </div>
    </div>
  </nav>

  <!-- Main Layout -->
  <div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="section-label">Management</div>
      <a href="/vuln/a01/" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg></span>
        Users
        <span class="item-badge">248</span>
      </a>
      <a href="/vuln/a01/admin-panel" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
        Roles
      </a>
      <a href="/vuln/a04/" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/></svg></span>
        Departments
      </a>

      <div class="section-label">System</div>
      <a href="/vuln/a05/" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg></span>
        Configuration
      </a>
      <a href="/vuln/settings/integrations" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
        Integrations
        <span class="item-badge info">3</span>
      </a>
      <a href="/vuln/settings/audit" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
        Audit Log
        <span class="item-badge success">New</span>
      </a>

      <div class="section-label">Security</div>
      <a href="/vuln/settings/certificates" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></span>
        Certificates
      </a>
      <a href="/vuln/dashboard/api-keys" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg></span>
        API Keys
      </a>
      <a href="/vuln/a02/" class="nav-item">
        <span class="icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
        Access Control
      </a>
    </aside>

    <!-- Content Area -->
    <main class="main-content">
      <div class="breadcrumbs">
        <a href="/vuln/">Home</a>
        <span class="sep">/</span>
        <a href="/vuln/">Portal</a>
        <span class="sep">/</span>
        <span>%s</span>
      </div>
      <div class="page-header">
        <h1>%s</h1>
      </div>
      %s
    </main>
  </div>

  <!-- Footer -->
  <footer class="footer">
    <div class="footer-inner">
      <div class="footer-top">
        <div>
          <div class="footer-brand">Acme Corporation</div>
          <div class="footer-tagline">Enterprise Management Portal</div>
        </div>
        <div class="footer-links">
          <a href="/vuln/a08/">Terms of Service</a>
          <a href="/vuln/a03/">Privacy Policy</a>
          <a href="/vuln/dashboard/api-keys">API Documentation</a>
          <a href="/vuln/dashboard/server-status">System Status</a>
        </div>
      </div>
      <div class="footer-bottom">
        <span class="footer-copy">&copy; 2024 Acme Corporation. All rights reserved.</span>
        <span class="footer-version">v3.2.1-build.4521</span>
      </div>
    </div>
  </footer>
</body>
</html>`, title, title, title, body)
}

// ---------------------------------------------------------------------------
// Helper: JSON serialization (stdlib-only, no encoding/json import needed)
// ---------------------------------------------------------------------------

func toJSON(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		parts := make([]string, 0, len(val))
		for k, v2 := range val {
			parts = append(parts, fmt.Sprintf("%q:%s", k, toJSON(v2)))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []map[string]interface{}:
		parts := make([]string, len(val))
		for i, m := range val {
			parts[i] = toJSON(m)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []string:
		parts := make([]string, len(val))
		for i, s := range val {
			parts[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return fmt.Sprintf("%q", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%.2f", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%q", fmt.Sprintf("%v", val))
	}
}
