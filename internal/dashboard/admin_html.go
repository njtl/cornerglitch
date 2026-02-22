package dashboard

import "fmt"

// ---------------------------------------------------------------------------
// Admin HTML page — self-contained, dark hacker theme
// ---------------------------------------------------------------------------

var adminPage = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glitch Server Admin Panel</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Courier New', monospace;
    background: #0a0a0a;
    color: #00ff88;
    padding: 20px;
    min-height: 100vh;
  }
  h1 {
    color: #00ffcc;
    margin-bottom: 6px;
    text-shadow: 0 0 10px #00ffcc44;
    font-size: 1.5em;
  }
  .subtitle {
    color: #666;
    font-size: 0.8em;
    margin-bottom: 20px;
  }
  h2 {
    color: #00ccaa;
    margin: 0 0 12px;
    font-size: 1.05em;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  a { color: #44aaff; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    border-bottom: 1px solid #00ff8833;
    padding-bottom: 8px;
    flex-wrap: wrap;
  }
  .tab {
    padding: 8px 18px;
    background: #111;
    border: 1px solid #00ff8822;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    color: #888;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.85em;
    transition: all 0.2s;
  }
  .tab:hover { color: #00ff88; background: #1a1a1a; }
  .tab.active {
    color: #00ffcc;
    background: #1a1a1a;
    border-color: #00ff8844;
  }
  .panel { display: none; }
  .panel.active { display: block; }

  /* Cards */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .card {
    background: #111;
    border: 1px solid #00ff8833;
    border-radius: 8px;
    padding: 14px;
  }
  .card .label {
    color: #888;
    font-size: 0.75em;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .card .value {
    font-size: 1.6em;
    font-weight: bold;
    margin-top: 4px;
  }
  .v-ok { color: #00ff88; }
  .v-warn { color: #ffaa00; }
  .v-err { color: #ff4444; }
  .v-info { color: #4488ff; }

  /* Section */
  .section {
    background: #111;
    border: 1px solid #00ff8822;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 18px;
  }

  /* Tables */
  table { width: 100%%; border-collapse: collapse; margin: 8px 0; }
  th, td {
    padding: 7px 10px;
    text-align: left;
    border-bottom: 1px solid #1a1a1a;
    font-size: 0.82em;
  }
  th {
    color: #00ccaa;
    background: #0d0d0d;
    position: sticky;
    top: 0;
    z-index: 1;
    font-weight: normal;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 0.75em;
  }
  tr:hover { background: #1a1a1a; }

  /* Status colors */
  .s2 { color: #00ff88; }
  .s4 { color: #ffaa00; }
  .s5 { color: #ff4444; }

  /* Mode colors */
  .m-normal { color: #00ff88; }
  .m-aggressive { color: #ff4444; }
  .m-labyrinth { color: #aa44ff; }
  .m-escalating { color: #ffaa00; }
  .m-cooperative { color: #44aaff; }
  .m-intermittent { color: #ff8844; }
  .m-mirror { color: #44ffaa; }

  /* Sparkline */
  .sparkline-wrap {
    width: 100%%;
    height: 80px;
    position: relative;
    background: #0d0d0d;
    border-radius: 4px;
    overflow: hidden;
  }
  .spark-bar {
    position: absolute;
    bottom: 0;
    background: #00ff88;
    min-width: 2px;
    border-radius: 1px 1px 0 0;
    transition: height 0.3s;
  }
  .spark-bar.err { background: #ff4444; }

  /* Pie chart (CSS) */
  .pie-wrap {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .pie-canvas { width: 140px; height: 140px; }
  .pie-legend { font-size: 0.8em; line-height: 1.8; }
  .pie-legend span {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 2px;
    margin-right: 6px;
    vertical-align: middle;
  }

  /* Toggle switches */
  .toggle-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
  }
  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #0d0d0d;
    border: 1px solid #222;
    border-radius: 6px;
    padding: 10px 14px;
  }
  .toggle-name {
    font-size: 0.85em;
    color: #ccc;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .toggle-sw {
    position: relative;
    width: 44px;
    height: 24px;
    cursor: pointer;
  }
  .toggle-sw input { display: none; }
  .toggle-track {
    position: absolute;
    inset: 0;
    background: #333;
    border-radius: 12px;
    transition: background 0.25s;
  }
  .toggle-sw input:checked + .toggle-track { background: #00aa66; }
  .toggle-knob {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    background: #ccc;
    border-radius: 50%%;
    transition: transform 0.25s;
  }
  .toggle-sw input:checked ~ .toggle-knob { transform: translateX(20px); background: #00ff88; }

  /* Sliders */
  .slider-group { margin-bottom: 16px; }
  .slider-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.82em;
    color: #aaa;
    margin-bottom: 4px;
  }
  .slider-label .val { color: #00ffcc; font-weight: bold; }

  /* Error weight radio grid */
  .ew-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 4px;
  }
  .ew-row {
    display: flex;
    align-items: center;
    gap: 6px;
    background: #0d0d0d;
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 0.78em;
  }
  .ew-name {
    width: 110px;
    color: #aaa;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ew-opts { display: flex; gap: 2px; flex: 1; }
  .ew-opt {
    padding: 2px 7px;
    border-radius: 3px;
    cursor: pointer;
    color: #555;
    border: 1px solid #222;
    font-size: 0.9em;
    transition: all 0.15s;
    text-align: center;
  }
  .ew-opt:hover { color: #aaa; border-color: #444; }
  .ew-opt input { display: none; }
  .ew-opt.active { color: #00ff88; background: #0a2a1a; border-color: #00ff8844; }

  input[type="range"] {
    -webkit-appearance: none;
    width: 100%%;
    height: 6px;
    background: #333;
    border-radius: 3px;
    outline: none;
  }
  input[type="range"]::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 16px;
    height: 16px;
    background: #00ff88;
    border-radius: 50%%;
    cursor: pointer;
  }
  input[type="range"]::-moz-range-thumb {
    width: 16px;
    height: 16px;
    background: #00ff88;
    border-radius: 50%%;
    cursor: pointer;
    border: none;
  }

  /* Search box */
  .search-box {
    width: 100%%;
    padding: 8px 14px;
    background: #0d0d0d;
    border: 1px solid #00ff8833;
    border-radius: 6px;
    color: #00ff88;
    font-family: inherit;
    font-size: 0.85em;
    margin-bottom: 12px;
    outline: none;
  }
  .search-box::placeholder { color: #555; }
  .search-box:focus { border-color: #00ff8866; }

  /* Scrollable table wrapper */
  .tbl-scroll {
    max-height: 420px;
    overflow-y: auto;
  }
  .tbl-scroll::-webkit-scrollbar { width: 6px; }
  .tbl-scroll::-webkit-scrollbar-track { background: #111; }
  .tbl-scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }

  /* Row highlight for log */
  .log-row td { font-size: 0.78em; }

  /* Mini bar chart for distributions */
  .bar-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
    font-size: 0.82em;
  }
  .bar-label { width: 120px; text-align: right; color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; height: 14px; background: #1a1a1a; border-radius: 3px; overflow: hidden; }
  .bar-fill { height: 100%%; background: #00ff88; border-radius: 3px; transition: width 0.3s; }
  .bar-count { width: 50px; color: #888; font-size: 0.9em; }

  /* Toast */
  .toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #00aa66;
    color: #000;
    padding: 10px 20px;
    border-radius: 6px;
    font-size: 0.85em;
    font-weight: bold;
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.3s;
    z-index: 9999;
    pointer-events: none;
  }
  .toast.show { opacity: 1; transform: translateY(0); }

  /* Severity badges */
  .sev { padding: 2px 8px; border-radius: 10px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
  .sev-critical { background: #ff2244; color: #fff; }
  .sev-high { background: #ff8800; color: #000; }
  .sev-medium { background: #ffcc00; color: #000; }
  .sev-low { background: #4488ff; color: #fff; }
  .sev-info { background: #444; color: #aaa; }

  /* Grade display */
  .grade { font-size: 4em; font-weight: bold; text-align: center; padding: 20px; }
  .grade-a { color: #00ff88; }
  .grade-b { color: #88ff00; }
  .grade-c { color: #ffcc00; }
  .grade-d { color: #ff8800; }
  .grade-f { color: #ff2244; }

  /* Progress bars */
  .prog-bar { height: 20px; background: #1a1a1a; border-radius: 4px; overflow: hidden; margin: 4px 0; }
  .prog-fill { height: 100%%; border-radius: 4px; transition: width 0.5s; }
  .prog-green { background: linear-gradient(90deg, #00aa66, #00ff88); }
  .prog-red { background: linear-gradient(90deg, #aa2200, #ff4444); }
  .prog-yellow { background: linear-gradient(90deg, #aa8800, #ffcc00); }

  /* Scanner controls */
  .scanner-btn { background: #00aa66; color: #000; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-family: inherit; font-weight: bold; font-size: 0.85em; margin: 4px; }
  .scanner-btn:hover { background: #00cc77; }
  .scanner-btn:disabled { background: #333; color: #666; cursor: not-allowed; }
  .scanner-btn.running { background: #ffaa00; animation: pulse 1s infinite; }
  @keyframes pulse { 0%%,100%% { opacity:1; } 50%% { opacity:0.6; } }

  /* Vuln table */
  .vuln-status-active { color: #00ff88; }
  .vuln-status-disabled { color: #666; }
  .vuln-endpoint { font-size: 0.75em; color: #44aaff; margin: 1px 0; display: block; }
  .vuln-endpoint:hover { color: #88ccff; }

  /* Scanner panels */
  .scanner-panel { background: #0d0d0d; border: 1px solid #222; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .scanner-panel h3 { color: #00ccaa; font-size: 0.9em; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }
  .scanner-select, .scanner-textarea {
    background: #111; color: #00ff88; border: 1px solid #333; border-radius: 4px;
    padding: 8px 12px; font-family: inherit; font-size: 0.85em; width: 100%%;
  }
  .scanner-select { width: auto; min-width: 160px; }
  .scanner-textarea { min-height: 120px; resize: vertical; margin: 8px 0; }

  /* Findings table */
  .findings-tbl { margin-top: 8px; }
  .findings-tbl td { font-size: 0.78em; }
  .findings-tbl .found { color: #00ff88; }
  .findings-tbl .missed { color: #ff4444; }
  .findings-tbl .false-pos { color: #ffaa00; }

  /* Group toggle */
  .group-toggles { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
  .group-toggle {
    display: flex; align-items: center; gap: 8px;
    background: #0d0d0d; border: 1px solid #222; border-radius: 6px; padding: 8px 14px;
  }
  .group-toggle .toggle-name { font-size: 0.82em; }

  /* Select dropdown */
  .ctrl-select {
    background: #0d0d0d; color: #00ff88; border: 1px solid #333;
    padding: 6px 12px; border-radius: 4px; font-family: inherit; font-size: 0.85em;
    width: 100%%;
  }

  /* Config buttons */
  .cfg-btn { background: #333; color: #ccc; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.85em; margin: 4px; }
  .cfg-btn:hover { background: #444; }
  .cfg-btn.primary { background: #00aa66; color: #000; font-weight: bold; }
  .cfg-btn.primary:hover { background: #00cc77; }
</style>
</head>
<body>

<h1>// GLITCH ADMIN PANEL</h1>
<div class="subtitle">Control center for the glitch web server</div>

<div class="tabs">
  <button class="tab active" onclick="showTab('dashboard')">Dashboard</button>
  <button class="tab" onclick="showTab('sessions')">Sessions</button>
  <button class="tab" onclick="showTab('traffic')">Traffic</button>
  <button class="tab" onclick="showTab('controls')">Controls</button>
  <button class="tab" onclick="showTab('log')">Request Log</button>
  <button class="tab" onclick="showTab('vulns')">Vulnerabilities</button>
  <button class="tab" onclick="showTab('scanner')">Scanner</button>
</div>

<!-- ==================== DASHBOARD TAB ==================== -->
<div id="panel-dashboard" class="panel active">
  <div class="grid" id="dash-metrics"></div>

  <div class="section">
    <h2>// Throughput (last 60s)</h2>
    <div class="sparkline-wrap" id="dash-sparkline"></div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Connected Clients</h2>
      <div class="tbl-scroll" style="max-height:300px">
        <table>
          <thead><tr>
            <th>Client</th><th>Requests</th><th>Req/s</th><th>Errors</th><th>Mode</th>
          </tr></thead>
          <tbody id="dash-clients-body"></tbody>
        </table>
      </div>
    </div>
    <div class="section">
      <h2>// Recent Requests</h2>
      <div class="tbl-scroll" style="max-height:300px">
        <table>
          <thead><tr>
            <th>Time</th><th>Client</th><th>Path</th><th>Status</th><th>Type</th>
          </tr></thead>
          <tbody id="dash-recent-body"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- ==================== SESSIONS TAB ==================== -->
<div id="panel-sessions" class="panel">
  <div class="section">
    <h2>// Active Client Sessions</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:10px">Click a client ID to view details and set behavior overrides.</p>
    <div class="tbl-scroll">
      <table>
        <thead><tr>
          <th>Client ID</th>
          <th>Requests</th>
          <th>Req/s</th>
          <th>Errors</th>
          <th>Paths</th>
          <th>Lab Depth</th>
          <th>Mode</th>
          <th>Last Seen</th>
          <th>Actions</th>
        </tr></thead>
        <tbody id="sess-body"></tbody>
      </table>
    </div>
  </div>
  <div class="section" id="client-detail" style="display:none">
    <h2>// Client Detail: <span id="detail-cid" style="color:#00ffcc"></span></h2>
    <div class="grid" id="detail-cards"></div>
    <div style="margin:12px 0">
      <label style="color:#aaa;font-size:0.85em">Override Mode:</label>
      <select id="override-mode" style="background:#0d0d0d;color:#00ff88;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;margin:0 8px">
        <option value="">-- auto --</option>
        <option value="normal">Normal</option>
        <option value="cooperative">Cooperative</option>
        <option value="aggressive">Aggressive</option>
        <option value="labyrinth">Labyrinth</option>
        <option value="escalating">Escalating</option>
        <option value="intermittent">Intermittent</option>
        <option value="mirror">Mirror</option>
        <option value="blocked">Blocked</option>
      </select>
      <button onclick="applyOverride()" style="background:#00aa66;color:#000;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:bold">Apply</button>
      <button onclick="clearOverride()" style="background:#333;color:#ccc;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;margin-left:4px">Clear</button>
    </div>
    <div id="detail-paths" style="max-height:200px;overflow-y:auto"></div>
  </div>
</div>

<!-- ==================== TRAFFIC TAB ==================== -->
<div id="panel-traffic" class="panel">
  <div class="grid" id="overview-cards"></div>

  <div class="section">
    <h2>// Requests/sec (last 60s)</h2>
    <div class="sparkline-wrap" id="sparkline"></div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Status Code Distribution</h2>
      <div class="pie-wrap">
        <canvas class="pie-canvas" id="pie-status" width="140" height="140"></canvas>
        <div class="pie-legend" id="pie-legend"></div>
      </div>
    </div>
    <div class="section">
      <h2>// Response Type Distribution</h2>
      <div id="resp-type-bars"></div>
    </div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Top 10 Paths</h2>
      <div id="top-paths"></div>
    </div>
    <div class="section">
      <h2>// Top 10 User Agents</h2>
      <div id="top-ua"></div>
    </div>
  </div>
</div>

<!-- ==================== CONTROLS TAB ==================== -->
<div id="panel-controls" class="panel">
  <div class="section">
    <h2>// Feature Toggles</h2>
    <div class="toggle-grid" id="toggles"></div>
  </div>

  <div class="section">
    <h2>// Depth &amp; Rate Controls</h2>
    <div id="sliders"></div>
  </div>

  <div class="section">
    <h2>// Error Weight Distribution</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:8px">Select preset level for each error type. Weights are normalized automatically.</p>
    <div class="ew-grid" id="error-weight-grid"></div>
    <button class="cfg-btn" onclick="resetErrorWeights()" style="margin-top:8px">Reset All to Default</button>
  </div>

  <div class="section">
    <h2>// Page Type Distribution</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:8px">Control the probability of each response page type. Set to 0 to disable.</p>
    <div class="ew-grid" id="page-type-grid"></div>
    <button class="cfg-btn" onclick="resetPageTypeWeights()" style="margin-top:8px">Reset to Default</button>
  </div>

  <div class="section">
    <h2>// Advanced Controls</h2>
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px;">
      <div>
        <div class="slider-label"><span>Honeypot Response Style</span></div>
        <select id="ctrl-honeypot-style" class="ctrl-select" onchange="setConfigKey('honeypot_response_style', this.value)">
          <option value="realistic">Realistic</option>
          <option value="verbose">Verbose</option>
          <option value="minimal">Minimal</option>
          <option value="deceptive">Deceptive</option>
        </select>
      </div>
      <div>
        <div class="slider-label"><span>Active Framework</span></div>
        <select id="ctrl-framework" class="ctrl-select" onchange="setConfigKey('active_framework', this.value)">
          <option value="auto">Auto (rotate)</option>
          <option value="express">Express.js</option>
          <option value="django">Django</option>
          <option value="rails">Ruby on Rails</option>
          <option value="laravel">Laravel</option>
          <option value="spring">Spring Boot</option>
          <option value="aspnet">ASP.NET</option>
          <option value="flask">Flask</option>
          <option value="fastapi">FastAPI</option>
          <option value="next">Next.js</option>
          <option value="nginx">nginx</option>
          <option value="apache">Apache</option>
          <option value="caddy">Caddy</option>
        </select>
      </div>
      <div>
        <div class="slider-label"><span>Content Theme</span></div>
        <select id="ctrl-theme" class="ctrl-select" onchange="setConfigKey('content_theme', this.value)">
          <option value="default">Default</option>
          <option value="corporate">Corporate</option>
          <option value="blog">Blog</option>
          <option value="ecommerce">E-Commerce</option>
          <option value="news">News Portal</option>
          <option value="forum">Forum</option>
        </select>
      </div>
      <div>
        <div id="advanced-sliders"></div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>// Configuration Import / Export</h2>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <button class="cfg-btn primary" onclick="exportConfig()">Export Config</button>
      <button class="cfg-btn" onclick="document.getElementById('cfg-import-file').click()">Import Config</button>
      <input type="file" id="cfg-import-file" accept=".json" style="display:none" onchange="importConfigFile(this)">
    </div>
    <div id="cfg-import-status" style="color:#888;font-size:0.82em"></div>
  </div>
</div>

<!-- ==================== REQUEST LOG TAB ==================== -->
<div id="panel-log" class="panel">
  <div class="section">
    <h2>// Request Log (last 200)</h2>
    <input type="text" class="search-box" id="log-filter" placeholder="Filter by status, client, path, type..." oninput="filterLog()">
    <div class="tbl-scroll" style="max-height: 600px;">
      <table>
        <thead><tr>
          <th>Time</th>
          <th>Client</th>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Latency</th>
          <th>Type</th>
          <th>Mode</th>
          <th>User Agent</th>
        </tr></thead>
        <tbody id="log-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== VULNERABILITIES TAB ==================== -->
<div id="panel-vulns" class="panel">
  <div class="section">
    <h2>// Vulnerability Profile Overview</h2>
    <div class="grid" id="vuln-overview-cards">
      <div class="card"><div class="label">Loading...</div><div class="value v-info">--</div></div>
    </div>
  </div>

  <div class="section">
    <h2>// Group Toggles</h2>
    <div class="group-toggles" id="vuln-group-toggles"></div>
  </div>

  <div class="section">
    <h2>// Severity Breakdown</h2>
    <div id="vuln-severity-badges" style="margin-bottom:12px"></div>
  </div>

  <div class="section">
    <h2>// All Vulnerability Endpoints</h2>
    <input type="text" class="search-box" id="vuln-filter" placeholder="Filter by name, severity, CWE, category..." oninput="filterVulns()">
    <div class="tbl-scroll" style="max-height: 600px;">
      <table>
        <thead><tr>
          <th>Name</th>
          <th>Severity</th>
          <th>CWE</th>
          <th>Category</th>
          <th>Endpoints</th>
          <th>Status</th>
        </tr></thead>
        <tbody id="vuln-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== SCANNER TAB ==================== -->
<div id="panel-scanner" class="panel">

  <!-- Expected Profile panel -->
  <div class="section">
    <h2>// Expected Profile</h2>
    <button class="scanner-btn" onclick="generateProfile()">Generate Profile</button>
    <div id="scanner-profile-summary" style="margin-top:14px">
      <div style="color:#555">Click "Generate Profile" to load the current vulnerability profile.</div>
    </div>
  </div>

  <!-- Scanner Results panel -->
  <div class="section">
    <h2>// Scanner Results</h2>
    <div class="scanner-panel">
      <h3>Select Scanner</h3>
      <select id="scanner-type" class="scanner-select">
        <option value="nuclei">Nuclei</option>
        <option value="nikto">Nikto</option>
        <option value="nmap">Nmap</option>
        <option value="ffuf">ffuf</option>
        <option value="wapiti">Wapiti</option>
        <option value="generic">Generic</option>
      </select>
    </div>

    <div class="scanner-panel">
      <h3>Upload / Paste Results</h3>
      <textarea id="scanner-output" class="scanner-textarea" placeholder="Paste scanner output here..."></textarea>
      <button class="scanner-btn" onclick="uploadResults()">Upload &amp; Compare</button>
    </div>

    <div class="scanner-panel">
      <h3>Run Scanner</h3>
      <p style="color:#888;font-size:0.82em;margin-bottom:8px">Launch a scanner against this server (requires tool to be installed on host).</p>
      <div id="scanner-run-btns">
        <button class="scanner-btn" onclick="runScanner('nuclei')">nuclei</button>
        <button class="scanner-btn" onclick="runScanner('nikto')">nikto</button>
        <button class="scanner-btn" onclick="runScanner('nmap')">nmap</button>
        <button class="scanner-btn" onclick="runScanner('ffuf')">ffuf</button>
        <button class="scanner-btn" onclick="runScanner('wapiti')">wapiti</button>
      </div>
      <div id="scanner-run-status" style="margin-top:8px;color:#555;font-size:0.82em"></div>
    </div>
  </div>

  <!-- Comparison Report panel -->
  <div class="section">
    <h2>// Comparison Report</h2>
    <div id="scanner-comparison">
      <div style="color:#555">No comparison data yet. Upload scanner results or run a scan.</div>
    </div>
  </div>

  <!-- History panel -->
  <div class="section">
    <h2>// Scan History</h2>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead><tr>
          <th>Timestamp</th>
          <th>Scanner</th>
          <th>Grade</th>
          <th>Detection</th>
          <th>Status</th>
        </tr></thead>
        <tbody id="scanner-history-body"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(function(){
  const API = window.location.protocol + '//' + window.location.hostname + ':' + window.location.port;
  let logData = [];

  // ------ Tabs with hash routing ------
  window.showTab = function(name, pushHash) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('panel-' + name).classList.add('active');
    document.querySelector('.tab[onclick*="' + name + '"]').classList.add('active');
    if (pushHash !== false) window.location.hash = '#' + name;
  };

  window.addEventListener('hashchange', function() {
    var tab = window.location.hash.replace('#', '');
    if (tab && document.getElementById('panel-' + tab)) showTab(tab, false);
  });

  // ------ Toast ------
  function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 1800);
  }

  // ------ Helpers ------
  async function api(path, opts) {
    const res = await fetch(API + path, opts);
    return res.json();
  }

  function sClass(code) {
    if (code >= 500) return 's5';
    if (code >= 400) return 's4';
    return 's2';
  }

  function mClass(mode) { return 'm-' + (mode || 'normal'); }

  function shortID(id) { return (id || '').substring(0, 16); }
  function shortUA(ua) { return (ua || '').substring(0, 50); }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function card(label, value, cls) {
    return '<div class="card"><div class="label">' + label + '</div><div class="value ' + cls + '">' + value + '</div></div>';
  }

  function fmtUptime(sec) {
    if (!sec) return '0s';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec %% 3600) / 60);
    const s = sec %% 60;
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
  }

  function timeSince(iso) {
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s/60) + 'm ago';
    return Math.floor(s/3600) + 'h ago';
  }

  // ------ Dashboard Tab ------
  async function refreshDashboard() {
    try {
      const [m, ts, cl, rc] = await Promise.all([
        api('/api/metrics'),
        api('/api/timeseries'),
        api('/api/clients'),
        api('/api/recent')
      ]);

      // Metrics cards
      document.getElementById('dash-metrics').innerHTML =
        card('Total Requests', (m.total_requests||0).toLocaleString(), 'v-ok') +
        card('Active Connections', m.active_connections||0, 'v-info') +
        card('2xx', (m.total_2xx||0).toLocaleString(), 'v-ok') +
        card('4xx', (m.total_4xx||0).toLocaleString(), 'v-warn') +
        card('5xx', (m.total_5xx||0).toLocaleString(), 'v-err') +
        card('Error Rate', ((m.error_rate_pct||0).toFixed(1)) + '%%', (m.error_rate_pct||0) > 10 ? 'v-err' : 'v-ok') +
        card('Labyrinth Hits', (m.total_labyrinth||0).toLocaleString(), 'v-info') +
        card('Unique Clients', m.unique_clients||0, 'v-info') +
        card('Uptime', fmtUptime(m.uptime_seconds), 'v-ok');

      // Sparkline
      const series = ts.series || [];
      const wrap = document.getElementById('dash-sparkline');
      if (series.length > 0) {
        const maxR = Math.max(...series.map(s => s.requests), 1);
        const bw = Math.max(2, Math.floor(wrap.clientWidth / series.length) - 1);
        wrap.innerHTML = series.map((s, i) => {
          const h = Math.max(2, (s.requests / maxR) * 100);
          const cls = s.errors > 0 ? 'spark-bar err' : 'spark-bar';
          return '<div class="' + cls + '" style="left:' + (i*(bw+1)) + 'px;width:' + bw + 'px;height:' + h + '%%;" title="' + s.requests + ' req"></div>';
        }).join('');
      }

      // Clients table
      const clients = (cl.clients || []).sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
      document.getElementById('dash-clients-body').innerHTML = clients.slice(0, 20).map(c =>
        '<tr>' +
        '<td>' + escapeHtml(shortID(c.client_id)) + '</td>' +
        '<td>' + c.total_requests + '</td>' +
        '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
        '<td>' + c.errors_received + '</td>' +
        '<td class="' + mClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
        '</tr>'
      ).join('');

      // Recent requests
      const records = (rc.records || []).slice(0, 30);
      document.getElementById('dash-recent-body').innerHTML = records.map(r =>
        '<tr class="log-row">' +
        '<td>' + new Date(r.timestamp).toLocaleTimeString() + '</td>' +
        '<td>' + escapeHtml(shortID(r.client_id)) + '</td>' +
        '<td title="' + escapeHtml(r.path) + '">' + escapeHtml(r.path.substring(0, 30)) + '</td>' +
        '<td class="' + sClass(r.status_code) + '">' + r.status_code + '</td>' +
        '<td>' + escapeHtml(r.response_type) + '</td>' +
        '</tr>'
      ).join('');
    } catch(e) { console.error('dashboard:', e); }
  }

  // ------ Sessions ------
  let selectedClient = null;
  async function refreshSessions() {
    try {
      const data = await api('/api/clients');
      const clients = (data.clients || []);
      clients.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
      const tbody = document.getElementById('sess-body');
      tbody.innerHTML = clients.map(c => {
        const ago = timeSince(c.last_seen);
        const cid = escapeHtml(c.client_id);
        const short = escapeHtml(shortID(c.client_id));
        return '<tr>' +
          '<td><a href="#" onclick="viewClient(\'' + cid + '\');return false" style="color:#44aaff">' + short + '</a></td>' +
          '<td>' + c.total_requests + '</td>' +
          '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
          '<td class="' + (c.errors_received > 0 ? 's5' : '') + '">' + c.errors_received + '</td>' +
          '<td>' + c.unique_paths + '</td>' +
          '<td>' + (c.labyrinth_depth||0) + '</td>' +
          '<td class="' + mClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
          '<td style="color:#888">' + ago + '</td>' +
          '<td><a href="#" onclick="viewClient(\'' + cid + '\');return false" style="color:#888;font-size:0.8em">details</a></td>' +
          '</tr>';
      }).join('');
    } catch(e) { console.error('sessions:', e); }
  }

  window.viewClient = async function(clientID) {
    selectedClient = clientID;
    try {
      const detail = await api('/admin/api/client/' + encodeURIComponent(clientID));
      document.getElementById('client-detail').style.display = 'block';
      document.getElementById('detail-cid').textContent = shortID(clientID);
      document.getElementById('detail-cards').innerHTML =
        card('Total Requests', detail.total_requests, 'v-ok') +
        card('Req/s', (detail.requests_per_sec||0).toFixed(1), 'v-info') +
        card('Errors', detail.errors_received, detail.errors_received > 0 ? 'v-err' : 'v-ok') +
        card('Unique Paths', detail.unique_paths, 'v-info') +
        card('Mode', detail.adaptive_mode || 'pending', 'v-warn') +
        card('Bot Score', (detail.bot_score||0).toFixed(1), detail.bot_score > 60 ? 'v-err' : 'v-ok') +
        card('Escalation', detail.escalation_level, 'v-warn') +
        card('Lab Depth', detail.labyrinth_depth, 'v-info');

      const paths = (detail.all_paths || []).slice(0, 20);
      if (paths.length > 0) {
        const maxC = paths[0].count || 1;
        document.getElementById('detail-paths').innerHTML = '<h2 style="margin-top:12px">// Top Paths</h2>' +
          paths.map(p =>
            '<div class="bar-row">' +
            '<div class="bar-label" title="' + escapeHtml(p.path) + '">' + escapeHtml(p.path.substring(0,40)) + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxC*100) + '%%"></div></div>' +
            '<div class="bar-count">' + p.count + '</div></div>'
          ).join('');
      }

      if (detail.adaptive_reason) {
        document.getElementById('detail-paths').innerHTML +=
          '<div style="margin-top:10px;color:#888;font-size:0.85em">Reason: ' + escapeHtml(detail.adaptive_reason) + '</div>';
      }
    } catch(e) { console.error('viewClient:', e); toast('Client not found'); }
  };

  window.applyOverride = async function() {
    if (!selectedClient) return;
    const mode = document.getElementById('override-mode').value;
    if (!mode) { toast('Select a mode first'); return; }
    await api('/admin/api/override', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({client_id: selectedClient, mode: mode})
    });
    toast('Override applied: ' + mode);
    viewClient(selectedClient);
  };

  window.clearOverride = async function() {
    if (!selectedClient) return;
    await api('/admin/api/override', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({client_id: selectedClient, clear: true})
    });
    toast('Override cleared');
    viewClient(selectedClient);
  };

  // ------ Traffic Overview ------
  async function refreshTraffic() {
    try {
      const ov = await api('/admin/api/overview');

      const total = ov.total_requests || 0;
      const errs = ov.total_errors || 0;
      const errPct = total > 0 ? (errs/total*100).toFixed(1) : '0.0';
      document.getElementById('overview-cards').innerHTML =
        card('Total Requests', total.toLocaleString(), 'v-ok') +
        card('Total Errors', errs.toLocaleString(), 'v-err') +
        card('Error Rate', errPct + '%%', parseFloat(errPct) > 10 ? 'v-err' : 'v-ok') +
        card('Uptime', fmtUptime(ov.uptime_seconds), 'v-info');

      const spark = ov.sparkline || [];
      const wrap = document.getElementById('sparkline');
      if (spark.length > 0) {
        const maxR = Math.max(...spark.map(s => s.requests), 1);
        const bw = Math.max(2, Math.floor(wrap.clientWidth / spark.length) - 1);
        wrap.innerHTML = spark.map((s, i) => {
          const h = Math.max(2, (s.requests / maxR) * 100);
          const cls = s.errors > 0 ? 'spark-bar err' : 'spark-bar';
          return '<div class="' + cls + '" style="left:' + (i*(bw+1)) + 'px;width:' + bw + 'px;height:' + h + '%%;" title="' + s.requests + ' req"></div>';
        }).join('');
      }

      drawPie(ov.status_codes || []);

      const types = ov.response_types || [];
      const maxT = types.length > 0 ? types[0].count : 1;
      document.getElementById('resp-type-bars').innerHTML = types.map(t =>
        '<div class="bar-row">' +
        '<div class="bar-label">' + escapeHtml(t.key || 'unknown') + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (t.count/maxT*100) + '%%"></div></div>' +
        '<div class="bar-count">' + t.count + '</div>' +
        '</div>'
      ).join('');

      const paths = ov.top_paths || [];
      const maxP = paths.length > 0 ? paths[0].count : 1;
      document.getElementById('top-paths').innerHTML = paths.map(p =>
        '<div class="bar-row">' +
        '<div class="bar-label" title="' + escapeHtml(p.key) + '">' + escapeHtml(p.key.substring(0, 30)) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxP*100) + '%%"></div></div>' +
        '<div class="bar-count">' + p.count + '</div>' +
        '</div>'
      ).join('') || '<div style="color:#555">No data yet</div>';

      const uas = ov.top_user_agents || [];
      const maxU = uas.length > 0 ? uas[0].count : 1;
      document.getElementById('top-ua').innerHTML = uas.map(u =>
        '<div class="bar-row">' +
        '<div class="bar-label" title="' + escapeHtml(u.key) + '">' + escapeHtml(u.key.substring(0, 30)) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (u.count/maxU*100) + '%%"></div></div>' +
        '<div class="bar-count">' + u.count + '</div>' +
        '</div>'
      ).join('') || '<div style="color:#555">No data yet</div>';
    } catch(e) { console.error('traffic:', e); }
  }

  const PIE_COLORS = ['#00ff88','#ffaa00','#ff4444','#4488ff','#aa44ff','#ff8844','#44ffaa','#ff44aa'];
  function drawPie(codes) {
    const canvas = document.getElementById('pie-status');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 70, cy = 70, r = 60;
    ctx.clearRect(0, 0, 140, 140);

    if (codes.length === 0) {
      ctx.fillStyle = '#222';
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI*2); ctx.fill();
      document.getElementById('pie-legend').innerHTML = '<div style="color:#555">No data</div>';
      return;
    }

    codes.sort((a, b) => a.code - b.code);
    const total = codes.reduce((s, c) => s + c.count, 0);
    let angle = -Math.PI / 2;
    let legend = '';

    codes.forEach((c, i) => {
      const slice = (c.count / total) * Math.PI * 2;
      const color = PIE_COLORS[i %% PIE_COLORS.length];
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
      legend += '<div><span style="background:' + color + '"></span>' + c.code + ': ' + c.count + ' (' + (c.count/total*100).toFixed(0) + '%%)</div>';
      angle += slice;
    });

    document.getElementById('pie-legend').innerHTML = legend;
  }

  // ------ Controls ------
  const FEATURE_LABELS = {
    labyrinth: 'Labyrinth',
    error_inject: 'Error Injection',
    captcha: 'CAPTCHA',
    honeypot: 'Honeypot',
    vuln: 'Vulnerability Endpoints',
    analytics: 'Analytics Tracking',
    cdn: 'CDN Emulation',
    oauth: 'OAuth Endpoints',
    header_corrupt: 'Header Corruption',
    cookie_traps: 'Cookie Traps',
    js_traps: 'JS Traps',
    bot_detection: 'Bot Detection',
    random_blocking: 'Random Blocking',
    framework_emul: 'Framework Emulation',
    search: 'Search Engine',
    email: 'Email/Webmail',
    i18n: 'Internationalization',
    recorder: 'Traffic Recorder',
    websocket: 'WebSocket',
    privacy: 'Privacy/Consent',
    health: 'Health Endpoints'
  };

  const ERROR_TYPES = [
    'none','500','502','503','504','404','403','429','408',
    'redirect_loop','empty_body','truncated','garbage',
    'slow_drip','delay_short','delay_long','header_only',
    'content_mismatch','encoding_mess','double_encode',
    'infinite_redirect','partial_content',
    'packet_drop','tcp_reset','stream_corrupt','session_timeout',
    'keepalive_abuse','tls_half_close','slow_headers','accept_then_fin'
  ];

  async function refreshControls() {
    try {
      const features = await api('/admin/api/features');
      const el = document.getElementById('toggles');
      el.innerHTML = Object.keys(FEATURE_LABELS).map(key => {
        const on = features[key] ? 'checked' : '';
        return '<div class="toggle-row">' +
          '<div class="toggle-name">' + FEATURE_LABELS[key] + '</div>' +
          '<label class="toggle-sw">' +
          '<input type="checkbox" ' + on + ' onchange="toggleFeature(\'' + key + '\', this.checked)">' +
          '<div class="toggle-track"></div>' +
          '<div class="toggle-knob"></div>' +
          '</label></div>';
      }).join('');

      const cfg = await api('/admin/api/config');
      document.getElementById('sliders').innerHTML =
        slider('max_labyrinth_depth', 'Max Labyrinth Depth', cfg.max_labyrinth_depth, 1, 100, 1) +
        slider('error_rate_multiplier', 'Error Rate Multiplier', cfg.error_rate_multiplier, 0, 5, 0.1) +
        slider('captcha_trigger_thresh', 'CAPTCHA Trigger Threshold', cfg.captcha_trigger_thresh, 0, 500, 1) +
        slider('block_chance', 'Random Block Chance', cfg.block_chance, 0, 1, 0.01) +
        slider('block_duration_sec', 'Block Duration (sec)', cfg.block_duration_sec, 1, 3600, 1) +
        slider('bot_score_threshold', 'Bot Score Threshold', cfg.bot_score_threshold, 0, 100, 1) +
        slider('header_corrupt_level', 'Header Corruption Level (0-4)', cfg.header_corrupt_level, 0, 4, 1) +
        slider('delay_min_ms', 'Delay Min (ms)', cfg.delay_min_ms, 0, 10000, 100) +
        slider('delay_max_ms', 'Delay Max (ms)', cfg.delay_max_ms, 0, 30000, 100) +
        slider('labyrinth_link_density', 'Labyrinth Links/Page', cfg.labyrinth_link_density, 1, 20, 1) +
        slider('adaptive_interval_sec', 'Adaptive Re-eval Interval (sec)', cfg.adaptive_interval_sec, 5, 300, 5);

      // Advanced sliders
      document.getElementById('advanced-sliders').innerHTML =
        slider('cookie_trap_frequency', 'Cookie Trap Frequency', cfg.cookie_trap_frequency || 3, 0, 20, 1) +
        slider('js_trap_difficulty', 'JS Trap Difficulty', cfg.js_trap_difficulty || 2, 0, 5, 1) +
        slider('content_cache_ttl_sec', 'Content Cache TTL (sec)', cfg.content_cache_ttl_sec || 60, 0, 3600, 10) +
        slider('adaptive_aggressive_rps', 'Adaptive Aggressive RPS', cfg.adaptive_aggressive_rps || 10, 1, 100, 1) +
        slider('adaptive_labyrinth_paths', 'Adaptive Labyrinth Paths', cfg.adaptive_labyrinth_paths || 5, 1, 50, 1);

      // Dropdowns
      if (cfg.honeypot_response_style) {
        var sel = document.getElementById('ctrl-honeypot-style');
        if (sel) sel.value = cfg.honeypot_response_style;
      }
      if (cfg.active_framework) {
        var sel2 = document.getElementById('ctrl-framework');
        if (sel2) sel2.value = cfg.active_framework;
      }
      if (cfg.content_theme) {
        var sel3 = document.getElementById('ctrl-theme');
        if (sel3) sel3.value = cfg.content_theme;
      }

      // Error weights
      refreshErrorWeights();
      // Page type weights
      refreshPageTypeWeights();
    } catch(e) { console.error('controls:', e); }
  }

  const EW_PRESETS = [
    {label:'OFF', value:0},
    {label:'LOW', value:0.01},
    {label:'MED', value:0.05},
    {label:'HIGH', value:0.15},
    {label:'MAX', value:0.5}
  ];

  async function refreshErrorWeights() {
    try {
      const data = await api('/admin/api/error-weights');
      const weights = data.weights || {};
      const el = document.getElementById('error-weight-grid');
      el.innerHTML = ERROR_TYPES.map(t => {
        var val = weights[t] !== undefined ? weights[t] : 0;
        return ewRow(t, val);
      }).join('');
    } catch(e) { console.error('error-weights:', e); }
  }

  function ewRow(name, value) {
    var closest = 0;
    var minDist = 999;
    EW_PRESETS.forEach(function(p, i) {
      var d = Math.abs(p.value - value);
      if (d < minDist) { minDist = d; closest = i; }
    });
    var opts = EW_PRESETS.map(function(p, i) {
      var active = i === closest ? ' active' : '';
      return '<label class="ew-opt' + active + '" onclick="ewSelect(\'' + name + '\',' + p.value + ',this)">' +
        '<input type="radio" name="ew-' + name + '"' + (i === closest ? ' checked' : '') + '>' +
        p.label + '</label>';
    }).join('');
    var displayName = name.replace(/_/g, ' ');
    return '<div class="ew-row"><span class="ew-name" title="' + name + '">' + displayName + '</span><div class="ew-opts">' + opts + '</div></div>';
  }

  window.ewSelect = function(name, val, el) {
    var row = el.closest('.ew-row');
    row.querySelectorAll('.ew-opt').forEach(function(o) { o.classList.remove('active'); });
    el.classList.add('active');
    api('/admin/api/error-weights', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({error_type: name, weight: val})
    }).then(() => toast(name + ': ' + (val === 0 ? 'off' : val)));
  };

  window.resetErrorWeights = function() {
    api('/admin/api/error-weights', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({reset: true})
    }).then(() => { toast('Error weights reset'); refreshErrorWeights(); });
  };

  // Page type weight controls
  const PAGE_TYPES = ['html','json','xml','csv','markdown','sse','websocket','graphql'];
  const PT_PRESETS = [
    {label:'OFF', value:0},
    {label:'LOW', value:0.05},
    {label:'MED', value:0.15},
    {label:'HIGH', value:0.3},
    {label:'MAX', value:0.5}
  ];

  async function refreshPageTypeWeights() {
    try {
      const data = await api('/admin/api/page-type-weights');
      const weights = data.weights || {};
      const el = document.getElementById('page-type-grid');
      el.innerHTML = PAGE_TYPES.map(function(t) {
        var val = weights[t] !== undefined ? weights[t] : 0;
        return ptRow(t, val);
      }).join('');
    } catch(e) { console.error('page-type-weights:', e); }
  }

  function ptRow(name, value) {
    var closest = 0;
    var minDist = 999;
    PT_PRESETS.forEach(function(p, i) {
      var d = Math.abs(p.value - value);
      if (d < minDist) { minDist = d; closest = i; }
    });
    var opts = PT_PRESETS.map(function(p, i) {
      var active = i === closest ? ' active' : '';
      return '<label class="ew-opt' + active + '" onclick="ptSelect(\'' + name + '\',' + p.value + ',this)">' +
        '<input type="radio" name="pt-' + name + '"' + (i === closest ? ' checked' : '') + '>' +
        p.label + '</label>';
    }).join('');
    return '<div class="ew-row"><span class="ew-name" title="' + name + '">' + name.toUpperCase() + '</span><div class="ew-opts">' + opts + '</div></div>';
  }

  window.ptSelect = function(name, val, el) {
    var row = el.closest('.ew-row');
    row.querySelectorAll('.ew-opt').forEach(function(o) { o.classList.remove('active'); });
    el.classList.add('active');
    api('/admin/api/page-type-weights', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({page_type: name, weight: val})
    }).then(() => toast(name + ': ' + (val === 0 ? 'off' : val)));
  };

  window.resetPageTypeWeights = function() {
    api('/admin/api/page-type-weights', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({reset: true})
    }).then(() => { toast('Page type weights reset'); refreshPageTypeWeights(); });
  };

  window.setConfigKey = function(key, val) {
    api('/admin/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: key, value: val})
    }).then(() => toast(key + ' updated'));
  };

  function slider(key, label, value, min, max, step) {
    const isFloat = step < 1;
    const display = isFloat ? parseFloat(value).toFixed(1) : parseInt(value);
    return '<div class="slider-group">' +
      '<div class="slider-label"><span>' + label + '</span><span class="val" id="sv-' + key + '">' + display + '</span></div>' +
      '<input type="range" min="' + min + '" max="' + max + '" step="' + step + '" value="' + value + '" oninput="sliderChange(\'' + key + '\', this.value, ' + isFloat + ')" onchange="sliderCommit(\'' + key + '\', this.value)">' +
      '</div>';
  }

  let sliderTimer = {};
  window.sliderChange = function(key, val, isFloat) {
    document.getElementById('sv-' + key).textContent = isFloat ? parseFloat(val).toFixed(1) : parseInt(val);
  };

  window.sliderCommit = function(key, val) {
    clearTimeout(sliderTimer[key]);
    sliderTimer[key] = setTimeout(() => {
      api('/admin/api/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key: key, value: parseFloat(val)})
      }).then(() => toast(key + ' updated'));
    }, 300);
  };

  window.toggleFeature = function(name, enabled) {
    api('/admin/api/features', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({feature: name, enabled: enabled})
    }).then(() => toast(name + (enabled ? ' enabled' : ' disabled')));
  };

  // ------ Request Log ------
  async function refreshLog() {
    try {
      const data = await api('/admin/api/log?limit=200');
      logData = data.records || [];
      renderLog(logData);
    } catch(e) { console.error('log:', e); }
  }

  function renderLog(records) {
    const tbody = document.getElementById('log-body');
    tbody.innerHTML = records.map(r => {
      return '<tr class="log-row" data-search="' + escapeHtml((r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent).toLowerCase()) + '">' +
        '<td>' + new Date(r.timestamp).toLocaleTimeString() + '</td>' +
        '<td>' + escapeHtml(shortID(r.client_id)) + '</td>' +
        '<td>' + r.method + '</td>' +
        '<td title="' + escapeHtml(r.path) + '">' + escapeHtml(r.path.substring(0, 45)) + '</td>' +
        '<td class="' + sClass(r.status_code) + '">' + r.status_code + '</td>' +
        '<td>' + r.latency_ms + 'ms</td>' +
        '<td>' + escapeHtml(r.response_type) + '</td>' +
        '<td class="' + mClass(r.mode) + '">' + (r.mode || '-') + '</td>' +
        '<td title="' + escapeHtml(r.user_agent || '') + '">' + escapeHtml(shortUA(r.user_agent)) + '</td>' +
        '</tr>';
    }).join('');
  }

  window.filterLog = function() {
    const q = document.getElementById('log-filter').value.toLowerCase().trim();
    if (!q) {
      renderLog(logData);
      return;
    }
    const filtered = logData.filter(r => {
      const haystack = (r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent + ' ' + r.mode).toLowerCase();
      return haystack.indexOf(q) !== -1;
    });
    renderLog(filtered);
  };

  // ------ Vulnerabilities Tab ------
  let vulnData = [];
  let vulnProfile = null;

  async function refreshVulns() {
    try {
      const [profile, vc] = await Promise.all([
        api('/admin/api/scanner/profile'),
        api('/admin/api/vulns')
      ]);
      vulnProfile = profile;
      var p = profile.profile || profile;
      vulnData = p.vulnerabilities || p.vulns || [];

      var ebt = p.endpoints_by_type || {};
      var cats = {owasp: 0, advanced: 0, dashboard: 0};
      vulnData.forEach(function(v) {
        if (v.owasp) cats.owasp++;
        else if (v.id && v.id.startsWith('dashboard')) cats.dashboard++;
        else cats.advanced++;
      });
      const sev = p.by_severity || p.severity_counts || {};
      document.getElementById('vuln-overview-cards').innerHTML =
        card('OWASP Top 10', cats.owasp || 0, 'v-err') +
        card('Advanced Vulns', cats.advanced || 0, 'v-warn') +
        card('Dashboard Vulns', cats.dashboard || 0, 'v-info') +
        card('Total Vulns', p.total_vulns || 0, 'v-ok') +
        card('Total Endpoints', p.total_endpoints || 0, 'v-info');

      // Group toggles
      var groups = vc.groups || {};
      document.getElementById('vuln-group-toggles').innerHTML =
        ['owasp', 'advanced', 'dashboard'].map(g => {
          var on = groups[g] !== false ? 'checked' : '';
          return '<div class="group-toggle">' +
            '<div class="toggle-name">' + g.toUpperCase() + '</div>' +
            '<label class="toggle-sw">' +
            '<input type="checkbox" ' + on + ' onchange="toggleVulnGroup(\'' + g + '\', this.checked)">' +
            '<div class="toggle-track"></div>' +
            '<div class="toggle-knob"></div>' +
            '</label></div>';
        }).join('');

      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      document.getElementById('vuln-severity-badges').innerHTML = sevOrder.map(function(s) {
        return '<span class="sev sev-' + s + '" style="margin-right:10px">' + s + ': ' + (sev[s] || 0) + '</span>';
      }).join('');

      renderVulnTable(vulnData, vc.categories || {});
    } catch(e) { console.error('vulns:', e); }
  }

  function renderVulnTable(vulns, catState) {
    var mainPort = 8765;
    var tbody = document.getElementById('vuln-body');
    tbody.innerHTML = vulns.map(function(v) {
      var endpoints = (v.endpoints || []).map(function(ep) {
        return '<a class="vuln-endpoint" href="http://' + window.location.hostname + ':' + mainPort + ep + '" target="_blank" title="' + escapeHtml(ep) + '">' + escapeHtml(ep.length > 60 ? ep.substring(0, 57) + '...' : ep) + '</a>';
      }).join('');
      var catEnabled = catState[v.id] !== false;
      var isActive = v.active !== false && v.detectable !== false;
      var statusClass = (isActive && catEnabled) ? 'vuln-status-active' : 'vuln-status-disabled';
      var statusText = (isActive && catEnabled) ? 'ACTIVE' : 'DISABLED';
      var toggleBtn = '<label class="toggle-sw" style="display:inline-block;vertical-align:middle;margin-left:8px">' +
        '<input type="checkbox" ' + (catEnabled ? 'checked' : '') + ' onchange="toggleVulnCat(\'' + escapeHtml(v.id || v.name) + '\', this.checked)">' +
        '<div class="toggle-track"></div>' +
        '<div class="toggle-knob"></div>' +
        '</label>';
      return '<tr>' +
        '<td>' + escapeHtml(v.name) + '</td>' +
        '<td><span class="sev sev-' + v.severity + '">' + v.severity + '</span></td>' +
        '<td style="color:#888">' + escapeHtml(v.cwe || '') + '</td>' +
        '<td>' + escapeHtml(v.owasp || v.category || v.id || '') + '</td>' +
        '<td>' + endpoints + '</td>' +
        '<td><span class="' + statusClass + '">' + statusText + '</span>' + toggleBtn + '</td>' +
        '</tr>';
    }).join('');
  }

  window.toggleVulnGroup = function(group, enabled) {
    api('/admin/api/vulns/group', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({group: group, enabled: enabled})
    }).then(() => { toast(group + (enabled ? ' enabled' : ' disabled')); refreshVulns(); });
  };

  window.toggleVulnCat = function(id, enabled) {
    api('/admin/api/vulns', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: id, enabled: enabled})
    }).then(() => toast(id + (enabled ? ' enabled' : ' disabled')));
  };

  window.filterVulns = function() {
    var q = document.getElementById('vuln-filter').value.toLowerCase().trim();
    if (!q) {
      renderVulnTable(vulnData, {});
      return;
    }
    var filtered = vulnData.filter(function(v) {
      var haystack = (v.name + ' ' + v.severity + ' ' + v.cwe + ' ' + v.category + ' ' + (v.endpoints || []).join(' ')).toLowerCase();
      return haystack.indexOf(q) !== -1;
    });
    renderVulnTable(filtered, {});
  };

  // ------ Config Import/Export ------
  window.exportConfig = async function() {
    try {
      const res = await fetch(API + '/admin/api/config/export');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'glitch-config-' + new Date().toISOString().slice(0,10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
      toast('Config exported');
    } catch(e) { console.error('export:', e); toast('Export failed'); }
  };

  window.importConfigFile = async function(input) {
    if (!input.files || !input.files[0]) return;
    const file = input.files[0];
    const text = await file.text();
    try {
      const result = await api('/admin/api/config/import', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: text
      });
      document.getElementById('cfg-import-status').innerHTML =
        '<span style="color:#00ff88">Config imported successfully. ' + (result.message || '') + '</span>';
      toast('Config imported');
      refreshControls();
    } catch(e) {
      document.getElementById('cfg-import-status').innerHTML =
        '<span style="color:#ff4444">Import failed: ' + escapeHtml(e.message) + '</span>';
    }
    input.value = '';
  };

  // ------ Scanner Tab ------
  let scanPollTimer = null;

  window.generateProfile = async function() {
    try {
      var profile = await api('/admin/api/scanner/profile');
      vulnProfile = profile;
      var sev = profile.severity_counts || {};
      var metrics = profile.expected_metrics || {};

      var sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      var sevHtml = sevOrder.map(function(s) {
        return '<span class="sev sev-' + s + '" style="margin-right:10px">' + s + ': ' + (sev[s] || 0) + '</span>';
      }).join('');

      var html = '<div class="grid">' +
        card('Total Vulns', profile.total_vulns || 0, 'v-ok') +
        card('Total Endpoints', profile.total_endpoints || 0, 'v-info') +
        card('OWASP', (profile.category_counts || {}).owasp || 0, 'v-err') +
        card('Advanced', (profile.category_counts || {}).advanced || 0, 'v-warn') +
        card('Dashboard', (profile.category_counts || {}).dashboard || 0, 'v-info') +
        '</div>' +
        '<div style="margin:12px 0">' + sevHtml + '</div>' +
        '<div style="margin-top:14px">' +
        '<h3 style="color:#00ccaa;font-size:0.85em;margin-bottom:8px">EXPECTED BEHAVIOR METRICS</h3>' +
        metricBar('Error Rate', metrics.error_rate || 0, 'prog-red') +
        metricBar('Labyrinth Rate', metrics.labyrinth_rate || 0, 'prog-yellow') +
        metricBar('Block Rate', metrics.block_rate || 0, 'prog-red') +
        metricBar('CAPTCHA Rate', metrics.captcha_rate || 0, 'prog-yellow') +
        '</div>';

      document.getElementById('scanner-profile-summary').innerHTML = html;
      toast('Profile generated');
    } catch(e) { console.error('generateProfile:', e); toast('Failed to generate profile'); }
  };

  function metricBar(label, value, cls) {
    var pct = Math.min(value * 100, 100).toFixed(1);
    return '<div style="margin:6px 0">' +
      '<div style="display:flex;justify-content:space-between;font-size:0.82em;color:#aaa"><span>' + label + '</span><span style="color:#00ffcc">' + pct + '%%</span></div>' +
      '<div class="prog-bar"><div class="prog-fill ' + cls + '" style="width:' + pct + '%%"></div></div>' +
      '</div>';
  }

  window.runScanner = async function(name) {
    document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ffaa00">Starting ' + escapeHtml(name) + '...</span>';
    try {
      var result = await api('/admin/api/scanner/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scanner: name, target: 'http://' + window.location.hostname + ':8765'})
      });
      if (result.status === 'error') {
        document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ff4444">' + escapeHtml(result.error || result.message || 'Scanner not found') + '</span>';
        return;
      }
      if (result.status === 'already_running') {
        document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ffaa00">' + escapeHtml(name) + ' is already running</span>';
        return;
      }
      toast(name + ' scan started');
      startScanPolling();
    } catch(e) {
      document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ff4444">Error: ' + escapeHtml(e.message) + '</span>';
    }
  };

  function startScanPolling() {
    if (scanPollTimer) return;
    scanPollTimer = setInterval(pollScannerStatus, 1500);
    pollScannerStatus();
  }

  async function pollScannerStatus() {
    try {
      var data = await api('/admin/api/scanner/results');
      var running = data.running || [];
      var completed = data.completed || [];

      // Update running status
      var statusEl = document.getElementById('scanner-run-status');
      if (running.length > 0) {
        statusEl.innerHTML = running.map(function(r) {
          return '<div style="margin:4px 0"><span style="color:#ffaa00">&#9654; ' + escapeHtml(r.scanner) + '</span> ' +
            '<span style="color:#888">' + escapeHtml(r.status) + ' (' + escapeHtml(r.elapsed) + ')</span> ' +
            '<button class="scanner-btn" style="padding:2px 10px;font-size:0.75em" onclick="stopScanner(\'' + escapeHtml(r.scanner) + '\')">Stop</button></div>';
        }).join('');

        // Disable run buttons while scan is active
        document.querySelectorAll('#scanner-run-btns .scanner-btn').forEach(function(btn) {
          var name = btn.textContent.trim();
          var isRunning = running.some(function(r) { return r.scanner === name; });
          if (isRunning) { btn.classList.add('running'); btn.disabled = true; }
          else { btn.classList.remove('running'); btn.disabled = false; }
        });
      } else {
        if (scanPollTimer) {
          clearInterval(scanPollTimer);
          scanPollTimer = null;
          statusEl.innerHTML = '<span style="color:#00ff88">No scans running</span>';
          document.querySelectorAll('#scanner-run-btns .scanner-btn').forEach(function(btn) {
            btn.classList.remove('running'); btn.disabled = false;
          });
        }
      }

      // Update history from server
      renderServerHistory(completed, running);

      // Show latest completed comparison report
      if (completed.length > 0) {
        var latest = completed[completed.length - 1];
        if (latest.Comparison) renderComparison(latest.Comparison);
        else if (latest.Result) renderScanResult(latest);
      }
    } catch(e) { console.error('pollScanner:', e); }
  }

  window.stopScanner = async function(name) {
    try {
      await api('/admin/api/scanner/stop', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scanner: name})
      });
      toast(name + ' stopped');
      pollScannerStatus();
    } catch(e) { toast('Failed to stop scanner'); }
  };

  window.uploadResults = async function() {
    var scanner = document.getElementById('scanner-type').value;
    var data = document.getElementById('scanner-output').value;
    if (!data.trim()) { toast('Paste scanner output first'); return; }

    try {
      var report = await api('/admin/api/scanner/compare', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scanner: scanner, data: data})
      });
      renderComparison(report);
      toast('Comparison complete: grade ' + (report.grade || '?'));
      pollScannerStatus();
    } catch(e) {
      console.error('uploadResults:', e);
      toast('Comparison failed');
    }
  };

  function renderScanResult(run) {
    var r = run.Result || {};
    var html = '<div class="grid">' +
      card('Scanner', escapeHtml(run.Scanner || ''), 'v-info') +
      card('Status', escapeHtml(run.Status || ''), run.Status === 'completed' ? 'v-ok' : 'v-err') +
      card('Duration', escapeHtml(run.Duration || '-'), 'v-info') +
      card('Findings', (r.Findings || []).length, 'v-warn') +
      card('Exit Code', run.ExitCode || 0, run.ExitCode === 0 ? 'v-ok' : 'v-err') +
      '</div>';

    var findings = r.Findings || [];
    if (findings.length > 0) {
      html += '<h3 style="color:#00ccaa;font-size:0.85em;margin-top:14px">FINDINGS (' + findings.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Name</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      findings.forEach(function(f) {
        html += '<tr><td>' + escapeHtml(f.name || f.Name || '') + '</td><td>' + escapeHtml(f.endpoint || f.Endpoint || '') + '</td><td>' + escapeHtml(f.severity || f.Severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (run.ErrorOutput) {
      html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:14px">SCANNER ERRORS</h3>';
      html += '<pre style="background:#1a0a0a;border:1px solid #330000;border-radius:4px;padding:10px;color:#ff6666;font-size:0.8em;max-height:200px;overflow:auto">' + escapeHtml(run.ErrorOutput) + '</pre>';
    }

    document.getElementById('scanner-comparison').innerHTML = html;
  }

  function renderComparison(report) {
    var grade = (report.grade || report.Grade || '?').toUpperCase();
    var gradeClass = 'grade-' + grade.toLowerCase();
    var detPct = ((report.detection_rate || report.DetectionRate || 0) * 100).toFixed(1);
    var fpPct = ((report.false_pos_rate || report.FalsePositiveRate || 0) * 100).toFixed(1);
    var accPct = ((report.accuracy || report.Accuracy || 0) * 100).toFixed(1);

    var html = '<div style="display:grid;grid-template-columns:200px 1fr;gap:20px">' +
      '<div>' +
        '<div class="grade ' + gradeClass + '">' + escapeHtml(grade) + '</div>' +
        '<div style="text-align:center;color:#888;font-size:0.85em">Scanner Grade</div>' +
      '</div>' +
      '<div>' +
        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">Detection Rate</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-green" style="width:' + detPct + '%%"></div></div>' +
        '<span style="color:#00ff88;font-size:0.85em">' + detPct + '%%</span></div>' +

        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">False Positive Rate</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-red" style="width:' + fpPct + '%%"></div></div>' +
        '<span style="color:#ff4444;font-size:0.85em">' + fpPct + '%%</span></div>' +

        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">Accuracy</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-yellow" style="width:' + accPct + '%%"></div></div>' +
        '<span style="color:#ffcc00;font-size:0.85em">' + accPct + '%%</span></div>' +
      '</div></div>';

    var health = report.scanner_health || report.ScannerHealth || {};
    html += '<div style="margin-top:14px;font-size:0.85em;color:#888">' +
      'Crashed: <span style="color:' + (health.crashed || health.Crashed ? '#ff4444' : '#00ff88') + '">' + (health.crashed || health.Crashed ? 'YES' : 'no') + '</span> | ' +
      'Timed out: <span style="color:' + (health.timed_out || health.TimedOut ? '#ff4444' : '#00ff88') + '">' + (health.timed_out || health.TimedOut ? 'YES' : 'no') + '</span> | ' +
      'Errors: <span style="color:' + ((health.errors || health.Errors || 0) > 0 ? '#ff4444' : '#00ff88') + '">' + (health.errors || health.Errors || 0) + '</span>' +
      '</div>';

    var tp = report.true_positives || report.TruePositives || [];
    if (tp.length > 0) {
      html += '<h3 style="color:#00ff88;font-size:0.85em;margin-top:16px">TRUE POSITIVES (' + tp.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      tp.forEach(function(item) {
        html += '<tr><td class="found">' + escapeHtml(item.name || item.Name || '') + '</td><td>' + escapeHtml(item.endpoint || item.Endpoint || '') + '</td><td>' + escapeHtml(item.severity || item.Severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    var fn = report.false_negatives || report.FalseNegatives || [];
    if (fn.length > 0) {
      html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:16px">FALSE NEGATIVES - MISSED (' + fn.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      fn.forEach(function(item) {
        html += '<tr><td class="missed">' + escapeHtml(item.name || item.Name || '') + '</td><td>' + escapeHtml(item.endpoint || item.Endpoint || '') + '</td><td>' + escapeHtml(item.severity || item.Severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    var fpList = report.false_positives || report.FalsePositives || [];
    if (fpList.length > 0) {
      html += '<h3 style="color:#ffaa00;font-size:0.85em;margin-top:16px">FALSE POSITIVES (' + fpList.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Reported Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      fpList.forEach(function(item) {
        html += '<tr><td class="false-pos">' + escapeHtml(item.name || item.Name || '') + '</td><td>' + escapeHtml(item.endpoint || item.Endpoint || '') + '</td><td>' + escapeHtml(item.severity || item.Severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (report.message || report.Message) {
      html += '<div style="margin-top:12px;color:#555;font-size:0.82em">' + escapeHtml(report.message || report.Message) + '</div>';
    }

    document.getElementById('scanner-comparison').innerHTML = html;
  }

  function renderServerHistory(completed, running) {
    var tbody = document.getElementById('scanner-history-body');
    var rows = [];

    // Running scans first
    (running || []).forEach(function(r) {
      rows.push('<tr style="background:#1a1a00">' +
        '<td style="color:#ffaa00">' + (r.started_at ? new Date(r.started_at).toLocaleString() : '-') + '</td>' +
        '<td>' + escapeHtml(r.scanner || '') + '</td>' +
        '<td style="font-weight:bold;color:#ffaa00">...</td>' +
        '<td style="color:#888">' + escapeHtml(r.elapsed || '-') + '</td>' +
        '<td><span style="color:#ffaa00">RUNNING</span></td>' +
        '</tr>');
    });

    // Completed scans (newest first)
    (completed || []).slice().reverse().forEach(function(r) {
      var comp = r.Comparison || {};
      var grade = comp.Grade || comp.grade || '-';
      var det = comp.DetectionRate || comp.detection_rate;
      var detStr = det !== undefined ? (det * 100).toFixed(0) + '%%' : '-';
      var gradeClass = grade !== '-' && grade !== '?' ? 'grade-' + grade.toLowerCase() : '';
      var statusColor = r.Status === 'completed' ? '#00ff88' : '#ff4444';
      rows.push('<tr onclick="viewScanRun(' + (completed.indexOf(r)) + ')" style="cursor:pointer">' +
        '<td style="color:#888">' + (r.CompletedAt ? new Date(r.CompletedAt).toLocaleString() : r.StartedAt ? new Date(r.StartedAt).toLocaleString() : '-') + '</td>' +
        '<td>' + escapeHtml(r.Scanner || '') + '</td>' +
        '<td' + (gradeClass ? ' class="' + gradeClass + '"' : '') + ' style="font-weight:bold;font-size:1.2em">' + escapeHtml(grade) + '</td>' +
        '<td>' + detStr + '</td>' +
        '<td style="color:' + statusColor + '">' + escapeHtml(r.Status || '-') + '</td>' +
        '</tr>');
    });

    tbody.innerHTML = rows.join('') || '<tr><td colspan="5" style="color:#555;text-align:center">No scans yet</td></tr>';

    // Store for click-to-view
    window._completedRuns = completed || [];
  }

  window.viewScanRun = function(idx) {
    var runs = window._completedRuns || [];
    if (idx >= 0 && idx < runs.length) {
      var run = runs[idx];
      if (run.Comparison) renderComparison(run.Comparison);
      else renderScanResult(run);
    }
  };

  async function refreshScannerTab() {
    try {
      var data = await api('/admin/api/scanner/results');
      var running = data.running || [];
      var completed = data.completed || [];
      renderServerHistory(completed, running);

      // Auto-start polling if scans are running
      if (running.length > 0 && !scanPollTimer) startScanPolling();

      // Update run status
      var statusEl = document.getElementById('scanner-run-status');
      if (running.length > 0) {
        statusEl.innerHTML = running.map(function(r) {
          return '<div style="margin:4px 0"><span style="color:#ffaa00">&#9654; ' + escapeHtml(r.scanner) + '</span> ' +
            '<span style="color:#888">' + escapeHtml(r.status) + ' (' + escapeHtml(r.elapsed) + ')</span> ' +
            '<button class="scanner-btn" style="padding:2px 10px;font-size:0.75em" onclick="stopScanner(\'' + escapeHtml(r.scanner) + '\')">Stop</button></div>';
        }).join('');
      }
    } catch(e) { console.error('scannerTab:', e); }
  }

  // ------ Main loop ------
  async function refresh() {
    const active = document.querySelector('.panel.active');
    if (!active) return;
    const id = active.id;
    if (id === 'panel-dashboard') await refreshDashboard();
    else if (id === 'panel-sessions') await refreshSessions();
    else if (id === 'panel-traffic') await refreshTraffic();
    else if (id === 'panel-controls') await refreshControls();
    else if (id === 'panel-log') await refreshLog();
    else if (id === 'panel-vulns') await refreshVulns();
    else if (id === 'panel-scanner') await refreshScannerTab();
  }

  // Initial load — restore tab from URL hash
  (async function init() {
    var hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById('panel-' + hash)) {
      showTab(hash, false);
    }
    await refresh();
  })();

  setInterval(refresh, 2000);
})();
</script>
</body>
</html>`)
