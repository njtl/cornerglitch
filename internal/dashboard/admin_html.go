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
  .tab[data-mode="server"].active { color: #00ff88; border-color: #00ff8844; }
  .tab[data-mode="scanner"].active { color: #00ccff; border-color: #00ccff44; }
  .tab[data-mode="proxy"].active { color: #ffaa00; border-color: #ffaa0044; }
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
    grid-template-columns: repeat(auto-fill, minmax(265px, 1fr));
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
    gap: 8px;
  }
  .toggle-name {
    font-size: 0.85em;
    color: #ccc;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .toggle-sw {
    position: relative;
    width: 44px;
    min-width: 44px;
    height: 24px;
    cursor: pointer;
    flex-shrink: 0;
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

  /* Tooltip system */
  .has-tip { position: relative; cursor: help; }
  .has-tip .tip-icon {
    display: inline-block;
    width: 14px; height: 14px;
    line-height: 14px;
    text-align: center;
    border-radius: 50%%;
    background: #222;
    color: #666;
    font-size: 10px;
    margin-left: 5px;
    vertical-align: middle;
    border: 1px solid #333;
  }
  .has-tip:hover .tip-icon { color: #0f8; border-color: #0f8; }
  .tip-box {
    display: none;
    position: absolute;
    bottom: calc(100%% + 8px);
    left: 0;
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 8px 12px;
    color: #bbb;
    font-size: 0.78em;
    line-height: 1.4;
    white-space: normal;
    width: 280px;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    pointer-events: none;
  }
  .has-tip:hover .tip-box { display: block; }

  /* Section group header */
  .ew-section-header {
    font-size: 0.82em;
    color: #00ffcc;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 12px 0 6px 0;
    padding-bottom: 4px;
    border-bottom: 1px solid #1a1a1a;
  }
  .ew-section-header:first-child { margin-top: 0; }

  /* Error weight radio grid */
  .ew-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
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
    min-width: 120px;
    color: #aaa;
    font-size: 0.95em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ew-opts { display: flex; gap: 2px; flex-shrink: 0; }
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
  .scanner-btn.danger { background: #882222; color: #ff6666; }
  .scanner-btn.danger:hover { background: #aa3333; }
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

  /* Built-in Scanner */
  .profile-card { background:#111;border:1px solid #333;border-radius:8px;padding:14px;cursor:pointer;transition:border-color .2s }
  .profile-card:hover { border-color:#555 }
  .profile-card.selected { border-color:#0ff;box-shadow:0 0 8px rgba(0,255,255,0.15) }
  .profile-card .profile-name { color:#0ff;font-weight:bold;font-size:1em;margin-bottom:6px }
  .profile-card .profile-desc { color:#888;font-size:0.8em;line-height:1.4 }
  .profile-card .profile-stats { color:#555;font-size:0.75em;margin-top:8px }
  .module-row { display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid #1a1a1a }
  .module-row:last-child { border-bottom:none }
  .module-row label { color:#ccc;cursor:pointer;flex:1 }
  .module-row .mod-reqs { color:#555;font-size:0.8em;min-width:80px;text-align:right }
  .builtin-progress { background:#111;border:1px solid #333;border-radius:4px;height:24px;position:relative;overflow:hidden;margin:10px 0 }
  .builtin-progress-bar { height:100%%;background:linear-gradient(90deg,#0a4,#0ff);transition:width .3s }
  .builtin-progress-text { position:absolute;top:0;left:0;right:0;text-align:center;line-height:24px;font-size:0.8em;color:#fff }
  .severity-badge { padding:2px 8px;border-radius:3px;font-size:0.75em;font-weight:bold }
  .severity-badge.sev-critical { background:#a00;color:#fff }
  .severity-badge.sev-high { background:#c50;color:#fff }
  .severity-badge.sev-medium { background:#a80;color:#fff }
  .severity-badge.sev-low { background:#069;color:#fff }
  .severity-badge.sev-info { background:#333;color:#aaa }

  /* Findings search and filter */
  .findings-search { width:100%%;padding:8px 12px;background:#111;border:1px solid #333;border-radius:4px;color:#eee;font-size:0.85em;margin-bottom:10px;box-sizing:border-box }
  .findings-search:focus { border-color:#0af;outline:none }
  .severity-filter { display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:bold;cursor:pointer;margin:0 4px 8px 0;border:1px solid transparent;opacity:0.5;transition:opacity .2s }
  .severity-filter.active { opacity:1;border-color:#fff3 }
  .severity-filter.sf-critical { background:#a00;color:#fff }
  .severity-filter.sf-high { background:#c50;color:#fff }
  .severity-filter.sf-medium { background:#a80;color:#fff }
  .severity-filter.sf-low { background:#069;color:#fff }
  .severity-filter.sf-info { background:#333;color:#aaa }
  .findings-group { margin-bottom:6px }
  .findings-group summary { cursor:pointer;padding:8px 12px;background:#1a1a1a;border:1px solid #333;border-radius:4px;color:#ddd;font-size:0.85em;list-style:none;display:flex;align-items:center;gap:8px;user-select:none }
  .findings-group summary::-webkit-details-marker { display:none }
  .findings-group summary .fg-arrow { display:inline-block;font-size:0.65em;transition:transform .2s;color:#888;width:12px }
  .findings-group[open] summary .fg-arrow { transform:rotate(90deg) }
  .findings-group summary .fg-count { color:#888;font-size:0.85em }
  .findings-group table { margin:0 }
  .findings-container { max-height:600px;overflow-y:auto }
  .findings-url { max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle }
  #builtin-history-body tr.history-clickable { cursor:pointer }
  #builtin-history-body tr.history-clickable:hover { background:#1a2a3a }
  .history-viewing-banner { background:#1a2a3a;border:1px solid #0af;border-radius:6px;padding:10px 16px;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;color:#88ccff;font-size:0.85em }
  .history-viewing-banner button { background:#333;color:#aaa;border:1px solid #555;border-radius:4px;padding:4px 14px;cursor:pointer;font-family:inherit;font-size:0.82em }
  .history-viewing-banner button:hover { background:#444;color:#fff }
  .crash-overlay { display:none;position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,0.7);z-index:9000;align-items:center;justify-content:center }
  .crash-overlay.open { display:flex }
  .crash-modal { background:#1a1a1a;border:1px solid #ff4444;border-radius:10px;padding:24px 28px;max-width:700px;width:90%%;max-height:80vh;overflow-y:auto;box-shadow:0 0 40px rgba(255,68,68,0.3) }
  .crash-modal h3 { color:#ff4444;margin:0 0 16px;font-size:1em;display:flex;align-items:center;justify-content:space-between }
  .crash-modal .close-btn { background:none;border:none;color:#888;font-size:1.4em;cursor:pointer;padding:0 4px }
  .crash-modal .close-btn:hover { color:#fff }
  .crash-modal .crash-field { margin:10px 0 }
  .crash-modal .crash-field .label { color:#888;font-size:0.8em;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px }
  .crash-modal .crash-field .value { color:#ddd;font-size:0.9em }
  .crash-modal pre { background:#0a0a0a;border:1px solid #333;border-radius:6px;padding:12px;color:#ff8844;font-size:0.8em;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0 0 }
  .crash-link { color:#ff4444;cursor:pointer;text-decoration:underline;text-decoration-style:dotted }
  .crash-link:hover { color:#ff6666;text-decoration-style:solid }

  /* Collapsible server sections */
  .srv-section { margin-bottom: 2px; }
  .srv-section-header {
    display: flex; align-items: center; justify-content: space-between;
    background: #111; border: 1px solid #1a1a1a; border-radius: 6px;
    padding: 10px 16px; cursor: pointer; transition: all 0.2s; user-select: none;
  }
  .srv-section-header:hover { background: #161616; border-color: #333; }
  .srv-section-header .srv-title { color: #00ccaa; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }
  .srv-section-header .srv-arrow { color: #555; transition: transform 0.2s; font-size: 0.9em; }
  .srv-section.open .srv-section-header { border-color: #00ff8844; }
  .srv-section.open .srv-arrow { transform: rotate(90deg); color: #00ff88; }
  .srv-section-body { display: none; padding: 16px; border: 1px solid #1a1a1a; border-top: none; border-radius: 0 0 6px 6px; background: #0d0d0d; }
  .srv-section.open .srv-section-body { display: block; }

  /* Mode status cards */
  .mode-cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 20px; }
  .mode-card { background: #111; border: 1px solid #222; border-radius: 10px; padding: 16px; position: relative; overflow: hidden; }
  .mode-card .mode-label { font-size: 0.7em; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 6px; font-weight: bold; }
  .mode-card .mode-status { font-size: 1.1em; margin-bottom: 4px; }
  .mode-card .mode-detail { color: #888; font-size: 0.78em; }
  .mode-card.mc-server { border-color: #00ff8833; }
  .mode-card.mc-server .mode-label { color: #00ff88; }
  .mode-card.mc-scanner { border-color: #00ccff33; }
  .mode-card.mc-scanner .mode-label { color: #00ccff; }
  .mode-card.mc-proxy { border-color: #ffaa0033; }
  .mode-card.mc-proxy .mode-label { color: #ffaa00; }

  /* Nightmare indicator */
  .nightmare-bar { display: flex; align-items: center; justify-content: space-between; padding: 6px 16px; margin-bottom: 10px; border-radius: 6px; font-size: 0.82em; transition: all 0.3s; }
  .nightmare-bar.off { background: #111; border: 1px solid #1a1a1a; color: #555; }
  .nightmare-bar.on { background: #ff000015; border: 1px solid #ff4444; color: #ff4444; animation: nightmare-pulse 2s infinite; }
  @keyframes nightmare-pulse { 0%%,100%% { box-shadow: 0 0 5px #ff000033; } 50%% { box-shadow: 0 0 20px #ff000066; } }
  @keyframes shimmer { 0%% { background-position: 200%% 0; } 100%% { background-position: -200%% 0; } }
  body.nightmare-active { background: #0a0000; }
  body.nightmare-active .tab { border-color: #ff444422; }
  .tab .tab-badge { display: none; color: #ff4444; font-size: 0.7em; margin-left: 4px; }
  body.nightmare-active .tab .tab-badge { display: inline; }

  /* Quick action buttons */
  .quick-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; }
  .quick-action-btn { background: #1a1a1a; border: 1px solid #333; color: #ccc; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.82em; transition: all 0.2s; }
  .quick-action-btn:hover { border-color: #00ff88; color: #00ff88; }
  .nightmare-btn { background: linear-gradient(135deg, #1a0000, #330000); border: 1px solid #ff4444; color: #ff4444; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.82em; font-weight: bold; transition: all 0.2s; }
  .nightmare-btn:hover { background: linear-gradient(135deg, #330000, #550000); box-shadow: 0 0 10px #ff000033; }

  /* Scanner sub-tab buttons - override */
  .scanner-subtab-btn { background: #111; border: 1px solid #222; color: #888; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.82em; transition: all 0.2s; border-bottom: none; }
  .scanner-subtab-btn:hover { color: #00ccff; border-color: #00ccff44; }
  .scanner-subtab-btn.active { color: #00ccff; border-color: #00ccff; background: #00ccff11; }

  /* Settings panel */
  .settings-input { background: #0d0d0d; color: #00ff88; border: 1px solid #333; padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 0.85em; width: 100%%; outline: none; }
  .settings-input:focus { border-color: #00ff8866; }
</style>
</head>
<body>

<div class="nightmare-bar off" id="nightmare-bar">
  <span id="nightmare-label">NIGHTMARE: OFF</span>
  <span id="nightmare-modes" style="font-size:0.8em"></span>
</div>

<h1>// GLITCH ADMIN PANEL</h1>
<div class="subtitle">Control center for the glitch web server &middot; <span id="header-uptime" style="color:#00ccff">uptime: --</span></div>

<div class="tabs">
  <button class="tab active" onclick="showTab('dashboard')" data-mode="">Dashboard</button>
  <button class="tab" onclick="showTab('server')" data-mode="server">Server<span class="tab-badge">!!</span></button>
  <button class="tab" onclick="showTab('scanner')" data-mode="scanner">Scanner<span class="tab-badge">!!</span></button>
  <button class="tab" onclick="showTab('proxy')" data-mode="proxy">Proxy<span class="tab-badge">!!</span></button>
  <button class="tab" onclick="showTab('settings')" data-mode="">Settings</button>
</div>

<!-- ==================== DASHBOARD TAB ==================== -->
<div id="panel-dashboard" class="panel active">
  <!-- Mode Status Cards -->
  <div class="mode-cards">
    <div class="mode-card mc-server" id="dash-mode-server">
      <div class="mode-label">Server</div>
      <div class="mode-status" id="dash-server-status">RUNNING</div>
      <div class="mode-detail" id="dash-server-detail">Loading...</div>
    </div>
    <div class="mode-card mc-scanner" id="dash-mode-scanner">
      <div class="mode-label">Scanner</div>
      <div class="mode-status" id="dash-scanner-status">IDLE</div>
      <div class="mode-detail" id="dash-scanner-detail">No active scans</div>
    </div>
    <div class="mode-card mc-proxy" id="dash-mode-proxy">
      <div class="mode-label">Proxy</div>
      <div class="mode-status" id="dash-proxy-status">--</div>
      <div class="mode-detail" id="dash-proxy-detail">Loading...</div>
    </div>
  </div>

  <!-- Global Metrics -->
  <div class="grid" id="dash-metrics"></div>

  <!-- Three-Column Mode Sections -->
  <p style="color:#555;font-size:0.72em;margin-bottom:8px">Per-subsystem metrics. Click any card heading to jump to that tab.</p>
  <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap: 18px; margin-bottom: 18px;">
    <!-- Server Column -->
    <div class="section" style="border-left: 3px solid #00ff88;">
      <h2 style="color:#00ff88; font-size:0.9em; margin-bottom:10px">// Server</h2>
      <div class="grid" style="grid-template-columns:1fr 1fr;" id="dash-srv-cards"></div>
      <div style="margin-top:10px">
        <div style="font-size:0.75em;color:#888;text-transform:uppercase;margin-bottom:4px">Status Codes</div>
        <div id="dash-status-bars"></div>
      </div>
      <div style="margin-top:10px">
        <div style="font-size:0.75em;color:#888;text-transform:uppercase;margin-bottom:4px">Response Types</div>
        <div id="dash-resp-types"></div>
      </div>
    </div>
    <!-- Scanner Column -->
    <div class="section" style="border-left: 3px solid #00ccff;">
      <h2 style="color:#00ccff; font-size:0.9em; margin-bottom:10px">// Scanner</h2>
      <div class="grid" style="grid-template-columns:1fr 1fr;" id="dash-scan-cards"></div>
      <div id="dash-scan-detail" style="margin-top:10px;font-size:0.82em;color:#888"></div>
    </div>
    <!-- Proxy Column -->
    <div class="section" style="border-left: 3px solid #ffaa00;">
      <h2 style="color:#ffaa00; font-size:0.9em; margin-bottom:10px">// Proxy</h2>
      <div class="grid" style="grid-template-columns:1fr 1fr;" id="dash-proxy-cards"></div>
      <div id="dash-proxy-detail-ext" style="margin-top:10px;font-size:0.82em;color:#888"></div>
    </div>
  </div>

  <!-- Performance Metrics -->
  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Throughput (last 60s)</h2>
      <div class="sparkline-wrap" id="dash-sparkline" style="height:100px"></div>
    </div>
    <div class="section">
      <h2>// Error Rate (last 60s)</h2>
      <div class="sparkline-wrap" id="dash-err-sparkline" style="height:100px"></div>
    </div>
  </div>

  <!-- Calculated Stats -->
  <div class="grid" id="dash-calc-stats"></div>

  <!-- Connected Clients (clickable) -->
  <div class="section">
    <h2>// Connected Clients</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Click any client to view details and override adaptive behavior mode.</p>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead><tr>
          <th>Client</th><th>Requests</th><th>Req/s</th><th>Errors</th><th>Mode</th><th>Last Seen</th>
        </tr></thead>
        <tbody id="dash-clients-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Client Detail Panel (shared - works from dashboard and server) -->
  <div class="section" id="dash-client-detail" style="display:none">
    <h2>// Client Detail: <span id="dash-detail-cid" style="color:#00ffcc"></span>
      <span style="float:right;cursor:pointer;color:#666;font-size:0.8em" onclick="document.getElementById('dash-client-detail').style.display='none'">[close]</span>
    </h2>
    <div class="grid" id="dash-detail-cards"></div>
    <div style="margin:12px 0">
      <label style="color:#aaa;font-size:0.85em">Override Mode:</label>
      <select id="dash-override-mode" style="background:#0d0d0d;color:#00ff88;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;margin:0 8px">
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
      <button onclick="dashApplyOverride()" style="background:#00aa66;color:#000;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:bold">Apply</button>
      <button onclick="dashClearOverride()" style="background:#333;color:#ccc;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;margin-left:4px">Clear</button>
    </div>
    <div id="dash-detail-paths" style="max-height:200px;overflow-y:auto"></div>
  </div>

  <!-- Traffic Analytics -->
  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Top 10 Paths</h2>
      <p style="color:#555;font-size:0.72em;margin-bottom:6px">Most frequently requested URL paths.</p>
      <div id="dash-top-paths"></div>
    </div>
    <div class="section">
      <h2>// Top 10 User Agents</h2>
      <p style="color:#555;font-size:0.72em;margin-bottom:6px">Most common User-Agent strings seen in traffic.</p>
      <div id="dash-top-ua"></div>
    </div>
  </div>

  <!-- Request Log -->
  <div class="section">
    <h2>// Request Log</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:6px">Live feed of recent requests. Use the filter to narrow by status code, client, path, type, or user agent.</p>
    <input type="text" class="search-box" id="dash-log-filter" placeholder="Filter by status, client, path, type..." oninput="filterDashLog()">
    <div class="tbl-scroll" style="max-height: 500px;">
      <table>
        <thead><tr><th>Time</th><th>Client</th><th>Method</th><th>Path</th><th>Status</th><th>Latency</th><th>Type</th><th>Mode</th><th>User Agent</th></tr></thead>
        <tbody id="dash-log-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Quick Actions -->
  <div class="quick-actions">
    <button class="nightmare-btn" onclick="toggleNightmareAll()" id="dash-nightmare-btn">Enable Nightmare</button>
    <button class="quick-action-btn" onclick="showTab('scanner');switchScannerSubtab('builtin')">Run Scanner</button>
    <button class="quick-action-btn" onclick="showTab('proxy')">View Proxy</button>
  </div>
</div>

<div id="panel-server" class="panel">

  <!-- Server Status Bar -->
  <div style="display:flex;align-items:center;justify-content:space-between;background:#111;border:1px solid #00ff8833;border-radius:6px;padding:10px 16px;margin-bottom:14px;font-size:0.82em">
    <span style="color:#00ff88;font-weight:bold">SERVER STATUS: <span id="srv-status-text">RUNNING</span></span>
    <span style="color:#888">Error Rate: <span id="srv-status-errrate" style="color:#ffaa00">--</span></span>
    <span style="color:#888">Clients: <span id="srv-status-clients" style="color:#00ccff">--</span></span>
    <span style="color:#888">Features: <span id="srv-status-features" style="color:#00ff88">--</span></span>
    <button class="nightmare-btn" onclick="toggleNightmareMode('server')" id="srv-nightmare-btn" style="padding:4px 12px;font-size:0.85em">Nightmare: OFF</button>
  </div>

  <!-- ====== Traffic Recording ====== -->
  <div class="srv-section" id="srv-recording">
    <div class="srv-section-header" onclick="toggleServerSection('recording')">
      <span class="srv-title">Traffic Recording</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <div style="display:grid;grid-template-columns:auto auto auto auto 1fr;gap:12px;align-items:end">
        <div>
          <div class="label" style="margin-bottom:4px">Format</div>
          <select id="rec-format" class="ctrl-select" style="min-width:80px">
            <option value="jsonl">JSONL</option>
            <option value="pcap">PCAP</option>
          </select>
        </div>
        <div>
          <div class="label" style="margin-bottom:4px">Max Duration (sec)</div>
          <input type="number" id="rec-max-dur" value="0" min="0" max="86400" step="60"
            style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100px"
            title="0 = unlimited">
        </div>
        <div>
          <div class="label" style="margin-bottom:4px">Max Requests</div>
          <input type="number" id="rec-max-reqs" value="0" min="0" max="10000000" step="1000"
            style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100px"
            title="0 = unlimited">
        </div>
        <div style="display:flex;gap:6px">
          <button class="scanner-btn" id="rec-start-btn" onclick="startRecording()">Start Recording</button>
          <button class="scanner-btn danger" id="rec-stop-btn" onclick="stopRecording()" style="display:none">Stop</button>
        </div>
        <div id="rec-status" style="font-size:0.82em;color:#555">Idle</div>
      </div>
      <div id="rec-stats" style="margin-top:10px;display:none">
        <div class="grid">
          <div class="card"><div class="label">Records</div><div class="value v-ok" id="rec-count">0</div></div>
          <div class="card"><div class="label">File Size</div><div class="value v-info" id="rec-size">0 B</div></div>
          <div class="card"><div class="label">Elapsed</div><div class="value v-info" id="rec-elapsed">0s</div></div>
          <div class="card"><div class="label">File</div><div class="value" style="font-size:0.6em;color:#888" id="rec-file">--</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ====== Feature Toggles ====== -->
  <div class="srv-section open" id="srv-features">
    <div class="srv-section-header" onclick="toggleServerSection('features')">
      <span class="srv-title">Feature Toggles</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <p style="color:#666;font-size:0.8em;margin-bottom:8px">Enable or disable individual server subsystems. Disabled features return normal responses instead.</p>
      <div style="margin-bottom:10px;display:flex;gap:6px">
        <button class="cfg-btn" onclick="setAllFeatures(true)" style="font-size:0.78em;padding:4px 12px">All On</button>
        <button class="cfg-btn" onclick="setAllFeatures(false)" style="font-size:0.78em;padding:4px 12px">All Off</button>
      </div>
      <div class="toggle-grid" id="toggles"></div>
    </div>
  </div>

  <!-- ====== Error Configuration ====== -->
  <div class="srv-section" id="srv-errors">
    <div class="srv-section-header" onclick="toggleServerSection('errors')">
      <span class="srv-title">Error Configuration</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <div style="margin-bottom:16px">
        <h2 style="font-size:0.9em;margin-bottom:8px">// Behavior Tuning</h2>
        <p style="color:#666;font-size:0.8em;margin-bottom:8px">Adjust thresholds, rates, and timing parameters that control server behavior.</p>
        <div id="sliders"></div>
      </div>
      <div style="margin-bottom:16px">
        <h2 style="font-size:0.9em;margin-bottom:8px">// HTTP Error Weights</h2>
        <p style="color:#666;font-size:0.8em;margin-bottom:8px">Control the probability of each HTTP error response. Higher weight = more frequent.</p>
        <div style="margin-bottom:8px;display:flex;gap:4px;flex-wrap:wrap">
          <button class="cfg-btn" onclick="setAllErrorWeights('http','off')" style="font-size:0.72em;padding:3px 10px">All OFF</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('http','low')" style="font-size:0.72em;padding:3px 10px">All LOW</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('http','med')" style="font-size:0.72em;padding:3px 10px">All MED</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('http','high')" style="font-size:0.72em;padding:3px 10px">All HIGH</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('http','max')" style="font-size:0.72em;padding:3px 10px">All MAX</button>
          <button class="cfg-btn" onclick="resetErrorWeights()" style="font-size:0.72em;padding:3px 10px">Reset Default</button>
        </div>
        <div class="ew-grid" id="http-error-grid"></div>
      </div>
      <div>
        <h2 style="font-size:0.9em;margin-bottom:8px">// TCP / Network Error Weights</h2>
        <p style="color:#666;font-size:0.8em;margin-bottom:8px">Low-level network errors that bypass HTTP entirely.</p>
        <div style="margin-bottom:8px;display:flex;gap:4px;flex-wrap:wrap">
          <button class="cfg-btn" onclick="setAllErrorWeights('tcp','off')" style="font-size:0.72em;padding:3px 10px">All OFF</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('tcp','low')" style="font-size:0.72em;padding:3px 10px">All LOW</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('tcp','med')" style="font-size:0.72em;padding:3px 10px">All MED</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('tcp','high')" style="font-size:0.72em;padding:3px 10px">All HIGH</button>
          <button class="cfg-btn" onclick="setAllErrorWeights('tcp','max')" style="font-size:0.72em;padding:3px 10px">All MAX</button>
        </div>
        <div class="ew-grid" id="tcp-error-grid"></div>
      </div>
    </div>
  </div>

  <!-- ====== Content & Presentation ====== -->
  <div class="srv-section" id="srv-content">
    <div class="srv-section-header" onclick="toggleServerSection('content')">
      <span class="srv-title">Content &amp; Presentation</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <div style="margin-bottom:16px">
        <h2 style="font-size:0.9em;margin-bottom:8px">// Page Type Distribution</h2>
        <p style="color:#666;font-size:0.8em;margin-bottom:8px">Control the probability of each response content type.</p>
        <div style="margin-bottom:8px;display:flex;gap:4px;flex-wrap:wrap">
          <button class="cfg-btn" onclick="setAllPageTypeWeights('off')" style="font-size:0.72em;padding:3px 10px">All OFF</button>
          <button class="cfg-btn" onclick="setAllPageTypeWeights('low')" style="font-size:0.72em;padding:3px 10px">All LOW</button>
          <button class="cfg-btn" onclick="setAllPageTypeWeights('med')" style="font-size:0.72em;padding:3px 10px">All MED</button>
          <button class="cfg-btn" onclick="setAllPageTypeWeights('high')" style="font-size:0.72em;padding:3px 10px">All HIGH</button>
          <button class="cfg-btn" onclick="setAllPageTypeWeights('max')" style="font-size:0.72em;padding:3px 10px">All MAX</button>
          <button class="cfg-btn" onclick="resetPageTypeWeights()" style="font-size:0.72em;padding:3px 10px">Reset Default</button>
        </div>
        <div class="ew-grid" id="page-type-grid"></div>
      </div>
      <div>
        <h2 style="font-size:0.9em;margin-bottom:8px">// Response &amp; Content Settings</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div class="has-tip">
            <div class="slider-label"><span>Honeypot Response Style</span><span class="tip-icon">?</span></div>
            <div class="tip-box">How honeypot trap endpoints respond. Realistic mimics real apps; Tarpit adds delays; Aggressive sends fake server headers.</div>
            <select id="ctrl-honeypot-style" class="ctrl-select" onchange="setConfigKey('honeypot_response_style', this.value)">
              <option value="realistic">Realistic</option><option value="verbose">Verbose</option><option value="minimal">Minimal</option>
              <option value="aggressive">Aggressive</option><option value="deceptive">Deceptive</option><option value="tarpit">Tarpit</option>
            </select>
          </div>
          <div class="has-tip">
            <div class="slider-label"><span>Active Framework Emulation</span><span class="tip-icon">?</span></div>
            <div class="tip-box">Which web framework to emulate in response headers and error pages.</div>
            <select id="ctrl-framework" class="ctrl-select" onchange="setConfigKey('active_framework', this.value)">
              <option value="auto">Auto (rotate)</option><option value="express">Express.js</option><option value="django">Django</option>
              <option value="rails">Ruby on Rails</option><option value="laravel">Laravel</option><option value="spring">Spring Boot</option>
              <option value="aspnet">ASP.NET</option><option value="flask">Flask</option><option value="fastapi">FastAPI</option>
              <option value="next">Next.js</option><option value="nginx">nginx</option><option value="apache">Apache</option><option value="caddy">Caddy</option>
            </select>
          </div>
          <div class="has-tip">
            <div class="slider-label"><span>Content Theme</span><span class="tip-icon">?</span></div>
            <div class="tip-box">Visual theme for generated HTML pages.</div>
            <select id="ctrl-theme" class="ctrl-select" onchange="setConfigKey('content_theme', this.value)">
              <option value="default">Default</option><option value="saas">SaaS</option><option value="ecommerce">E-Commerce</option>
              <option value="social">Social Media</option><option value="news">News Portal</option><option value="docs">Documentation</option>
              <option value="corporate">Corporate</option><option value="startup">Startup</option><option value="govt">Government</option>
              <option value="university">University</option><option value="banking">Banking</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ====== Labyrinth ====== -->
  <div class="srv-section" id="srv-labyrinth">
    <div class="srv-section-header" onclick="toggleServerSection('labyrinth')">
      <span class="srv-title">Labyrinth</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <p style="color:#666;font-size:0.8em;margin-bottom:8px">Controls for the infinite procedural page graph that traps scrapers.</p>
      <div id="labyrinth-sliders"></div>
    </div>
  </div>

  <!-- ====== Adaptive Behavior ====== -->
  <div class="srv-section" id="srv-adaptive">
    <div class="srv-section-header" onclick="toggleServerSection('adaptive')">
      <span class="srv-title">Adaptive Behavior</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <p style="color:#666;font-size:0.8em;margin-bottom:8px">Controls for how the server adapts to client behavior over time.</p>
      <div id="adaptive-sliders"></div>
    </div>
  </div>

  <!-- ====== Traps & Detection ====== -->
  <div class="srv-section" id="srv-traps">
    <div class="srv-section-header" onclick="toggleServerSection('traps')">
      <span class="srv-title">Traps &amp; Detection</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <p style="color:#666;font-size:0.8em;margin-bottom:8px">Captcha triggers, cookie traps, JS challenges, bot detection thresholds.</p>
      <div id="traps-sliders"></div>
    </div>
  </div>

  <!-- ====== Spider & Crawl Data ====== -->
  <div class="srv-section" id="srv-spider">
    <div class="srv-section-header" onclick="toggleServerSection('spider')">
      <span class="srv-title">Spider &amp; Crawl Data</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <p style="color:#666;font-size:0.8em;margin-bottom:8px">Configure error rates for spider/crawler resource files.</p>
      <div id="spider-sliders"></div>
    </div>
  </div>

  <!-- ====== Vulnerabilities ====== -->
  <div class="srv-section" id="srv-vulns">
    <div class="srv-section-header" onclick="toggleServerSection('vulns')">
      <span class="srv-title">Vulnerabilities</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <div class="grid" id="vuln-overview-cards" style="margin-bottom:14px">
        <div class="card"><div class="label">Loading...</div><div class="value v-info">--</div></div>
      </div>
      <div style="margin-bottom:8px;display:flex;gap:6px">
        <button class="cfg-btn" onclick="setAllVulnGroups(true)" style="font-size:0.72em;padding:3px 10px">All Groups On</button>
        <button class="cfg-btn" onclick="setAllVulnGroups(false)" style="font-size:0.72em;padding:3px 10px">All Groups Off</button>
      </div>
      <div class="group-toggles" id="vuln-group-toggles" style="margin-bottom:14px"></div>
      <div id="vuln-severity-badges" style="margin-bottom:14px"></div>
      <input type="text" class="search-box" id="vuln-filter" placeholder="Filter by name, severity, CWE, category..." oninput="filterVulns()">
      <div class="tbl-scroll" style="max-height: 500px;">
        <table>
          <thead><tr><th>Name</th><th>Severity</th><th>CWE</th><th>Category</th><th>Endpoints</th><th>Status</th></tr></thead>
          <tbody id="vuln-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ====== Sessions & Clients ====== -->
  <div class="srv-section" id="srv-sessions">
    <div class="srv-section-header" onclick="toggleServerSection('sessions')">
      <span class="srv-title">Sessions &amp; Clients</span>
      <span class="srv-arrow">&#9654;</span>
    </div>
    <div class="srv-section-body">
      <h2 style="font-size:0.9em;margin-bottom:8px">// Active Client Sessions</h2>
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
  </div>


</div> <!-- end panel-server -->

<!-- ==================== SCANNER TAB ==================== -->
<div id="panel-scanner" class="panel">

  <!-- Scanner Status Bar -->
  <div style="display:flex;align-items:center;justify-content:space-between;background:#111;border:1px solid #00ccff33;border-radius:6px;padding:10px 16px;margin-bottom:14px;font-size:0.82em">
    <span style="color:#00ccff;font-weight:bold">SCANNER STATUS: <span id="scan-status-text">IDLE</span></span>
    <span style="color:#888" id="scan-status-detail">No active scans</span>
    <button class="nightmare-btn" onclick="toggleNightmareMode('scanner')" id="scan-nightmare-btn" style="padding:4px 12px;font-size:0.85em">Nightmare: OFF</button>
  </div>

  <!-- Sub-tab navigation -->
  <div style="display:flex;gap:8px;margin-bottom:16px">
    <button class="scanner-subtab-btn active" onclick="switchScannerSubtab('eval')">Evaluate External</button>
    <button class="scanner-subtab-btn" onclick="switchScannerSubtab('builtin')">Built-in Scanner</button>
    <button class="scanner-subtab-btn" onclick="switchScannerSubtab('replay')">PCAP Replay</button>
  </div>

  <!-- ====== Sub-tab A: Evaluate External Scanners ====== -->
  <div id="scanner-eval-panel">

    <!-- 1. Launch External Scanner -->
    <div class="section">
      <h2>// Launch External Scanner</h2>
      <p style="color:#888;font-size:0.82em;margin-bottom:12px">Launch a scanner against this server (requires tool to be installed on host).</p>

      <!-- Active Scanners Banner -->
      <div id="active-scanners-banner" style="display:none;background:#1a1a00;border:1px solid #333300;border-radius:6px;padding:10px 14px;margin-bottom:12px">
        <div style="color:#ffaa00;font-weight:bold;font-size:0.85em;margin-bottom:6px">Active Scanners</div>
        <div id="active-scanners-list"></div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">
        <div class="scanner-panel" id="scanner-card-nuclei" style="margin-bottom:0;display:flex;flex-direction:column">
          <h3>Nuclei</h3>
          <p style="color:#666;font-size:0.78em;margin-bottom:8px;flex:1">Template-based scanner. Fast, accurate, low false positives.</p>
          <button class="scanner-btn" id="scanner-btn-nuclei" onclick="runScanner('nuclei')">Launch</button>
        </div>
        <div class="scanner-panel" id="scanner-card-nikto" style="margin-bottom:0;display:flex;flex-direction:column">
          <h3>Nikto</h3>
          <p style="color:#666;font-size:0.78em;margin-bottom:8px;flex:1">Classic web server scanner. Checks for misconfigurations and known vulns.</p>
          <button class="scanner-btn" id="scanner-btn-nikto" onclick="runScanner('nikto')">Launch</button>
        </div>
        <div class="scanner-panel" id="scanner-card-nmap" style="margin-bottom:0;display:flex;flex-direction:column">
          <h3>Nmap</h3>
          <p style="color:#666;font-size:0.78em;margin-bottom:8px;flex:1">Network mapper with NSE scripts for service and vuln detection.</p>
          <button class="scanner-btn" id="scanner-btn-nmap" onclick="runScanner('nmap')">Launch</button>
        </div>
        <div class="scanner-panel" id="scanner-card-ffuf" style="margin-bottom:0;display:flex;flex-direction:column">
          <h3>ffuf</h3>
          <p style="color:#666;font-size:0.78em;margin-bottom:8px;flex:1">Fast web fuzzer. Directory brute-forcing and parameter discovery.</p>
          <button class="scanner-btn" id="scanner-btn-ffuf" onclick="runScanner('ffuf')">Launch</button>
        </div>
        <div class="scanner-panel" id="scanner-card-wapiti" style="margin-bottom:0;display:flex;flex-direction:column">
          <h3>Wapiti</h3>
          <p style="color:#666;font-size:0.78em;margin-bottom:8px;flex:1">Black-box web app scanner. Tests for XSS, SQLi, SSRF, and more.</p>
          <button class="scanner-btn" id="scanner-btn-wapiti" onclick="runScanner('wapiti')">Launch</button>
        </div>
      </div>
      <div id="scanner-run-status" style="margin-top:8px;color:#555;font-size:0.82em"></div>
    </div>

    <!-- 2. Scan History -->
    <div class="section">
      <h2>// Scan History</h2>
      <div class="tbl-scroll" style="max-height:400px">
        <table>
          <thead><tr>
            <th>Timestamp</th>
            <th>Scanner</th>
            <th>Grade</th>
            <th>Detection</th>
            <th>Status</th>
            <th>Actions</th>
          </tr></thead>
          <tbody id="scanner-history-body"></tbody>
        </table>
      </div>
    </div>

    <!-- 3. Scan Results -->
    <div class="section">
      <h2>// Scan Results</h2>
      <div id="scanner-result-tabs" style="display:none;margin-bottom:10px;border-bottom:1px solid #333;padding-bottom:6px">
        <!-- Populated dynamically: one tab per scanner that has results -->
      </div>
      <div id="scanner-comparison">
        <div style="color:#555">Launch an external scanner above. Results are captured and graded automatically.</div>
      </div>
    </div>

    <!-- 4. Target Vulnerability Surface -->
    <div class="section">
      <h2>// Target Vulnerability Surface</h2>
      <div id="scanner-profile-summary" style="margin-top:8px">
        <div style="color:#555">Loading vulnerability surface...</div>
      </div>
    </div>

    <!-- Manual Upload (collapsible) -->
    <div class="section">
      <div style="cursor:pointer;display:flex;justify-content:space-between;align-items:center" onclick="var el=document.getElementById('manual-upload-body');el.style.display=el.style.display==='none'?'':'none'">
        <h2>// Manual Upload (optional)</h2>
        <span style="color:#555;font-size:0.85em">Click to expand</span>
      </div>
      <div id="manual-upload-body" style="display:none;margin-top:12px">
        <p style="color:#666;font-size:0.8em;margin-bottom:8px">Paste scanner output from an external run for grading.</p>
        <div class="scanner-panel">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
            <label style="color:#aaa;font-size:0.85em">Scanner Type:</label>
            <select id="scanner-type" class="scanner-select">
              <option value="nuclei">Nuclei</option>
              <option value="nikto">Nikto</option>
              <option value="nmap">Nmap</option>
              <option value="ffuf">ffuf</option>
              <option value="wapiti">Wapiti</option>
              <option value="generic">Generic</option>
            </select>
          </div>
          <textarea id="scanner-output" class="scanner-textarea" placeholder="Paste scanner output here..."></textarea>
          <button class="scanner-btn" onclick="uploadResults()">Upload &amp; Grade</button>
        </div>
      </div>
    </div>

  </div>

  <!-- ====== Sub-tab B: Built-in Scanner ====== -->
  <div id="scanner-builtin-panel" style="display:none">

    <!-- Context Banner -->
    <div class="section">
      <h2>// Glitch Built-in Scanner</h2>
      <p style="color:#888;font-size:0.85em;margin-bottom:8px">
        Run the glitch server's own vulnerability scanner against a target. This scanner knows every vulnerability the server emulates and can verify coverage, resilience, and evasion handling.
      </p>
      <div style="display:flex;align-items:center;gap:10px;margin-top:8px">
        <label style="color:#aaa;font-size:0.85em">Target:</label>
        <input type="text" id="builtin-target" placeholder="http://localhost:8765"
          value="" style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;flex:1">
      </div>
    </div>

    <!-- Scan Profile -->
    <div class="section">
      <h2>// Scan Profile</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
        <div class="profile-card selected" onclick="selectBuiltinProfile(this,'compliance')">
          <input type="radio" name="builtin-profile" value="compliance" checked style="display:none">
          <div class="profile-name">Compliance</div>
          <div class="profile-desc">Methodical scan with minimal load. Suitable for baseline audits.</div>
          <div class="profile-stats">Workers: 2 | Rate: 10 req/s | Evasion: none</div>
        </div>
        <div class="profile-card" onclick="selectBuiltinProfile(this,'aggressive')">
          <input type="radio" name="builtin-profile" value="aggressive" style="display:none">
          <div class="profile-name">Aggressive</div>
          <div class="profile-desc">High-speed scan with many workers. Maximum throughput.</div>
          <div class="profile-stats">Workers: 50 | Rate: 500 req/s | Evasion: none</div>
        </div>
        <div class="profile-card" onclick="selectBuiltinProfile(this,'stealth')">
          <input type="radio" name="builtin-profile" value="stealth" style="display:none">
          <div class="profile-name">Stealth</div>
          <div class="profile-desc">Low and slow with advanced evasion. Avoids detection.</div>
          <div class="profile-stats">Workers: 1 | Rate: 2 req/s | Evasion: advanced</div>
        </div>
        <div class="profile-card" onclick="selectBuiltinProfile(this,'nightmare')">
          <input type="radio" name="builtin-profile" value="nightmare" style="display:none">
          <div class="profile-name" style="color:#ff4444">Nightmare</div>
          <div class="profile-desc" style="color:#ff8866">Unlimited rate, full evasion, maximum chaos. <strong style="color:#ff4444">Will generate extreme load.</strong></div>
          <div class="profile-stats" style="color:#ff6644">Workers: 100 | Rate: unlimited | Evasion: nightmare</div>
        </div>
      </div>
    </div>

    <!-- Attack Modules -->
    <div class="section">
      <h2>// Attack Modules</h2>
      <div style="display:flex;gap:8px;margin-bottom:10px">
        <button class="scanner-btn" style="padding:4px 14px;font-size:0.78em" onclick="toggleAllModules(true)">Select All</button>
        <button class="scanner-btn" style="padding:4px 14px;font-size:0.78em;background:#333;color:#ccc" onclick="toggleAllModules(false)">Deselect All</button>
        <span id="builtin-module-count" style="color:#555;font-size:0.8em;line-height:28px;margin-left:8px">Loading modules...</span>
      </div>
      <div id="builtin-modules" style="background:#0d0d0d;border:1px solid #222;border-radius:8px;max-height:300px;overflow-y:auto">
        <div style="color:#555;padding:12px;text-align:center">Loading modules...</div>
      </div>
    </div>

    <!-- Run Controls -->
    <div class="section">
      <h2>// Run Controls</h2>
      <div id="builtin-run-summary" style="color:#888;font-size:0.85em;margin-bottom:10px">
        Profile: <span style="color:#0ff">compliance</span> |
        Modules: <span id="builtin-selected-count" style="color:#0ff">0</span> selected |
        Target: <span id="builtin-target-display" style="color:#0ff">-</span>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <button class="scanner-btn" id="builtin-run-btn" style="background:#0aa;color:#000;font-weight:bold;padding:10px 28px" onclick="runBuiltinScan()">Run Glitch Scanner</button>
        <button class="scanner-btn" id="builtin-stop-btn" style="background:#a00;color:#fff;display:none;padding:10px 28px" onclick="stopBuiltinScan()">Stop Scan</button>
      </div>
      <div id="builtin-progress-wrap" style="display:none;margin-top:12px">
        <div class="builtin-progress">
          <div class="builtin-progress-bar" id="builtin-progress-bar" style="width:0%%"></div>
          <div class="builtin-progress-text" id="builtin-progress-text">0%%</div>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:0.8em;color:#666;margin-top:4px">
          <span id="builtin-status-text">Idle</span>
          <span id="builtin-elapsed">0s</span>
          <span id="builtin-req-count">0 requests</span>
          <span id="builtin-finding-count">0 findings</span>
        </div>
      </div>
    </div>

    <!-- Scan Results -->
    <div class="section" id="builtin-results-section" style="display:none">
      <h2>// Scan Results</h2>
      <div id="builtin-results-cards" style="margin-bottom:14px"></div>
      <div id="builtin-coverage-table" style="margin-bottom:14px"></div>
      <div id="builtin-scores" style="margin-bottom:14px"></div>
      <div id="builtin-findings-table"></div>
    </div>

    <!-- Scan History -->
    <div class="section">
      <h2>// Scan History</h2>
      <div class="tbl-scroll" style="max-height:300px">
        <table>
          <thead><tr>
            <th>Timestamp</th>
            <th>Profile</th>
            <th>Findings</th>
            <th>Coverage</th>
            <th>Resilience</th>
          </tr></thead>
          <tbody id="builtin-history-body"></tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- ====== Sub-tab C: PCAP Replay ====== -->
  <div id="scanner-replay-panel" style="display:none">

    <!-- Upload Section -->
    <div class="section">
      <h2>// Upload Capture</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div class="card">
          <div class="label" style="margin-bottom:8px">Upload File</div>
          <div style="display:flex;gap:8px;align-items:center">
            <input type="file" id="replay-upload-file" accept=".pcap,.jsonl"
              style="display:none" onchange="document.getElementById('replay-upload-filename').textContent=this.files[0]?this.files[0].name:'No file chosen'">
            <label for="replay-upload-file" class="scanner-btn" id="replay-upload-label" style="white-space:nowrap;cursor:pointer;margin:0">Choose File</label>
            <span id="replay-upload-filename" style="color:#0f8;font-size:0.82em;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">No file chosen</span>
            <button class="scanner-btn" onclick="replayUpload()" style="white-space:nowrap;margin:0">Upload</button>
          </div>
          <div style="color:#555;font-size:0.72em;margin-top:4px">Accepts .pcap and .jsonl files (max 100 MB)</div>
        </div>
        <div class="card">
          <div class="label" style="margin-bottom:8px">Load from URL</div>
          <div style="display:flex;gap:8px;align-items:center">
            <input type="text" id="replay-fetch-url" placeholder="https://example.com/capture.pcap"
              style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;flex:1">
            <button class="scanner-btn" onclick="replayFetchURL()" style="white-space:nowrap">Fetch</button>
          </div>
          <div style="color:#555;font-size:0.72em;margin-top:4px">Download a .pcap or .jsonl from a remote URL</div>
        </div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <div class="label" style="white-space:nowrap">Cleanup:</div>
        <input type="number" id="replay-cleanup-size" value="500" min="1" max="10000" step="10"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100px">
        <span style="color:#555;font-size:0.78em">MB limit</span>
        <button class="scanner-btn danger" onclick="replayCleanup()" title="Remove oldest capture files until total size is under the MB limit">Trim to Size Limit</button>
      </div>
    </div>

    <!-- Capture Files List -->
    <div class="section">
      <h2>// Capture Files</h2>
      <div style="margin-bottom:12px">
        <button class="scanner-btn" onclick="refreshReplayFiles()">Refresh</button>
      </div>
      <div class="tbl-scroll" style="max-height:300px">
        <table>
          <thead><tr><th>File</th><th>Size</th><th>Modified</th><th>Action</th></tr></thead>
          <tbody id="replay-files-body"></tbody>
        </table>
      </div>
    </div>

    <!-- PCAP Metadata -->
    <div class="section" id="replay-metadata-section" style="display:none">
      <h2>// Capture Metadata</h2>
      <div class="grid" id="replay-metadata-cards"></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px">
        <div id="replay-meta-methods" style="background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;padding:12px"></div>
        <div id="replay-meta-paths" style="background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;padding:12px"></div>
      </div>
      <div id="replay-meta-protocols" style="margin-top:8px;background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;padding:12px;font-size:0.82em;color:#888"></div>
    </div>

    <!-- Replay Target -->
    <div class="section">
      <h2>// Replay Target</h2>
      <div style="margin-bottom:8px;color:#888;font-size:0.82em">Requests will be replayed against this URL</div>
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px">
        <span class="label" style="white-space:nowrap">Target URL</span>
        <input type="text" id="replay-target" placeholder="http://localhost:8765" value="http://localhost:8765"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.85em;flex:1">
      </div>
      <div id="replay-target-display" style="font-size:0.82em;color:#555"></div>
    </div>

    <!-- Playback Controls -->
    <div class="section">
      <h2>// Playback Controls</h2>
      <div class="grid">
        <div class="card">
          <div class="label">Timing Mode</div>
          <select id="replay-timing" class="ctrl-select" style="margin-top:6px">
            <option value="burst">Burst (all at once)</option>
            <option value="exact">Exact (original timing)</option>
            <option value="scaled">Scaled (adjustable speed)</option>
          </select>
        </div>
        <div class="card">
          <div class="label">Speed</div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
            <input type="range" id="replay-speed" min="0.1" max="10" step="0.1" value="1.0"
              oninput="document.getElementById('replay-speed-val').textContent=this.value+'x'"
              style="flex:1;accent-color:#00ff88;">
            <span id="replay-speed-val" style="color:#00ffcc;font-weight:bold;min-width:36px">1x</span>
          </div>
          <div style="display:flex;gap:4px;margin-top:6px">
            <button class="cfg-btn" onclick="setReplaySpeed(1)" style="padding:4px 10px;font-size:0.75em">1x</button>
            <button class="cfg-btn" onclick="setReplaySpeed(2)" style="padding:4px 10px;font-size:0.75em">2x</button>
            <button class="cfg-btn" onclick="setReplaySpeed(5)" style="padding:4px 10px;font-size:0.75em">5x</button>
            <button class="cfg-btn" onclick="document.getElementById('replay-timing').value='burst'" style="padding:4px 10px;font-size:0.75em">Burst</button>
          </div>
        </div>
        <div class="card">
          <div class="label">Filter Path</div>
          <input type="text" id="replay-filter" placeholder="/api/ (substring match)" style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%;margin-top:6px">
        </div>
        <div class="card">
          <div class="label">Loop</div>
          <label style="display:flex;align-items:center;gap:8px;margin-top:6px;cursor:pointer">
            <input type="checkbox" id="replay-loop" style="accent-color:#00ff88;width:18px;height:18px">
            <span style="color:#888;font-size:0.82em">Repeat when finished</span>
          </label>
        </div>
      </div>
      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="scanner-btn" onclick="replayStart()" id="replay-play-btn">Play</button>
        <button class="scanner-btn danger" onclick="replayStop()" id="replay-stop-btn">Stop</button>
      </div>
    </div>

    <!-- Playback Status -->
    <div class="section">
      <h2>// Playback Status</h2>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <div id="replay-state-badge" style="background:#222;color:#666;padding:6px 16px;border-radius:20px;font-size:0.85em;font-weight:bold;letter-spacing:0.5px">STOPPED</div>
        <div id="replay-state-detail" style="color:#888;font-size:0.82em"></div>
      </div>
      <div style="background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;height:28px;overflow:hidden;position:relative;margin-bottom:12px">
        <div id="replay-progress-bar" style="height:100%%;background:linear-gradient(90deg,#00aa66,#00ff88);width:0%%;transition:width 0.5s;border-radius:6px"></div>
        <div id="replay-progress-text" style="position:absolute;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;font-size:0.78em;color:#ccc;font-weight:bold">0 / 0 packets</div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Packets Loaded</div><div class="value v-info" id="replay-loaded">0</div></div>
        <div class="card"><div class="label">Packets Played</div><div class="value v-ok" id="replay-played">0</div></div>
        <div class="card"><div class="label">Errors</div><div class="value v-err" id="replay-errors">0</div></div>
        <div class="card"><div class="label">Elapsed</div><div class="value v-info" id="replay-elapsed">0ms</div></div>
        <div class="card"><div class="label">Loaded File</div><div class="value" id="replay-loaded-file" style="font-size:0.85em;color:#888">None</div></div>
      </div>
    </div>

  </div>
</div>

<!-- ==================== PROXY TAB ==================== -->
<div id="panel-proxy" class="panel">
  <!-- Proxy Status Bar -->
  <div style="display:flex;align-items:center;justify-content:space-between;background:#111;border:1px solid #ffaa0033;border-radius:6px;padding:10px 16px;margin-bottom:14px;font-size:0.82em">
    <span style="color:#ffaa00;font-weight:bold">PROXY STATUS: <span id="proxy-status-text">TRANSPARENT</span></span>
    <span style="color:#888" id="proxy-status-detail">--</span>
    <span id="proxy-runtime-badge" style="padding:3px 10px;border-radius:12px;font-size:0.78em;background:#33000033;border:1px solid #333;color:#666">STOPPED</span>
    <button class="nightmare-btn" onclick="toggleNightmareMode('proxy')" id="proxy-nightmare-btn" style="padding:4px 12px;font-size:0.85em">Nightmare: OFF</button>
  </div>

  <!-- Runtime Controls -->
  <div class="section" style="border-color:#ffaa0033">
    <h2>// Runtime Controls</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Start/stop the proxy process. Set the listen port and backend target before starting.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:12px;align-items:end">
      <div>
        <div class="label" style="margin-bottom:4px">Listen Port</div>
        <input type="number" id="proxy-rt-port" value="8080" min="1" max="65535"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%">
      </div>
      <div>
        <div class="label" style="margin-bottom:4px">Backend Target</div>
        <input type="text" id="proxy-rt-target" placeholder="http://localhost:8765" value="http://localhost:8765"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%">
      </div>
      <div>
        <div class="label" style="margin-bottom:4px">Uptime</div>
        <div id="proxy-rt-uptime" style="color:#888;font-size:0.9em;padding:6px 0">--</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="scanner-btn" id="proxy-rt-start-btn" onclick="startProxy()" style="white-space:nowrap">Start Proxy</button>
        <button class="scanner-btn danger" id="proxy-rt-stop-btn" onclick="stopProxy()" style="display:none;white-space:nowrap">Stop</button>
        <button class="cfg-btn" id="proxy-rt-restart-btn" onclick="restartProxy()" style="display:none;white-space:nowrap">Restart</button>
      </div>
    </div>
    <div id="proxy-rt-stats" style="margin-top:8px;display:none">
      <div class="grid">
        <div class="card"><div class="label">Requests</div><div class="value v-ok" id="proxy-rt-reqs">0</div></div>
        <div class="card"><div class="label">Uptime</div><div class="value v-info" id="proxy-rt-uptime-card">0s</div></div>
        <div class="card"><div class="label">Mode</div><div class="value v-warn" id="proxy-rt-mode">--</div></div>
      </div>
    </div>
  </div>

  <!-- Proxy Recording -->
  <div class="section" style="border-color:#ffaa0033">
    <h2>// Proxy Traffic Recording</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Record proxy traffic to JSONL or PCAP files. Set limits to auto-stop, or leave at 0 for unlimited.</p>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <select id="proxy-rec-format" class="ctrl-select" style="min-width:80px">
        <option value="jsonl">JSONL</option>
        <option value="pcap">PCAP</option>
      </select>
      <div style="display:flex;align-items:center;gap:4px"><span class="label">Duration:</span>
        <input type="number" id="proxy-rec-dur" value="0" min="0" max="86400" step="60"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:4px 8px;border-radius:4px;font-family:inherit;font-size:0.82em;width:80px" title="0 = unlimited"><span style="color:#555;font-size:0.78em">sec</span></div>
      <div style="display:flex;align-items:center;gap:4px"><span class="label">Requests:</span>
        <input type="number" id="proxy-rec-reqs" value="0" min="0" max="10000000" step="1000"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:4px 8px;border-radius:4px;font-family:inherit;font-size:0.82em;width:80px" title="0 = unlimited"></div>
      <button class="scanner-btn" id="proxy-rec-start-btn" onclick="startRecording()">Record</button>
      <button class="scanner-btn danger" id="proxy-rec-stop-btn" onclick="stopRecording()" style="display:none">Stop</button>
      <span id="proxy-rec-status" style="font-size:0.82em;color:#555">Idle</span>
    </div>
  </div>

  <div class="grid" id="proxy-metrics"></div>

  <!-- Proxy Configuration -->
  <div class="section">
    <h2>// Proxy Configuration</h2>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div class="card">
        <div class="label" style="margin-bottom:6px">Upstream Target</div>
        <input type="text" id="proxy-upstream" placeholder="http://localhost:8765" value="http://localhost:8765"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%">
        <div style="color:#555;font-size:0.72em;margin-top:4px">URL the proxy forwards requests to</div>
      </div>
      <div class="card">
        <div class="label" style="margin-bottom:6px">Listen Address</div>
        <input type="text" id="proxy-listen" placeholder="0.0.0.0:8080" value="0.0.0.0:8080"
          style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%">
        <div style="color:#555;font-size:0.72em;margin-top:4px">Address:port the proxy listens on</div>
      </div>
    </div>
  </div>

  <!-- Mode Selection -->
  <div class="section">
    <h2>// Mode Selection</h2>
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;" id="proxy-mode-radios">
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">TRANSPARENT</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">Pass-through, no modification</div>
        </div>
        <input type="radio" name="proxy-mode" value="transparent" onchange="setProxyMode(this.value)" checked style="accent-color:#00ff88;">
      </label>
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">WAF</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">Web Application Firewall filtering</div>
        </div>
        <input type="radio" name="proxy-mode" value="waf" onchange="setProxyMode(this.value)" style="accent-color:#00ff88;">
      </label>
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">CHAOS</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">Random latency, corruption, drops</div>
        </div>
        <input type="radio" name="proxy-mode" value="chaos" onchange="setProxyMode(this.value)" style="accent-color:#00ff88;">
      </label>
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">GATEWAY</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">API gateway with rate limiting</div>
        </div>
        <input type="radio" name="proxy-mode" value="gateway" onchange="setProxyMode(this.value)" style="accent-color:#00ff88;">
      </label>
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">NIGHTMARE</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">Maximum chaos, all glitches active</div>
        </div>
        <input type="radio" name="proxy-mode" value="nightmare" onchange="setProxyMode(this.value)" style="accent-color:#00ff88;">
      </label>
      <label class="toggle-row" style="cursor:pointer;">
        <div>
          <div class="toggle-name">MIRROR SERVER</div>
          <div style="color:#555;font-size:0.72em;margin-top:2px;">Copy server behavior settings</div>
        </div>
        <input type="radio" name="proxy-mode" value="mirror" onchange="setProxyMode(this.value)" style="accent-color:#00ff88;">
      </label>
    </div>
    <div id="proxy-mode-desc" style="margin-top:10px;padding:10px 14px;background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;font-size:0.82em;color:#888"></div>
  </div>

  <!-- Mirror Server Settings -->
  <div class="section" id="proxy-mirror-section" style="display:none">
    <h2>// Mirrored Server Settings</h2>
    <div style="margin-bottom:10px;color:#888;font-size:0.82em">
      The proxy is mirroring the server's behavior settings. Responses will use the same error types, page types, and chaos parameters as the server.
    </div>
    <button class="quick-action-btn" onclick="refreshMirror()" style="margin-bottom:12px">Refresh from Server</button>
    <div id="proxy-mirror-info" class="grid"></div>
    <div id="proxy-mirror-time" style="color:#555;font-size:0.72em;margin-top:8px"></div>
  </div>

  <!-- WAF Settings -->
  <div class="section">
    <h2>// WAF Settings</h2>
    <div id="proxy-waf-status">
      <div style="color:#555">WAF not enabled. Select WAF, Gateway, or Nightmare mode to activate.</div>
    </div>
    <div id="proxy-waf-settings" style="display:none;margin-top:12px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="card">
          <div class="label" style="margin-bottom:6px">WAF Block Action</div>
          <select id="proxy-waf-action" class="ctrl-select" onchange="setWafBlockAction(this.value)">
            <option value="block">Block</option>
            <option value="log">Log Only</option>
            <option value="challenge">Challenge</option>
            <option value="reject" selected>Reject</option>
            <option value="tarpit">Tarpit</option>
            <option value="redirect">Redirect</option>
          </select>
        </div>
        <div class="card">
          <div class="label" style="margin-bottom:6px">Rate Limit (req/sec)</div>
          <input type="number" id="proxy-waf-ratelimit" value="100" min="1" max="100000" step="10"
            style="background:#0d0d0d;color:#0f8;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:0.82em;width:100%%">
        </div>
      </div>
    </div>
  </div>

  <!-- Chaos Configuration -->
  <div class="section">
    <h2>// Chaos Configuration</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Probability of injecting latency, corruption, drops, or resets into proxied traffic. Only applies in Chaos, Gateway, and Nightmare modes.</p>
    <div id="proxy-chaos-sliders"></div>
  </div>

  <!-- Connection Info -->
  <div class="section">
    <h2>// Connection Info</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Live proxy connection statistics.</p>
    <div class="grid" id="proxy-connection-info">
      <div class="card"><div class="label">Active Connections</div><div class="value v-info" id="proxy-active-conns">0</div></div>
      <div class="card"><div class="label">Requests Forwarded</div><div class="value v-ok" id="proxy-fwd-reqs">0</div></div>
      <div class="card"><div class="label">Requests Blocked</div><div class="value v-err" id="proxy-blocked-reqs">0</div></div>
    </div>
  </div>

  <!-- Pipeline Stats -->
  <div class="section">
    <h2>// Pipeline Stats</h2>
    <p style="color:#555;font-size:0.72em;margin-bottom:8px">Per-interceptor request/response counts and block rates in the proxy pipeline.</p>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead><tr>
          <th>Interceptor</th>
          <th>Requests</th>
          <th>Responses</th>
          <th>Blocked</th>
          <th>Avg Latency</th>
        </tr></thead>
        <tbody id="proxy-pipeline-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== SETTINGS TAB ==================== -->
<div id="panel-settings" class="panel">
  <div class="section">
    <h2>// Admin Password</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:12px">Change the admin panel password. Current password is required.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;max-width:800px">
      <div>
        <div class="label" style="margin-bottom:4px">Current Password</div>
        <input type="password" id="settings-current-pw" class="settings-input" placeholder="Current password">
      </div>
      <div>
        <div class="label" style="margin-bottom:4px">New Password</div>
        <input type="password" id="settings-new-pw" class="settings-input" placeholder="New password (min 4 chars)">
      </div>
      <div>
        <div class="label" style="margin-bottom:4px">Confirm Password</div>
        <input type="password" id="settings-confirm-pw" class="settings-input" placeholder="Confirm new password">
      </div>
    </div>
    <button class="scanner-btn" onclick="changePassword()" style="margin-top:12px">Change Password</button>
    <div id="settings-pw-status" style="font-size:0.82em;margin-top:8px;color:#555"></div>
  </div>

  <div class="section">
    <h2>// Configuration Import / Export</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:8px">Save or restore the entire server configuration as a JSON file.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <button class="cfg-btn primary" onclick="exportConfig()">Export Config</button>
      <button class="cfg-btn" onclick="document.getElementById('cfg-import-file').click()">Import Config</button>
      <input type="file" id="cfg-import-file" accept=".json" style="display:none" onchange="importConfigFile(this)">
    </div>
    <div id="cfg-import-status" style="color:#555;font-size:0.82em">Select a JSON config file to restore server settings</div>
  </div>

  <div class="section">
    <h2>// Recording Format</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:8px">File format for recorded traffic captures.</p>
    <select id="ctrl-recorder-format" class="ctrl-select" style="max-width:200px" onchange="setConfigKey('recorder_format', this.value)">
      <option value="jsonl">JSONL</option>
      <option value="pcap">PCAP</option>
    </select>
  </div>

  <div class="section">
    <h2>// Server Info</h2>
    <div class="grid" id="settings-info">
      <div class="card"><div class="label">Server Port</div><div class="value v-info" style="font-size:1em" id="settings-server-port">--</div></div>
      <div class="card"><div class="label">Dashboard Port</div><div class="value v-info" style="font-size:1em" id="settings-dash-port">--</div></div>
      <div class="card"><div class="label">Uptime</div><div class="value v-ok" style="font-size:1em" id="settings-uptime">--</div></div>
      <div class="card"><div class="label">Go Version</div><div class="value" style="font-size:1em;color:#888">1.24+</div></div>
    </div>
  </div>
</div>

<div class="crash-overlay" id="crash-overlay" onclick="if(event.target===this)closeCrashModal()">
  <div class="crash-modal" id="crash-modal-content"></div>
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
    var panel = document.getElementById('panel-' + name);
    if (panel) panel.classList.add('active');
    var tabBtn = document.querySelector('.tab[onclick*="' + name + '"]');
    if (tabBtn) tabBtn.classList.add('active');
    if (pushHash !== false) window.location.hash = '#' + name;
  };

  window.addEventListener('hashchange', function() {
    var tab = window.location.hash.replace('#', '');
    if (tab && document.getElementById('panel-' + tab)) showTab(tab, false);
  });

  // ------ Server section toggle ------
  window.toggleServerSection = function(name) {
    var sec = document.getElementById('srv-' + name);
    if (sec) sec.classList.toggle('open');
  };

  // ------ Scanner sub-tab switch (3 tabs now) ------

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
    if (res.status === 401) { window.location.href = '/admin/login'; throw new Error('session expired'); }
    if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + res.statusText);
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
      var totalReqs = m.total_requests || 0;
      var uptimeSec = m.uptime_seconds || 1;
      var avgRps = (m.current_rps !== undefined ? m.current_rps : (totalReqs / uptimeSec)).toFixed(1);
      var avgLatMs = m.avg_latency_ms || 0;
      var p95Lat = m.p95_latency_ms || avgLatMs * 2;
      document.getElementById('dash-metrics').innerHTML =
        card('Total Requests', totalReqs.toLocaleString(), 'v-ok') +
        card('Req/s', avgRps, 'v-info') +
        card('Active Connections', m.active_connections||0, 'v-info') +
        card('2xx', (m.total_2xx||0).toLocaleString(), 'v-ok') +
        card('4xx', (m.total_4xx||0).toLocaleString(), 'v-warn') +
        card('5xx', (m.total_5xx||0).toLocaleString(), 'v-err') +
        card('Error Rate', ((m.error_rate_pct||0).toFixed(1)) + '%%', (m.error_rate_pct||0) > 10 ? 'v-err' : 'v-ok') +
        card('Labyrinth Hits', (m.total_labyrinth||0).toLocaleString(), 'v-info') +
        card('Unique Clients', m.unique_clients||0, 'v-info') +
        card('Uptime', fmtUptime(m.uptime_seconds), 'v-ok');

      // Uptime in header
      var uptimeEl = document.getElementById('header-uptime');
      if (uptimeEl && m.uptime_seconds) uptimeEl.textContent = 'uptime: ' + fmtUptime(m.uptime_seconds);

      // Mode cards
      var srvStatus = document.getElementById('dash-server-status');
      var srvDetail = document.getElementById('dash-server-detail');
      if (srvStatus) srvStatus.textContent = 'RUNNING';
      if (srvDetail) srvDetail.textContent = (m.total_requests||0).toLocaleString() + ' reqs | ' + ((m.error_rate_pct||0).toFixed(1)) + '%% err | ' + (m.unique_clients||0) + ' clients';

      // Scanner mode card
      try {
        var scanData = await api('/admin/api/scanner/builtin/status');
        var scanStatus = document.getElementById('dash-scanner-status');
        var scanDetail = document.getElementById('dash-scanner-detail');
        if (scanData.running) {
          if (scanStatus) scanStatus.textContent = 'SCANNING';
          if (scanDetail) scanDetail.textContent = (scanData.progress||0) + '%% complete';
        } else {
          if (scanStatus) scanStatus.textContent = 'IDLE';
          if (scanDetail) scanDetail.textContent = scanData.last_profile ? 'Last: ' + scanData.last_profile : 'No active scans';
        }
      } catch(se) {}

      // Proxy mode card — check runtime status first
      try {
        var proxyStatus = document.getElementById('dash-proxy-status');
        var proxyDetail = document.getElementById('dash-proxy-detail');
        try {
          var rtData = await api('/admin/api/proxy/runtime');
          if (rtData.running) {
            if (proxyStatus) proxyStatus.textContent = (rtData.mode || 'TRANSPARENT').toUpperCase();
            if (proxyDetail) proxyDetail.textContent = ':' + (rtData.port||8080) + ' | ' + (rtData.requests||0) + ' reqs';
          } else {
            if (proxyStatus) proxyStatus.textContent = 'STOPPED';
            if (proxyDetail) proxyDetail.textContent = 'Proxy not running';
          }
        } catch(rte) {
          var proxyData = await api('/admin/api/proxy/status');
          var pMode = (proxyData.mode || 'transparent').toUpperCase();
          if (proxyStatus) proxyStatus.textContent = pMode;
          var pStats = proxyData.pipeline_stats || {};
          if (proxyDetail) proxyDetail.textContent = (pStats.requests_processed||0) + ' fwd | ' + (pStats.requests_blocked||0) + ' blocked';
        }
      } catch(pe) {}

      // Throughput sparkline
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

      // Error rate sparkline
      const errWrap = document.getElementById('dash-err-sparkline');
      if (series.length > 0 && errWrap) {
        const maxE = Math.max(...series.map(s => s.errors || 0), 1);
        const ebw = Math.max(2, Math.floor(errWrap.clientWidth / series.length) - 1);
        errWrap.innerHTML = series.map((s, i) => {
          const h = Math.max(2, ((s.errors || 0) / maxE) * 100);
          return '<div class="spark-bar err" style="left:' + (i*(ebw+1)) + 'px;width:' + ebw + 'px;height:' + h + '%%;" title="' + (s.errors||0) + ' err"></div>';
        }).join('');
      }

      // Calculated statistics
      var recentReqs = series.reduce(function(a,s){return a+s.requests},0);
      var recentErrs = series.reduce(function(a,s){return a+(s.errors||0)},0);
      var recentAvg = series.length > 0 ? series.reduce(function(a,s){return a+(s.avg_ms||0)},0)/series.length : 0;
      var curRps = series.length > 1 ? series[series.length-1].requests : 0;
      var recentErrRate = recentReqs > 0 ? (recentErrs/recentReqs*100).toFixed(1) : '0.0';
      document.getElementById('dash-calc-stats').innerHTML =
        card('Current RPS', curRps.toLocaleString(), 'v-ok') +
        card('60s Requests', recentReqs.toLocaleString(), 'v-info') +
        card('60s Errors', recentErrs.toLocaleString(), recentErrs > 0 ? 'v-err' : 'v-ok') +
        card('60s Error Rate', recentErrRate + '%%', parseFloat(recentErrRate) > 10 ? 'v-err' : 'v-ok') +
        card('Avg Latency', recentAvg.toFixed(1) + 'ms', recentAvg > 500 ? 'v-err' : 'v-ok');

      // Status code and response type distributions from overview
      try {
        var ov = await api('/admin/api/overview');
        var statusCodes = ov.status_codes || [];
        var totalSC = statusCodes.reduce(function(a,c){return a+c.count},0) || 1;
        document.getElementById('dash-status-bars').innerHTML = statusCodes.map(function(c) {
          var pct = (c.count / totalSC * 100).toFixed(1);
          var color = c.code >= 500 ? '#ff4444' : c.code >= 400 ? '#ffaa00' : c.code >= 300 ? '#4488ff' : '#00ff88';
          return '<div class="bar-row"><div class="bar-label">' + c.code + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%%;background:' + color + '"></div></div>' +
            '<div class="bar-count">' + c.count + ' (' + pct + '%%)</div></div>';
        }).join('') || '<div style="color:#555">No data</div>';

        var types = ov.response_types || [];
        var totalT = types.reduce(function(a,t){return a+t.count},0) || 1;
        document.getElementById('dash-resp-types').innerHTML = types.map(function(t) {
          var pct = (t.count / totalT * 100).toFixed(1);
          return '<div class="bar-row"><div class="bar-label">' + escapeHtml(t.key||'unknown') + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%%"></div></div>' +
            '<div class="bar-count">' + t.count + ' (' + pct + '%%)</div></div>';
        }).join('') || '<div style="color:#555">No data</div>';
      } catch(oe) {}

      // Three-column mode cards
      var srvCards = document.getElementById('dash-srv-cards');
      if (srvCards) srvCards.innerHTML =
        card('Requests', (m.total_requests||0).toLocaleString(), 'v-ok') +
        card('Error Rate', ((m.error_rate_pct||0).toFixed(1)) + '%%', (m.error_rate_pct||0) > 10 ? 'v-err' : 'v-ok') +
        card('2xx/4xx/5xx', (m.total_2xx||0) + '/' + (m.total_4xx||0) + '/' + (m.total_5xx||0), 'v-info') +
        card('Labyrinth', (m.total_labyrinth||0).toLocaleString(), 'v-info');

      // Scanner column cards
      try {
        var scanData2 = await api('/admin/api/scanner/builtin/status');
        var scanCards = document.getElementById('dash-scan-cards');
        var scanDetailExt = document.getElementById('dash-scan-detail');
        if (scanCards) {
          if (scanData2.running) {
            scanCards.innerHTML = card('Status', 'SCANNING', 'v-warn') + card('Progress', (scanData2.progress||0) + '%%', 'v-info');
            if (scanDetailExt) scanDetailExt.textContent = 'Profile: ' + (scanData2.profile||'default') + ' | Target: ' + (scanData2.target||'-');
          } else {
            scanCards.innerHTML = card('Status', 'IDLE', 'v-ok') + card('Last', scanData2.last_profile||'none', 'v-info');
            if (scanDetailExt) scanDetailExt.textContent = scanData2.last_profile ? 'Completed: ' + (scanData2.last_profile||'') : 'No scans run';
          }
        }
      } catch(se2) {}

      // Proxy column cards
      try {
        var proxyCards = document.getElementById('dash-proxy-cards');
        var proxyDetailExt = document.getElementById('dash-proxy-detail-ext');
        try {
          var rtData2 = await api('/admin/api/proxy/runtime');
          if (proxyCards) {
            if (rtData2.running) {
              proxyCards.innerHTML = card('Mode', (rtData2.mode||'transparent').toUpperCase(), 'v-ok') + card('Requests', (rtData2.requests||0).toLocaleString(), 'v-info');
              if (proxyDetailExt) proxyDetailExt.textContent = 'Port: ' + (rtData2.port||8080) + ' | Target: ' + (rtData2.target||'-');
            } else {
              proxyCards.innerHTML = card('Status', 'STOPPED', 'v-warn') + card('Requests', '0', 'v-info');
              if (proxyDetailExt) proxyDetailExt.textContent = 'Proxy not running';
            }
          }
        } catch(rte2) {
          var proxyData2 = await api('/admin/api/proxy/status');
          var pStats2 = proxyData2.pipeline_stats || {};
          if (proxyCards) proxyCards.innerHTML = card('Mode', (proxyData2.mode||'transparent').toUpperCase(), 'v-ok') + card('Forwarded', (pStats2.requests_processed||0).toLocaleString(), 'v-info');
          if (proxyDetailExt) proxyDetailExt.textContent = (pStats2.requests_blocked||0) + ' blocked';
        }
      } catch(pe2) {}

      // Traffic analytics (top paths + top UAs)
      try {
        var ov2 = await api('/admin/api/overview');
        var topPaths = ov2.top_paths || [];
        var maxP = topPaths.length > 0 ? topPaths[0].count : 1;
        document.getElementById('dash-top-paths').innerHTML = topPaths.slice(0, 10).map(function(p) {
          return '<div class="bar-row"><div class="bar-label" title="' + escapeHtml(p.key) + '">' + escapeHtml(p.key.substring(0, 30)) + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxP*100) + '%%"></div></div>' +
            '<div class="bar-count">' + p.count + '</div></div>';
        }).join('') || '<div style="color:#555">No data yet</div>';

        var topUA = ov2.top_user_agents || [];
        var maxUA = topUA.length > 0 ? topUA[0].count : 1;
        document.getElementById('dash-top-ua').innerHTML = topUA.slice(0, 10).map(function(u) {
          return '<div class="bar-row"><div class="bar-label" title="' + escapeHtml(u.key) + '">' + escapeHtml(u.key.substring(0, 30)) + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + (u.count/maxUA*100) + '%%"></div></div>' +
            '<div class="bar-count">' + u.count + '</div></div>';
        }).join('') || '<div style="color:#555">No data yet</div>';
      } catch(oe2) {}

      // Clickable clients table
      const clients = (cl.clients || []).sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen) || (a.client_id || '').localeCompare(b.client_id || ''));
      document.getElementById('dash-clients-body').innerHTML = clients.slice(0, 20).map(function(c) {
        var cid = escapeHtml(c.client_id);
        var short = escapeHtml(shortID(c.client_id));
        var ago = timeSince(c.last_seen);
        return '<tr style="cursor:pointer" onclick="dashViewClient(\'' + cid + '\')">' +
        '<td><a href="#" onclick="event.stopPropagation();dashViewClient(\'' + cid + '\');return false" style="color:#44aaff">' + short + '</a></td>' +
        '<td>' + c.total_requests + '</td>' +
        '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
        '<td class="' + (c.errors_received > 0 ? 's5' : '') + '">' + c.errors_received + '</td>' +
        '<td class="' + mClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
        '<td style="color:#888">' + ago + '</td>' +
        '</tr>';
      }).join('');

      // Request log (dashboard)
      try {
        var logResp = await api('/admin/api/log?limit=200');
        dashLogData = logResp.records || [];
        renderDashLog(dashLogData);
      } catch(le) {}
    } catch(e) { console.error('dashboard:', e); }
  }

  // ------ Dashboard Log + Client Detail ------
  var dashLogData = [];

  function renderDashLog(records) {
    var tbody = document.getElementById('dash-log-body');
    if (!tbody) return;
    tbody.innerHTML = records.map(function(r) {
      return '<tr class="log-row" data-search="' + escapeHtml((r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent + ' ' + r.mode).toLowerCase()) + '">' +
        '<td>' + new Date(r.timestamp).toLocaleTimeString() + '</td>' +
        '<td><a href="#" onclick="event.stopPropagation();dashViewClient(\'' + escapeHtml(r.client_id) + '\');return false" style="color:#44aaff">' + escapeHtml(shortID(r.client_id)) + '</a></td>' +
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

  window.filterDashLog = function() {
    var q = document.getElementById('dash-log-filter').value.toLowerCase().trim();
    if (!q) { renderDashLog(dashLogData); return; }
    var filtered = dashLogData.filter(function(r) {
      var haystack = (r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent + ' ' + r.mode).toLowerCase();
      return haystack.indexOf(q) !== -1;
    });
    renderDashLog(filtered);
  };

  var dashSelectedClient = null;
  window.dashViewClient = async function(clientID) {
    dashSelectedClient = clientID;
    try {
      var detail = await api('/admin/api/client/' + encodeURIComponent(clientID));
      var panel = document.getElementById('dash-client-detail');
      panel.style.display = 'block';
      document.getElementById('dash-detail-cid').textContent = shortID(detail.client_id || clientID);
      document.getElementById('dash-detail-cards').innerHTML =
        card('Total Requests', detail.total_requests, 'v-ok') +
        card('Req/s', (detail.requests_per_sec||0).toFixed(1), 'v-info') +
        card('Errors', detail.errors_received, detail.errors_received > 0 ? 'v-err' : 'v-ok') +
        card('Unique Paths', detail.unique_paths, 'v-info') +
        card('Mode', detail.adaptive_mode || 'pending', 'v-warn') +
        card('Bot Score', (detail.bot_score||0).toFixed(1), detail.bot_score > 60 ? 'v-err' : 'v-ok') +
        card('Escalation', detail.escalation_level, 'v-warn') +
        card('Labyrinth Depth', detail.labyrinth_depth||0, 'v-info');
      dashSelectedClient = detail.client_id || clientID;
      document.getElementById('dash-override-mode').value = detail.adaptive_mode || '';
      var paths = (detail.all_paths || []).slice(0, 20);
      if (paths.length > 0) {
        var maxC = paths[0].count || 1;
        document.getElementById('dash-detail-paths').innerHTML = '<div style="font-size:0.8em;color:#888;margin-bottom:6px">Top paths:</div>' +
          paths.map(function(p) {
            return '<div class="bar-row">' +
              '<div class="bar-label" title="' + escapeHtml(p.path) + '">' + escapeHtml(p.path.substring(0,40)) + '</div>' +
              '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxC*100) + '%%"></div></div>' +
              '<div class="bar-count">' + p.count + '</div></div>';
          }).join('');
      } else {
        document.getElementById('dash-detail-paths').innerHTML = '<div style="color:#555;font-size:0.8em">No path data</div>';
      }
      if (detail.adaptive_reason) {
        document.getElementById('dash-detail-paths').innerHTML +=
          '<div style="margin-top:10px;color:#888;font-size:0.85em">Reason: ' + escapeHtml(detail.adaptive_reason) + '</div>';
      }
      panel.scrollIntoView({behavior:'smooth',block:'nearest'});
    } catch(e) { console.error('dash client detail:', e); }
  };

  window.dashApplyOverride = async function() {
    var mode = document.getElementById('dash-override-mode').value;
    if (!dashSelectedClient) return;
    if (!mode) { toast('Select a mode first'); return; }
    try {
      await api('/admin/api/override', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: dashSelectedClient, mode: mode})});
      toast('Override applied: ' + mode);
      dashViewClient(dashSelectedClient);
    } catch(e) { console.error('override:', e); }
  };

  window.dashClearOverride = async function() {
    if (!dashSelectedClient) return;
    try {
      await api('/admin/api/override', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: dashSelectedClient, clear: true})});
      document.getElementById('dash-override-mode').value = '';
      toast('Override cleared');
      dashViewClient(dashSelectedClient);
    } catch(e) { console.error('clear override:', e); }
  };

  // ------ Sessions ------
  let selectedClient = null;
  async function refreshSessions() {
    try {
      const data = await api('/api/clients');
      const clients = (data.clients || []);
      clients.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen) || (a.client_id || '').localeCompare(b.client_id || ''));
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
    health: 'Health Endpoints',
    spider: 'Spider / Crawl Data'
  };

  const HTTP_ERROR_TYPES = [
    'none',
    '500_internal','502_bad_gateway','503_unavailable','504_timeout',
    '404_not_found','403_forbidden','429_rate_limit','408_timeout',
    'slow_drip','connection_reset','partial_body','wrong_content_type',
    'garbage_body','empty_body','huge_headers',
    'delay_1s','delay_3s','delay_10s','delay_random',
    'redirect_loop','double_encoding','flip_flop'
  ];
  const TCP_ERROR_TYPES = [
    'packet_drop','tcp_reset','stream_corrupt','session_timeout',
    'keepalive_abuse','tls_half_close','slow_headers','accept_then_fin'
  ];
  const ERROR_TYPES = HTTP_ERROR_TYPES.concat(TCP_ERROR_TYPES);

  const FEATURE_TIPS = {
    labyrinth: 'Generates infinite pages to trap web crawlers and AI scrapers in an endless maze',
    error_inject: 'Randomly injects HTTP errors (5xx, 4xx, timeouts) into responses',
    captcha: 'Shows CAPTCHA challenges when bot-like activity is detected',
    honeypot: 'Serves decoy pages with hidden links to identify automated tools',
    vuln: 'Exposes intentionally vulnerable endpoints (OWASP categories) for scanner testing',
    analytics: 'Injects fake analytics/tracking scripts into served pages',
    cdn: 'Emulates CDN response headers and caching behavior',
    oauth: 'Provides fake OAuth/OpenID Connect authorization endpoints',
    header_corrupt: 'Injects invalid or malformed HTTP headers into responses',
    cookie_traps: 'Sets trap cookies that detect automated cookie handling',
    js_traps: 'Embeds JavaScript challenges to detect headless browsers',
    bot_detection: 'Scores visitors based on behavioral heuristics to identify bots',
    random_blocking: 'Randomly blocks requests with configurable probability',
    framework_emul: 'Mimics server signatures of popular frameworks (Rails, Django, etc.)',
    search: 'Serves fake search engine results pages for crawler testing',
    email: 'Emulates webmail login and inbox pages',
    i18n: 'Serves content in multiple languages with locale detection',
    recorder: 'Records all incoming HTTP traffic for later replay',
    websocket: 'Provides WebSocket upgrade endpoints with test payloads',
    privacy: 'Serves GDPR/privacy consent banners and cookie notices',
    health: 'Exposes health check and status endpoints',
    spider: 'Serves robots.txt, sitemap.xml, favicon.ico and other crawler data files with configurable error injection'
  };

  const SLIDER_TIPS = {
    max_labyrinth_depth: 'Maximum page depth before the labyrinth loops back',
    error_rate_multiplier: 'Multiplies the base error probability (0=no errors, 5=very frequent)',
    captcha_trigger_thresh: 'Number of requests before CAPTCHA is shown',
    block_chance: 'Probability of randomly blocking any individual request',
    block_duration_sec: 'How long a client stays blocked after being randomly selected',
    bot_score_threshold: 'Score above which a visitor is classified as a bot (0-100)',
    header_corrupt_level: 'Severity of header corruption (0=none, 4=extreme)',
    delay_min_ms: 'Minimum artificial response delay in milliseconds',
    delay_max_ms: 'Maximum artificial response delay in milliseconds',
    labyrinth_link_density: 'Number of links generated per labyrinth page',
    adaptive_interval_sec: 'Seconds between adaptive behavior re-evaluation',
    cookie_trap_frequency: 'How often trap cookies are injected (higher = more frequent)',
    js_trap_difficulty: 'Complexity of JavaScript challenges (0=easy, 5=very hard)',
    content_cache_ttl_sec: 'How long generated content is cached before regeneration',
    adaptive_aggressive_rps: 'Requests/sec threshold to trigger aggressive adaptive mode',
    adaptive_labyrinth_paths: 'Min suspicious path count to redirect client into labyrinth',
    proxy_latency_prob: 'Probability of adding random latency to proxied requests (0=none, 1=always)',
    proxy_corrupt_prob: 'Probability of corrupting proxied response data (0=none, 1=always)',
    proxy_drop_prob: 'Probability of silently dropping proxied requests (0=none, 1=always)',
    proxy_reset_prob: 'Probability of sending TCP RST instead of response (0=none, 1=always)',
    protocol_glitch_level: 'Severity of HTTP protocol-level glitches (0=disabled, 1=subtle, 2=moderate, 3=aggressive, 4=chaos)'
  };

  const ERROR_TIPS = {
    none: 'No error — serve normal response',
    '500_internal': 'HTTP 500 Internal Server Error',
    '502_bad_gateway': 'HTTP 502 Bad Gateway',
    '503_unavailable': 'HTTP 503 Service Unavailable',
    '504_timeout': 'HTTP 504 Gateway Timeout',
    '404_not_found': 'HTTP 404 Not Found',
    '403_forbidden': 'HTTP 403 Forbidden',
    '429_rate_limit': 'HTTP 429 Too Many Requests',
    '408_timeout': 'HTTP 408 Request Timeout',
    slow_drip: 'Send response one byte at a time over seconds',
    connection_reset: 'Abruptly reset the TCP connection mid-response',
    partial_body: 'Send truncated response body',
    wrong_content_type: 'Serve content with an incorrect Content-Type header',
    garbage_body: 'Return random binary garbage as the response body',
    empty_body: 'Return 200 OK but with a completely empty body',
    huge_headers: 'Send very large response headers to overflow buffers',
    delay_1s: 'Add a fixed 1 second delay before responding',
    delay_3s: 'Add a fixed 3 second delay before responding',
    delay_10s: 'Add a fixed 10 second delay before responding',
    delay_random: 'Add a random delay (1-30s) before responding',
    redirect_loop: 'Redirect the client in an infinite loop',
    double_encoding: 'Double-encode the response body',
    flip_flop: 'Alternate between valid and broken responses',
    packet_drop: 'Accept connection but never send any data (TCP black hole)',
    tcp_reset: 'Send TCP RST instead of a proper close',
    stream_corrupt: 'Start valid HTTP then inject garbage bytes mid-stream',
    session_timeout: 'Send response at 1 byte/second (extreme slow-loris)',
    keepalive_abuse: 'Send keep-alive with infinite timeout then stall',
    tls_half_close: 'Close write side of connection but keep reading',
    slow_headers: 'Send HTTP headers one byte at a time',
    accept_then_fin: 'Accept connection and immediately send FIN'
  };

  async function refreshControls() {
    try {
      const features = await api('/admin/api/features');
      const el = document.getElementById('toggles');
      el.innerHTML = Object.keys(FEATURE_LABELS).map(key => {
        const on = features[key] ? 'checked' : '';
        const tip = FEATURE_TIPS[key] || '';
        return '<div class="toggle-row">' +
          '<div class="toggle-name has-tip">' + FEATURE_LABELS[key] +
          (tip ? '<span class="tip-icon">?</span><span class="tip-box">' + tip + '</span>' : '') +
          '</div>' +
          '<label class="toggle-sw">' +
          '<input type="checkbox" ' + on + ' onchange="toggleFeature(\'' + key + '\', this.checked)">' +
          '<div class="toggle-track"></div>' +
          '<div class="toggle-knob"></div>' +
          '</label></div>';
      }).join('');

      const cfg = await api('/admin/api/config');
      document.getElementById('sliders').innerHTML =
        slider('error_rate_multiplier', 'Error Rate Multiplier', cfg.error_rate_multiplier, 0, 5, 0.1) +
        slider('block_chance', 'Random Block Chance', cfg.block_chance, 0, 1, 0.01) +
        slider('block_duration_sec', 'Block Duration (sec)', cfg.block_duration_sec, 1, 3600, 1) +
        slider('header_corrupt_level', 'Header Corruption Level (0-4)', cfg.header_corrupt_level, 0, 4, 1) +
        slider('protocol_glitch_level', 'Protocol Glitch Level (0-4)', cfg.protocol_glitch_level || 2, 0, 4, 1) +
        '<div class="toggle-row" style="margin-top:8px">' +
          '<div class="toggle-name has-tip">Protocol Glitch Enabled' +
            '<span class="tip-icon">?</span><span class="tip-box">Enable HTTP protocol-level glitches (version violations, encoding conflicts, header corruption)</span>' +
          '</div>' +
          '<label class="toggle-sw">' +
          '<input type="checkbox" ' + (cfg.protocol_glitch_enabled ? 'checked' : '') + ' onchange="sliderCommit(\'protocol_glitch_enabled\', this.checked ? 1 : 0)">' +
          '<div class="toggle-track"></div>' +
          '<div class="toggle-knob"></div>' +
          '</label></div>';

      // Labyrinth sliders
      var labEl = document.getElementById('labyrinth-sliders');
      if (labEl) labEl.innerHTML =
        slider('max_labyrinth_depth', 'Max Labyrinth Depth', cfg.max_labyrinth_depth, 1, 100, 1) +
        slider('labyrinth_link_density', 'Labyrinth Links/Page', cfg.labyrinth_link_density, 1, 20, 1) +
        slider('adaptive_labyrinth_paths', 'Adaptive Labyrinth Paths', cfg.adaptive_labyrinth_paths || 5, 1, 50, 1);

      // Adaptive behavior sliders
      var adaptEl = document.getElementById('adaptive-sliders');
      if (adaptEl) adaptEl.innerHTML =
        slider('adaptive_interval_sec', 'Adaptive Re-eval Interval (sec)', cfg.adaptive_interval_sec, 5, 300, 5) +
        slider('adaptive_aggressive_rps', 'Adaptive Aggressive RPS', cfg.adaptive_aggressive_rps || 10, 1, 100, 1) +
        slider('delay_min_ms', 'Delay Min (ms)', cfg.delay_min_ms, 0, 10000, 100) +
        slider('delay_max_ms', 'Delay Max (ms)', cfg.delay_max_ms, 0, 30000, 100);

      // Traps & detection sliders
      var trapsEl = document.getElementById('traps-sliders');
      if (trapsEl) trapsEl.innerHTML =
        slider('captcha_trigger_thresh', 'CAPTCHA Trigger Threshold', cfg.captcha_trigger_thresh, 0, 500, 1) +
        slider('cookie_trap_frequency', 'Cookie Trap Frequency', cfg.cookie_trap_frequency || 3, 0, 20, 1) +
        slider('js_trap_difficulty', 'JS Trap Difficulty', cfg.js_trap_difficulty || 2, 0, 5, 1) +
        slider('bot_score_threshold', 'Bot Score Threshold', cfg.bot_score_threshold, 0, 100, 1) +
        slider('content_cache_ttl_sec', 'Content Cache TTL (sec)', cfg.content_cache_ttl_sec || 60, 0, 3600, 10);

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
      if (cfg.recorder_format) {
        var sel4 = document.getElementById('ctrl-recorder-format');
        if (sel4) sel4.value = cfg.recorder_format;
      }

      // Error weights
      refreshErrorWeights();
      // Page type weights
      refreshPageTypeWeights();
      // Spider config
      refreshSpiderConfig();
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
      const httpEl = document.getElementById('http-error-grid');
      if (httpEl) httpEl.innerHTML = HTTP_ERROR_TYPES.map(t => {
        var val = weights[t] !== undefined ? weights[t] : 0;
        return ewRow(t, val);
      }).join('');
      const tcpEl = document.getElementById('tcp-error-grid');
      if (tcpEl) tcpEl.innerHTML = TCP_ERROR_TYPES.map(t => {
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
    var tip = ERROR_TIPS[name] || '';
    return '<div class="ew-row"><span class="ew-name has-tip" title="' + name + '">' + displayName +
      (tip ? '<span class="tip-icon">?</span><span class="tip-box">' + tip + '</span>' : '') +
      '</span><div class="ew-opts">' + opts + '</div></div>';
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

  // Spider config
  async function refreshSpiderConfig() {
    try {
      const cfg = await api('/admin/api/spider');
      document.getElementById('spider-sliders').innerHTML =
        spiderSlider('sitemap_error_rate', 'Sitemap Error Rate', cfg.sitemap_error_rate || 0, 0, 1, 0.01) +
        spiderSlider('sitemap_gzip_error_rate', 'Sitemap Gzip Error Rate', cfg.sitemap_gzip_error_rate || 0, 0, 1, 0.01) +
        spiderSlider('favicon_error_rate', 'Favicon Error Rate', cfg.favicon_error_rate || 0, 0, 1, 0.01) +
        spiderSlider('robots_error_rate', 'Robots.txt Error Rate', cfg.robots_error_rate || 0, 0, 1, 0.01) +
        spiderSlider('meta_error_rate', 'Meta Files Error Rate', cfg.meta_error_rate || 0, 0, 1, 0.01);
    } catch(e) { console.error('spider-config:', e); }
  }

  function spiderSlider(key, label, value, min, max, step) {
    const isFloat = step < 1;
    const display = isFloat ? parseFloat(value).toFixed(2) : parseInt(value);
    return '<div class="slider-group">' +
      '<div class="slider-label"><span>' + label + '</span>' +
      '<span class="val" id="sp-' + key + '">' + display + '</span></div>' +
      '<input type="range" min="' + min + '" max="' + max + '" step="' + step + '" value="' + value + '" oninput="spiderSliderChange(\'' + key + '\', this.value)" onchange="sliderCommitSpider(\'' + key + '\', this.value)">' +
      '</div>';
  }

  let spiderSliderTimer = {};
  window.spiderSliderChange = function(key, val) {
    document.getElementById('sp-' + key).textContent = parseFloat(val).toFixed(2);
  };

  window.sliderCommitSpider = function(key, val) {
    clearTimeout(spiderSliderTimer[key]);
    spiderSliderTimer[key] = setTimeout(() => {
      api('/admin/api/spider', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key: key, value: parseFloat(val)})
      }).then(() => toast(key + ': ' + parseFloat(val).toFixed(2)));
    }, 300);
  };

  function slider(key, label, value, min, max, step) {
    const isFloat = step < 1;
    const display = isFloat ? parseFloat(value).toFixed(1) : parseInt(value);
    const tip = SLIDER_TIPS[key] || '';
    return '<div class="slider-group">' +
      '<div class="slider-label has-tip"><span>' + label + '</span>' +
      (tip ? '<span class="tip-icon">?</span><span class="tip-box">' + tip + '</span>' : '') +
      '<span class="val" id="sv-' + key + '">' + display + '</span></div>' +
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

  window.setAllFeatures = async function(enabled) {
    var keys = Object.keys(FEATURE_LABELS);
    for (var i = 0; i < keys.length; i++) {
      await api('/admin/api/features', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({feature: keys[i], enabled: enabled})
      });
    }
    toast('All features ' + (enabled ? 'enabled' : 'disabled'));
    refreshControls();
  };

  window.setAllErrorWeights = async function(group, level) {
    var types = group === 'tcp' ? TCP_ERROR_TYPES : HTTP_ERROR_TYPES;
    var valMap = {off: 0, low: 0.01, med: 0.05, high: 0.15, max: 0.5};
    var val = valMap[level] || 0;
    for (var i = 0; i < types.length; i++) {
      if (types[i] === 'none') continue;
      await api('/admin/api/error-weights', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({error_type: types[i], weight: val})
      });
    }
    toast(group.toUpperCase() + ' errors: ' + level.toUpperCase());
    refreshErrorWeights();
  };

  window.setAllPageTypeWeights = async function(level) {
    var valMap = {off: 0, low: 0.05, med: 0.15, high: 0.3, max: 0.5};
    var val = valMap[level] || 0;
    for (var i = 0; i < PAGE_TYPES.length; i++) {
      await api('/admin/api/page-type-weights', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({page_type: PAGE_TYPES[i], weight: val})
      });
    }
    toast('Page types: ' + level.toUpperCase());
    refreshPageTypeWeights();
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

      var catCounts = p.category_counts || {};
      const sev = p.by_severity || p.severity_counts || {};
      document.getElementById('vuln-overview-cards').innerHTML =
        card('Total Vulns', p.total_vulns || 0, 'v-ok') +
        card('Total Endpoints', p.total_endpoints || 0, 'v-info') +
        card('Groups Active', Object.values(vc.groups || {}).filter(v => v).length + '/' + Object.keys(vc.groups || {}).length, 'v-ok');

      // Group toggles
      var groups = vc.groups || {};
      var VULN_GROUPS = {
        owasp: 'OWASP Top 10',
        api_security: 'API Security',
        advanced: 'Advanced',
        modern: 'Modern (LLM/CI-CD/Cloud)',
        infrastructure: 'Infrastructure',
        iot_desktop: 'IoT / Desktop',
        mobile_privacy: 'Mobile / Privacy',
        specialized: 'Specialized',
        dashboard: 'Dashboard'
      };
      document.getElementById('vuln-group-toggles').innerHTML =
        Object.keys(VULN_GROUPS).map(g => {
          var on = groups[g] !== false ? 'checked' : '';
          return '<div class="group-toggle">' +
            '<div class="toggle-name">' + VULN_GROUPS[g] + '</div>' +
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

  window.setAllVulnGroups = async function(enabled) {
    var groups = ['owasp','api_security','advanced','modern','infrastructure','iot_desktop','mobile_privacy','specialized','dashboard'];
    for (var i = 0; i < groups.length; i++) {
      await api('/admin/api/vulns/group', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({group: groups[i], enabled: enabled})
      });
    }
    toast('All vuln groups ' + (enabled ? 'enabled' : 'disabled'));
    refreshVulns();
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
  let profileLoading = false;

  window.generateProfile = async function(showToast) {
    if (profileLoading) return;
    profileLoading = true;
    try {
      var data = await api('/admin/api/scanner/profile');
      vulnProfile = data;
      var p = data.profile || data;
      var summary = data.summary || {};
      var vulns = p.vulnerabilities || [];
      var sev = summary.by_severity || p.by_severity || {};
      var totalVulns = summary.total || p.total_vulns || 0;
      var detectable = summary.detectable || 0;
      var enabledGroups = summary.enabled_groups || 0;
      var totalGroups = summary.total_groups || 0;
      var totalEndpoints = summary.total_endpoints || p.total_endpoints || 0;

      // a) Summary cards row
      var sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      var sevSummary = sevOrder.map(function(s) { return (sev[s] || 0) + ' ' + s; }).join(' / ');
      var html = '<div class="grid">' +
        card('Total Vulnerabilities', totalVulns, 'v-ok') +
        card('By Severity', sevSummary, 'v-warn') +
        card('Enabled Groups', enabledGroups + ' of ' + totalGroups, 'v-info') +
        card('Detectable', detectable + ' of ' + totalVulns, 'v-ok') +
        '</div>';

      // b) Help text
      html += '<div style="margin:12px 0;padding:10px 14px;background:#0a1a1a;border:1px solid #00ccff22;border-radius:6px;color:#889;font-size:0.82em;line-height:1.5">' +
        'This shows what vulnerabilities the server currently exposes. Scanners are graded against this profile &mdash; a perfect scanner would detect all detectable vulnerabilities.' +
        '</div>';

      // d) Coverage section (only if scan has run)
      var runs = window._completedRuns || [];
      if (runs.length > 0) {
        var lastRun = runs[runs.length - 1];
        var comp = lastRun.comparison || {};
        var tp = (comp.true_positives || []).length;
        var testedEndpoints = tp;
        var coveragePct = totalVulns > 0 ? Math.min((testedEndpoints / totalVulns) * 100, 100).toFixed(1) : '0.0';
        html += '<div style="margin:12px 0;padding:10px 14px;background:#111;border:1px solid #00ff8833;border-radius:6px">' +
          '<div style="color:#aaa;font-size:0.82em;margin-bottom:6px">Last scan detected ' +
          '<span style="color:#00ff88;font-weight:bold">' + testedEndpoints + '</span> of ' +
          '<span style="color:#0ff">' + totalVulns + '</span> vulnerabilities (' +
          '<span style="color:#00ff88">' + coveragePct + '%%</span>)</div>' +
          '<div class="prog-bar"><div class="prog-fill prog-green" style="width:' + coveragePct + '%%"></div></div>' +
          '</div>';
      }

      // c) Collapsible vulnerability list (collapsed by default)
      html += '<div style="margin-top:14px">' +
        '<div style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#111;border:1px solid #00ccff33;border-radius:6px" ' +
        'onclick="var body=document.getElementById(\'vuln-surface-list\');body.style.display=body.style.display===\'none\'?\'\':\'none\';this.querySelector(\'.vuln-expand-arrow\').textContent=body.style.display===\'none\'?\'\\u25B6\':\'\\u25BC\'">' +
        '<span style="color:#00ccaa;font-size:0.85em;font-weight:bold"><span class="vuln-expand-arrow" style="margin-right:6px">&#9654;</span>View All Expected Vulnerabilities (' + totalVulns + ')</span>' +
        '<span style="color:#555;font-size:0.8em">click to expand</span>' +
        '</div>';

      html += '<div id="vuln-surface-list" style="display:none;margin-top:8px">';

      // Filter buttons by severity
      html += '<div style="margin-bottom:10px;display:flex;gap:6px;flex-wrap:wrap">' +
        '<button class="scanner-btn" style="padding:3px 10px;font-size:0.75em" onclick="filterVulnSurface(\'all\')">All</button>';
      sevOrder.forEach(function(s) {
        var color = s === 'critical' ? '#ff2244' : s === 'high' ? '#ff8800' : s === 'medium' ? '#ffcc00' : s === 'low' ? '#4488ff' : '#666';
        html += '<button class="scanner-btn" style="padding:3px 10px;font-size:0.75em;border-color:' + color + '" onclick="filterVulnSurface(\'' + s + '\')">' +
          s.charAt(0).toUpperCase() + s.slice(1) + ' (' + (sev[s] || 0) + ')</button>';
      });
      html += '</div>';

      // Vulnerability table
      html += '<div class="tbl-scroll" style="max-height:500px"><table id="vuln-surface-table">' +
        '<thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Endpoints</th><th>Detectable</th></tr></thead><tbody>';
      vulns.forEach(function(v) {
        var sevColor = v.severity === 'critical' ? '#ff2244' : v.severity === 'high' ? '#ff8800' : v.severity === 'medium' ? '#ffcc00' : v.severity === 'low' ? '#4488ff' : '#666';
        var endpoints = (v.endpoints || []).join(', ') || '-';
        var detectIcon = v.detectable ? '<span style="color:#00ff88">Yes</span>' : '<span style="color:#555">No</span>';
        html += '<tr data-severity="' + escapeHtml(v.severity || '') + '">' +
          '<td style="color:#888;font-size:0.8em;white-space:nowrap">' + escapeHtml(v.id || '') + '</td>' +
          '<td>' + escapeHtml(v.name || '') + '</td>' +
          '<td><span style="color:' + sevColor + ';font-weight:bold;text-transform:uppercase;font-size:0.8em">' + escapeHtml(v.severity || '') + '</span></td>' +
          '<td style="color:#888;font-size:0.8em;max-width:280px;overflow:hidden;text-overflow:ellipsis">' + escapeHtml(endpoints) + '</td>' +
          '<td style="text-align:center">' + detectIcon + '</td>' +
          '</tr>';
      });
      html += '</tbody></table></div>';
      html += '</div></div>';

      document.getElementById('scanner-profile-summary').innerHTML = html;
      if (showToast) toast('Profile loaded');
    } catch(e) { console.error('generateProfile:', e); if (showToast) toast('Failed to load profile'); }
    finally { profileLoading = false; }
  };

  window.filterVulnSurface = function(severity) {
    var table = document.getElementById('vuln-surface-table');
    if (!table) return;
    var rows = table.querySelectorAll('tbody tr');
    rows.forEach(function(row) {
      if (severity === 'all' || row.getAttribute('data-severity') === severity) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
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

      // Update active scanners banner
      var banner = document.getElementById('active-scanners-banner');
      var listEl = document.getElementById('active-scanners-list');
      if (running.length > 0) {
        banner.style.display = '';
        listEl.innerHTML = running.map(function(r) {
          return '<div style="display:flex;align-items:center;gap:8px;margin:4px 0">' +
            '<span style="color:#ffaa00;font-weight:bold">' + escapeHtml(r.scanner) + '</span> ' +
            '<span style="color:#888;font-size:0.82em">' + escapeHtml(r.status) + ' (' + escapeHtml(r.elapsed) + ')</span> ' +
            '<button class="scanner-btn" style="padding:2px 10px;font-size:0.75em" onclick="stopScanner(\'' + escapeHtml(r.scanner) + '\')">Stop</button>' +
            '</div>';
        }).join('');
      } else {
        banner.style.display = 'none';
      }

      // Update scanner card buttons — disable running scanners
      var scannerNames = ['nuclei', 'nikto', 'nmap', 'ffuf', 'wapiti'];
      var runningNames = running.map(function(r) { return r.scanner; });
      scannerNames.forEach(function(name) {
        var btn = document.getElementById('scanner-btn-' + name);
        var card = document.getElementById('scanner-card-' + name);
        if (!btn || !card) return;
        if (runningNames.indexOf(name) >= 0) {
          btn.disabled = true;
          btn.textContent = 'Running...';
          btn.style.opacity = '0.5';
          card.style.borderColor = '#ffaa00';
        } else {
          btn.disabled = false;
          btn.textContent = 'Launch';
          btn.style.opacity = '1';
          card.style.borderColor = '';
        }
      });

      var statusEl = document.getElementById('scanner-run-status');
      if (running.length === 0 && scanPollTimer) {
        clearInterval(scanPollTimer);
        scanPollTimer = null;
        statusEl.innerHTML = '<span style="color:#00ff88">All scans completed</span>';
      } else if (running.length > 0) {
        statusEl.innerHTML = '<span style="color:#ffaa00">' + running.length + ' scanner(s) active</span>';
      }

      // Update history from server
      renderServerHistory(completed, running);

      // Build scanner result tabs for multi-scanner display
      buildResultTabs(completed);
    } catch(e) { console.error('pollScanner:', e); }
  }

  // Build tabs for each scanner that has completed results
  function buildResultTabs(completed) {
    var tabsEl = document.getElementById('scanner-result-tabs');
    if (!completed || completed.length === 0) {
      tabsEl.style.display = 'none';
      return;
    }

    // Group completed scans by scanner name
    var scannerRuns = {};
    completed.forEach(function(run, idx) {
      var name = run.scanner || 'unknown';
      if (!scannerRuns[name]) scannerRuns[name] = [];
      scannerRuns[name].push({run: run, idx: idx});
    });

    var scannerNames = Object.keys(scannerRuns);
    if (scannerNames.length <= 1 && completed.length <= 1) {
      // Only one result — show it directly without tabs
      tabsEl.style.display = 'none';
      if (completed.length === 1) {
        var only = completed[0];
        if (only.comparison) renderComparison(only.comparison, only.scanner, only);
        else renderScanResult(only);
      }
      return;
    }

    tabsEl.style.display = '';
    var html = '<div style="display:flex;gap:4px;flex-wrap:wrap">';
    html += '<button class="scanner-btn" style="padding:3px 10px;font-size:0.78em' +
      (window._activeResultTab === 'latest' || !window._activeResultTab ? ';background:#00ff88;color:#000' : '') +
      '" onclick="showResultTab(\'latest\')">Latest</button>';

    scannerNames.forEach(function(name) {
      var runs = scannerRuns[name];
      var label = escapeHtml(name) + ' (' + runs.length + ')';
      var isActive = window._activeResultTab === name;
      html += '<button class="scanner-btn" style="padding:3px 10px;font-size:0.78em' +
        (isActive ? ';background:#00ff88;color:#000' : '') +
        '" onclick="showResultTab(\'' + escapeHtml(name) + '\')">' + label + '</button>';
    });

    // Multi-compare button if 2+ scanners have comparison results
    var comparableScanners = scannerNames.filter(function(name) {
      return scannerRuns[name].some(function(r) { return r.run.comparison; });
    });
    if (comparableScanners.length >= 2) {
      html += '<button class="cfg-btn" style="padding:3px 10px;font-size:0.78em;margin-left:8px" onclick="showMultiCompare()">Compare All</button>';
    }
    html += '</div>';
    tabsEl.innerHTML = html;

    // Show selected tab content
    if (!window._activeResultTab || window._activeResultTab === 'latest') {
      var latest = completed[completed.length - 1];
      if (latest.comparison) renderComparison(latest.comparison, latest.scanner, latest);
      else renderScanResult(latest);
    } else {
      var tabRuns = scannerRuns[window._activeResultTab];
      if (tabRuns && tabRuns.length > 0) {
        var latestRun = tabRuns[tabRuns.length - 1].run;
        if (latestRun.comparison) renderComparison(latestRun.comparison, latestRun.scanner, latestRun);
        else renderScanResult(latestRun);
      }
    }
  }

  window.showResultTab = function(tab) {
    window._activeResultTab = tab;
    var completed = window._completedRuns || [];
    buildResultTabs(completed);
  };

  window.showMultiCompare = function() {
    var completed = window._completedRuns || [];
    var scannerBest = {};
    completed.forEach(function(run) {
      if (run.comparison && run.scanner) {
        scannerBest[run.scanner] = run;
      }
    });

    var names = Object.keys(scannerBest);
    if (names.length < 2) { toast('Need 2+ scanner results to compare'); return; }

    window._crashInfos = [];
    var html = '<h3 style="color:#00ccaa;font-size:0.9em;margin-bottom:12px">Multi-Scanner Comparison</h3>';
    html += '<table class="findings-tbl"><thead><tr><th>Scanner</th><th>Grade</th><th>Detection</th><th>False Pos.</th><th>Accuracy</th><th>Crashed</th></tr></thead><tbody>';
    names.forEach(function(name) {
      var c = scannerBest[name].comparison;
      var run = scannerBest[name];
      var gradeClass = c.grade ? 'grade-' + c.grade.toLowerCase() : '';
      var crashCell = 'No';
      if (c.scanner_crashed) {
        var ci = window._crashInfos.length;
        window._crashInfos.push({scanner:name, status:'CRASHED', exit_code:c.crash_exit_code||run.exit_code||0, crash_signal:c.crash_signal||run.crash_signal||'', scanner_errors:c.scanner_errors||[], crash_stderr:c.crash_stderr||run.stderr_excerpt||'', error_output:run.error_output||''});
        crashCell = '<span class="crash-link" onclick="showCrashModal(window._crashInfos['+ci+'])">YES (details)</span>';
      }
      html += '<tr>' +
        '<td style="font-weight:bold">' + escapeHtml(name) + '</td>' +
        '<td class="' + gradeClass + '" style="font-weight:bold;font-size:1.1em">' + escapeHtml(c.grade || '?') + '</td>' +
        '<td>' + ((c.detection_rate || 0) * 100).toFixed(1) + '%%</td>' +
        '<td>' + ((c.false_positive_rate || 0) * 100).toFixed(1) + '%%</td>' +
        '<td>' + (c.accuracy || 0).toFixed(1) + '%%</td>' +
        '<td style="color:' + (c.scanner_crashed ? '#ff4444' : '#00ff88') + '">' + crashCell + '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('scanner-comparison').innerHTML = html;
    window._activeResultTab = 'compare';
    document.getElementById('scanner-result-tabs').querySelectorAll('button').forEach(function(b) { b.style.background = ''; b.style.color = ''; });
  };

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
      renderComparison(report, scanner);
      toast('Comparison complete: grade ' + (report.grade || '?'));
      pollScannerStatus();
    } catch(e) {
      console.error('uploadResults:', e);
      toast('Comparison failed');
    }
  };

  function renderScanResult(run) {
    var r = run.result || {};
    var statusCls = run.status === 'completed' ? 'v-ok' : 'v-err';
    var statusText = run.status || '-';
    if (run.crashed) statusText = 'CRASHED';
    if (run.not_installed) statusText = 'NOT INSTALLED';
    window._currentRunCrash = {scanner:run.scanner||'', status:statusText, exit_code:run.exit_code||0, crash_signal:run.crash_signal||'', scanner_errors:[], crash_stderr:run.stderr_excerpt||'', error_output:run.error_output||''};

    var html = '<div class="grid">' +
      card('Scanner', escapeHtml(run.scanner || ''), 'v-info') +
      card('Status', escapeHtml(statusText), statusCls) +
      card('Duration', escapeHtml(run.duration || '-'), 'v-info') +
      card('Findings', (r.findings || []).length, 'v-warn') +
      card('Exit Code', run.exit_code || 0, run.exit_code === 0 || run.exit_code === 1 ? 'v-ok' : 'v-err') +
      '</div>';

    // Crash alert
    if (run.crashed) {
      html += '<div style="background:#330000;border:1px solid #ff4444;border-radius:6px;padding:12px;margin:12px 0;cursor:pointer" onclick="showCrashModal(window._currentRunCrash)">' +
        '<span style="color:#ff4444;font-weight:bold;font-size:0.9em">\u26A0 SCANNER CRASHED</span>';
      if (run.crash_signal) html += ' <span style="color:#ff8844">Signal: ' + escapeHtml(run.crash_signal) + '</span>';
      html += '<div style="color:#ff6666;font-size:0.82em;margin-top:6px">The scanner terminated abnormally. Exit code: ' + (run.exit_code || 0) + ' \u2014 <span style="text-decoration:underline">click for full details</span></div>';
      html += '</div>';
    }

    // Not installed alert
    if (run.not_installed) {
      html += '<div style="background:#1a1a00;border:1px solid #ffaa00;border-radius:6px;padding:12px;margin:12px 0">' +
        '<span style="color:#ffaa00;font-weight:bold;font-size:0.9em">SCANNER NOT INSTALLED</span>' +
        '<div style="color:#cc8800;font-size:0.82em;margin-top:6px">Install the scanner binary and try again.</div>' +
        '</div>';
    }

    var findings = r.findings || [];
    if (findings.length > 0) {
      html += '<h3 style="color:#00ccaa;font-size:0.85em;margin-top:14px">FINDINGS (' + findings.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Name</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      findings.forEach(function(f) {
        html += '<tr><td>' + escapeHtml(f.title || f.id || '') + '</td><td>' + escapeHtml(f.url || '') + '</td><td>' + escapeHtml(f.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (run.error_output) {
      html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:14px">SCANNER OUTPUT</h3>';
      html += '<pre style="background:#1a0a0a;border:1px solid #330000;border-radius:4px;padding:10px;color:#ff6666;font-size:0.8em;max-height:200px;overflow:auto">' + escapeHtml(run.error_output) + '</pre>';
    }

    if (run.stderr_excerpt) {
      html += '<h3 style="color:#ff8844;font-size:0.85em;margin-top:14px">STDERR EXCERPT</h3>';
      html += '<pre style="background:#1a0a00;border:1px solid #331100;border-radius:4px;padding:10px;color:#ff8844;font-size:0.8em;max-height:200px;overflow:auto">' + escapeHtml(run.stderr_excerpt) + '</pre>';
    }

    document.getElementById('scanner-comparison').innerHTML = html;
  }

  function renderComparison(report, scannerName, run) {
    var grade = (report.grade || '?').toUpperCase();
    var gradeClass = 'grade-' + grade.toLowerCase();
    var detPct = ((report.detection_rate || 0) * 100).toFixed(1);
    var fpPct = ((report.false_positive_rate || 0) * 100).toFixed(1);
    var accPct = (report.accuracy || 0).toFixed(1);
    var displayName = scannerName || report.scanner || 'Scanner';

    var html = '<div style="margin-bottom:10px;display:flex;align-items:center;gap:10px">' +
      '<span style="color:#00ccaa;font-weight:bold;font-size:1.1em">' + escapeHtml(displayName) + '</span>' +
      '<span style="color:#555;font-size:0.82em">|</span>' +
      '<span style="color:#888;font-size:0.82em">Expected: ' + (report.expected_vulns || 0) + ' vulns</span>' +
      '<span style="color:#888;font-size:0.82em">Found: ' + (report.found_vulns || 0) + '</span>' +
      '</div>';

    html += '<div style="display:grid;grid-template-columns:200px 1fr;gap:20px">' +
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

    var crashedLabel = 'no';
    if (report.scanner_crashed) {
      window._compCrashInfo = {scanner:scannerName||report.scanner||'', status:'CRASHED', exit_code:report.crash_exit_code||(run&&run.exit_code)||0, crash_signal:report.crash_signal||(run&&run.crash_signal)||'', scanner_errors:report.scanner_errors||[], crash_stderr:report.crash_stderr||(run&&run.stderr_excerpt)||'', error_output:(run&&run.error_output)||''};
      crashedLabel = '<span class="crash-link" onclick="showCrashModal(window._compCrashInfo)">YES (details)</span>';
    }
    html += '<div style="margin-top:14px;font-size:0.85em;color:#888">' +
      'Crashed: <span style="color:' + (report.scanner_crashed ? '#ff4444' : '#00ff88') + '">' + crashedLabel + '</span> | ' +
      'Timed out: <span style="color:' + (report.scanner_timed_out ? '#ff4444' : '#00ff88') + '">' + (report.scanner_timed_out ? 'YES' : 'no') + '</span> | ' +
      'Errors: <span style="color:' + ((report.scanner_errors || []).length > 0 ? '#ff4444' : '#00ff88') + '">' + (report.scanner_errors || []).length + '</span>' +
      '</div>';

    var tp = report.true_positives || [];
    if (tp.length > 0) {
      html += '<h3 style="color:#00ff88;font-size:0.85em;margin-top:16px">TRUE POSITIVES (' + tp.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      tp.forEach(function(item) {
        var exp = item.expected || {};
        html += '<tr><td class="found">' + escapeHtml(exp.name || '') + '</td><td>' + escapeHtml((exp.endpoints || [])[0] || '') + '</td><td>' + escapeHtml(exp.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    var fn = report.false_negatives || [];
    var cfn = report.classified_false_negatives || [];
    if (fn.length > 0) {
      // If we have classified FN data, split into two groups
      if (cfn.length > 0) {
        var critical = cfn.filter(function(c) { return c.classification === 'crawled_not_detected'; });
        var notCrawled = cfn.filter(function(c) { return c.classification === 'not_crawled'; });

        html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:16px">FALSE NEGATIVES - MISSED (' + fn.length + ') ' +
          '<span style="background:#ff4444;color:#000;padding:1px 6px;border-radius:3px;font-size:0.85em;margin-left:6px">' + critical.length + ' critical</span> ' +
          '<span style="background:#ffaa00;color:#000;padding:1px 6px;border-radius:3px;font-size:0.85em;margin-left:4px">' + notCrawled.length + ' not crawled</span></h3>';

        if (critical.length > 0) {
          html += '<h4 style="color:#ff4444;font-size:0.8em;margin-top:10px;text-transform:uppercase;letter-spacing:0.5px">CRAWLED BUT NOT DETECTED (Critical)</h4>';
          html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Severity</th><th>Endpoints Hit</th><th>Endpoints Missed</th></tr></thead><tbody>';
          critical.forEach(function(item) {
            var v = item.vuln || {};
            var hitStr = (item.endpoints_hit || []).map(function(e) { return escapeHtml(e); }).join(', ') || '-';
            var missStr = (item.endpoints_missed || []).map(function(e) { return escapeHtml(e); }).join(', ') || '-';
            html += '<tr style="background:#330000"><td class="missed">' + escapeHtml(v.name || '') + '</td><td>' + escapeHtml(v.severity || '') + '</td>' +
              '<td style="color:#ff6666;font-size:0.85em">' + hitStr + '</td>' +
              '<td style="color:#888;font-size:0.85em">' + missStr + '</td></tr>';
          });
          html += '</tbody></table>';
        }

        if (notCrawled.length > 0) {
          html += '<h4 style="color:#ffaa00;font-size:0.8em;margin-top:10px;text-transform:uppercase;letter-spacing:0.5px">NOT CRAWLED (Crawling Issue)</h4>';
          html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Severity</th><th>Endpoints Not Reached</th></tr></thead><tbody>';
          notCrawled.forEach(function(item) {
            var v = item.vuln || {};
            var missStr = (item.endpoints_missed || []).map(function(e) { return escapeHtml(e); }).join(', ') || '-';
            html += '<tr style="background:#1a1a00"><td style="color:#ffaa00">' + escapeHtml(v.name || '') + '</td><td>' + escapeHtml(v.severity || '') + '</td>' +
              '<td style="color:#888;font-size:0.85em">' + missStr + '</td></tr>';
          });
          html += '</tbody></table>';
        }
      } else {
        // No classification data - fall back to original display
        html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:16px">FALSE NEGATIVES - MISSED (' + fn.length + ')</h3>';
        html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
        fn.forEach(function(item) {
          html += '<tr><td class="missed">' + escapeHtml(item.name || '') + '</td><td>' + escapeHtml((item.endpoints || [])[0] || '') + '</td><td>' + escapeHtml(item.severity || '') + '</td></tr>';
        });
        html += '</tbody></table>';
      }
    }

    var fpList = report.false_positives || [];
    if (fpList.length > 0) {
      html += '<h3 style="color:#ffaa00;font-size:0.85em;margin-top:16px">FALSE POSITIVES (' + fpList.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Reported Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      fpList.forEach(function(item) {
        html += '<tr><td class="false-pos">' + escapeHtml(item.title || item.id || '') + '</td><td>' + escapeHtml(item.url || '') + '</td><td>' + escapeHtml(item.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (report.message) {
      html += '<div style="margin-top:12px;color:#555;font-size:0.82em">' + escapeHtml(report.message) + '</div>';
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
        '<td></td>' +
        '</tr>');
    });

    // Completed scans (newest first)
    (completed || []).slice().reverse().forEach(function(r, idx) {
      var comp = r.comparison || {};
      var grade = comp.grade || '-';
      var det = comp.detection_rate;
      var detStr = det !== undefined ? (det * 100).toFixed(0) + '%%' : '-';
      var gradeClass = grade !== '-' && grade !== '?' ? 'grade-' + grade.toLowerCase() : '';
      var statusText = r.status || '-';
      var statusColor = '#00ff88';
      if (r.crashed) { statusText = 'CRASHED'; statusColor = '#ff4444'; }
      else if (r.not_installed) { statusText = 'NOT INSTALLED'; statusColor = '#ff8844'; }
      else if (r.status === 'failed') { statusColor = '#ff4444'; }
      else if (r.status === 'timeout') { statusText = 'TIMEOUT'; statusColor = '#ffaa00'; }
      else if (r.status === 'crashed') { statusColor = '#ff4444'; }

      var exitInfo = '';
      if (r.exit_code && r.exit_code !== 0) exitInfo = ' (exit ' + r.exit_code + ')';
      if (r.crash_signal) exitInfo = ' (' + r.crash_signal + ')';

      var realIdx = completed.length - 1 - idx;
      var actions = '<button class="scanner-btn" style="padding:2px 8px;font-size:0.72em" onclick="viewScanRun(' + realIdx + ')">View</button>';
      if (comp.grade) {
        actions += ' <button class="cfg-btn" style="padding:2px 8px;font-size:0.72em" onclick="compareScanRun(' + realIdx + ')">Compare</button>';
      }

      var statusCell = escapeHtml(statusText) + escapeHtml(exitInfo);
      if (r.crashed || r.status === 'crashed') {
        var hci = window._crashInfos ? window._crashInfos.length : 0;
        if (!window._crashInfos) window._crashInfos = [];
        window._crashInfos.push({scanner:r.scanner||'', status:'CRASHED', exit_code:r.exit_code||0, crash_signal:r.crash_signal||'', scanner_errors:(comp.scanner_errors||[]), crash_stderr:r.stderr_excerpt||'', error_output:r.error_output||''});
        statusCell = '<span class="crash-link" onclick="event.stopPropagation();showCrashModal(window._crashInfos['+hci+'])">' + escapeHtml(statusText) + escapeHtml(exitInfo) + '</span>';
      }

      rows.push('<tr>' +
        '<td style="color:#888">' + (r.completed_at ? new Date(r.completed_at).toLocaleString() : r.started_at ? new Date(r.started_at).toLocaleString() : '-') + '</td>' +
        '<td>' + escapeHtml(r.scanner || '') + '</td>' +
        '<td' + (gradeClass ? ' class="' + gradeClass + '"' : '') + ' style="font-weight:bold;font-size:1.2em">' + escapeHtml(grade) + '</td>' +
        '<td>' + detStr + '</td>' +
        '<td style="color:' + statusColor + '">' + statusCell + '</td>' +
        '<td>' + actions + '</td>' +
        '</tr>');
    });

    tbody.innerHTML = rows.join('') || '<tr><td colspan="6" style="color:#555;text-align:center">No scans yet</td></tr>';

    // Store for click-to-view
    window._completedRuns = completed || [];
  }

  window.showCrashModal = function(info) {
    var html = '<h3><span>\u26A0 Scanner Crash Details</span><button class="close-btn" onclick="closeCrashModal()">\u00D7</button></h3>';
    html += '<div class="crash-field"><div class="label">Scanner</div><div class="value">' + escapeHtml(info.scanner || '-') + '</div></div>';
    html += '<div class="crash-field"><div class="label">Status</div><div class="value" style="color:#ff4444;font-weight:bold">' + escapeHtml(info.status || 'CRASHED') + '</div></div>';
    if (info.exit_code !== undefined && info.exit_code !== 0) {
      html += '<div class="crash-field"><div class="label">Exit Code</div><div class="value" style="color:#ff8844">' + info.exit_code + '</div></div>';
    }
    if (info.crash_signal) {
      html += '<div class="crash-field"><div class="label">Signal</div><div class="value" style="color:#ff6644">' + escapeHtml(info.crash_signal) + '</div></div>';
    }
    var errors = info.scanner_errors || info.errors || [];
    if (errors.length > 0) {
      html += '<div class="crash-field"><div class="label">Errors (' + errors.length + ')</div>';
      html += '<pre>' + errors.map(function(e){ return escapeHtml(e); }).join('\\n') + '</pre></div>';
    }
    var stderr = info.crash_stderr || info.stderr_excerpt || '';
    if (stderr) {
      html += '<div class="crash-field"><div class="label">Stderr Output</div>';
      html += '<pre>' + escapeHtml(stderr) + '</pre></div>';
    }
    if (info.error_output && info.error_output !== stderr) {
      html += '<div class="crash-field"><div class="label">Error Output</div>';
      html += '<pre>' + escapeHtml(info.error_output) + '</pre></div>';
    }
    if (!stderr && !info.error_output && errors.length === 0) {
      html += '<div class="crash-field"><div class="value" style="color:#888">No additional crash details available.</div></div>';
    }
    document.getElementById('crash-modal-content').innerHTML = html;
    document.getElementById('crash-overlay').classList.add('open');
  };

  window.closeCrashModal = function() {
    document.getElementById('crash-overlay').classList.remove('open');
  };

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeCrashModal();
  });

  window.viewScanRun = function(idx) {
    var runs = window._completedRuns || [];
    if (idx >= 0 && idx < runs.length) {
      var run = runs[idx];
      if (run.comparison) renderComparison(run.comparison, run.scanner, run);
      else renderScanResult(run);
    }
  };

  window.compareScanRun = function(idx) {
    var runs = window._completedRuns || [];
    if (idx >= 0 && idx < runs.length) {
      var run = runs[idx];
      if (run.comparison) {
        renderComparison(run.comparison, run.scanner, run);
        toast('Showing comparison for ' + (run.scanner || 'scan'));
      }
    }
  };

  async function refreshScannerTab() {
    try {
      // Auto-load profile on first call (only once)
      if (vulnProfile === null || vulnProfile === undefined) {
        generateProfile(false);
      }

      var data = await api('/admin/api/scanner/results');
      var running = data.running || [];
      var completed = data.completed || [];
      renderServerHistory(completed, running);

      // Auto-start polling if scans are running
      if (running.length > 0 && !scanPollTimer) startScanPolling();

      // Update active scanners banner and button states
      var banner = document.getElementById('active-scanners-banner');
      var listEl = document.getElementById('active-scanners-list');
      if (running.length > 0) {
        banner.style.display = '';
        listEl.innerHTML = running.map(function(r) {
          return '<div style="display:flex;align-items:center;gap:8px;margin:4px 0">' +
            '<span style="color:#ffaa00;font-weight:bold">' + escapeHtml(r.scanner) + '</span> ' +
            '<span style="color:#888;font-size:0.82em">' + escapeHtml(r.status) + ' (' + escapeHtml(r.elapsed) + ')</span> ' +
            '<button class="scanner-btn" style="padding:2px 10px;font-size:0.75em" onclick="stopScanner(\'' + escapeHtml(r.scanner) + '\')">Stop</button>' +
            '</div>';
        }).join('');
      } else {
        banner.style.display = 'none';
      }

      // Disable launch buttons for running scanners
      var runningNames = running.map(function(r) { return r.scanner; });
      ['nuclei', 'nikto', 'nmap', 'ffuf', 'wapiti'].forEach(function(name) {
        var btn = document.getElementById('scanner-btn-' + name);
        var card = document.getElementById('scanner-card-' + name);
        if (!btn || !card) return;
        if (runningNames.indexOf(name) >= 0) {
          btn.disabled = true; btn.textContent = 'Running...'; btn.style.opacity = '0.5'; card.style.borderColor = '#ffaa00';
        } else {
          btn.disabled = false; btn.textContent = 'Launch'; btn.style.opacity = '1'; card.style.borderColor = '';
        }
      });

      // Build result tabs for multi-scanner display
      buildResultTabs(completed);
    } catch(e) { console.error('scannerTab:', e); }
  }

  // ------ Built-in Scanner Tab ------
  var builtinPollTimer = null;
  var viewingHistoryReport = false;

  window.switchScannerSubtab = function(tab) {
    document.getElementById('scanner-eval-panel').style.display = tab === 'eval' ? '' : 'none';
    document.getElementById('scanner-builtin-panel').style.display = tab === 'builtin' ? '' : 'none';
    var replayPanel = document.getElementById('scanner-replay-panel');
    if (replayPanel) replayPanel.style.display = tab === 'replay' ? '' : 'none';
    document.querySelectorAll('.scanner-subtab-btn').forEach(function(b) { b.classList.remove('active'); });
    if (event && event.target) event.target.classList.add('active');
    else document.querySelectorAll('.scanner-subtab-btn').forEach(function(b) { if (b.textContent.toLowerCase().indexOf(tab) >= 0) b.classList.add('active'); });
    if (tab === 'eval') refreshScannerTab();
    else if (tab === 'builtin') refreshBuiltinScanner();
    else if (tab === 'replay') refreshReplay();
  };

  window.selectBuiltinProfile = function(el, profile) {
    document.querySelectorAll('.profile-card').forEach(function(c) { c.classList.remove('selected'); });
    el.classList.add('selected');
    el.querySelector('input[type="radio"]').checked = true;
    updateBuiltinSummary();
  };

  window.toggleAllModules = function(checked) {
    document.querySelectorAll('#builtin-modules input[type="checkbox"]').forEach(function(cb) { cb.checked = checked; });
    updateBuiltinModuleCount();
  };

  function updateBuiltinModuleCount() {
    var total = document.querySelectorAll('#builtin-modules input[type="checkbox"]').length;
    var selected = document.querySelectorAll('#builtin-modules input[type="checkbox"]:checked').length;
    var countEl = document.getElementById('builtin-module-count');
    if (countEl) countEl.textContent = selected + ' of ' + total + ' modules selected';
    var selEl = document.getElementById('builtin-selected-count');
    if (selEl) selEl.textContent = selected;
  }

  function updateBuiltinSummary() {
    var profile = document.querySelector('input[name="builtin-profile"]:checked');
    var profileName = profile ? profile.value : 'compliance';
    var summary = document.getElementById('builtin-run-summary');
    if (summary) {
      var target = document.getElementById('builtin-target').value || 'http://' + window.location.hostname + ':8765';
      var selected = document.querySelectorAll('#builtin-modules input[type="checkbox"]:checked').length;
      summary.innerHTML = 'Profile: <span style="color:#0ff">' + escapeHtml(profileName) + '</span> | ' +
        'Modules: <span id="builtin-selected-count" style="color:#0ff">' + selected + '</span> selected | ' +
        'Target: <span id="builtin-target-display" style="color:#0ff">' + escapeHtml(target) + '</span>';
    }
  }

  async function refreshBuiltinScanner() {
    try {
      // Fetch modules
      var modData = await api('/admin/api/scanner/builtin/modules');
      var modules = modData.modules || modData || [];
      var modContainer = document.getElementById('builtin-modules');
      if (Array.isArray(modules) && modules.length > 0) {
        var html = '';
        modules.forEach(function(m) {
          var name = m.name || m.id || '';
          var desc = m.description || '';
          var reqs = m.requests || 0;
          html += '<div class="module-row">' +
            '<input type="checkbox" id="mod-' + escapeHtml(name) + '" value="' + escapeHtml(name) + '" checked onchange="updateBuiltinModuleCount();updateBuiltinSummary()">' +
            '<label for="mod-' + escapeHtml(name) + '">' + escapeHtml(name) + (desc ? ' <span style="color:#555">- ' + escapeHtml(desc) + '</span>' : '') + '</label>' +
            '<span class="mod-reqs">' + reqs + ' reqs</span>' +
            '</div>';
        });
        modContainer.innerHTML = html;
      } else {
        modContainer.innerHTML = '<div style="color:#555;padding:12px;text-align:center">No modules available</div>';
      }
      updateBuiltinModuleCount();
      updateBuiltinSummary();

      // Fetch status
      try {
        var status = await api('/admin/api/scanner/builtin/status');
        if (status.state === 'running') {
          document.getElementById('builtin-run-btn').style.display = 'none';
          document.getElementById('builtin-stop-btn').style.display = '';
          document.getElementById('builtin-progress-wrap').style.display = '';
          // Delegate display to pollBuiltinStatus for consistency
          pollBuiltinStatus();
          if (!builtinPollTimer) {
            builtinPollTimer = setInterval(pollBuiltinStatus, 1500);
          }
        } else if (status.state === 'completed') {
          document.getElementById('builtin-run-btn').style.display = '';
          document.getElementById('builtin-stop-btn').style.display = 'none';
          document.getElementById('builtin-progress-wrap').style.display = 'none';
          if (!viewingHistoryReport) {
            try {
              var results = await api('/admin/api/scanner/builtin/results');
              renderBuiltinResults(results);
            } catch(e) { /* no results yet */ }
          }
        } else {
          document.getElementById('builtin-run-btn').style.display = '';
          document.getElementById('builtin-stop-btn').style.display = 'none';
          document.getElementById('builtin-progress-wrap').style.display = 'none';
        }
      } catch(e) { /* status endpoint may not exist yet */ }

      // Fetch history
      try {
        var histData = await api('/admin/api/scanner/builtin/history');
        var history = histData.history || histData || [];
        var tbody = document.getElementById('builtin-history-body');
        if (Array.isArray(history) && history.length > 0) {
          var rows = history.slice().reverse().map(function(h) {
            var covPct = h.coverage_pct !== undefined ? h.coverage_pct.toFixed(1) + '%%' : '-';
            var resPct = h.resilience_pct !== undefined ? h.resilience_pct.toFixed(1) + '%%' : '-';
            return '<tr class="history-clickable" onclick="loadHistoryReport(\'' + escapeHtml(h.id || '') + '\')">' +
              '<td style="color:#888">' + (h.timestamp ? new Date(h.timestamp).toLocaleString() : '-') + '</td>' +
              '<td>' + escapeHtml(h.profile || '-') + '</td>' +
              '<td>' + (h.findings || 0) + '</td>' +
              '<td>' + covPct + '</td>' +
              '<td>' + resPct + '</td>' +
              '</tr>';
          }).join('');
          tbody.innerHTML = rows;
        } else {
          tbody.innerHTML = '<tr><td colspan="5" style="color:#555;text-align:center">No scans yet</td></tr>';
        }
      } catch(e) {
        document.getElementById('builtin-history-body').innerHTML = '<tr><td colspan="5" style="color:#555;text-align:center">No scans yet</td></tr>';
      }

      // Set default target
      var targetEl = document.getElementById('builtin-target');
      if (targetEl && !targetEl.value) {
        targetEl.value = 'http://' + window.location.hostname + ':8765';
      }
    } catch(e) { console.error('refreshBuiltinScanner:', e); }
  }

  async function pollBuiltinStatus() {
    try {
      var status = await api('/admin/api/scanner/builtin/status');
      if (status.state === 'running') {
        var phase = status.phase || 'scanning';
        var pct = status.progress_pct || 0;
        var completed = status.completed || 0;
        var total = status.total || 0;
        var findings = status.findings || 0;
        var elapsedMs = status.elapsed_ms || 0;
        var elapsedSec = (elapsedMs / 1000).toFixed(1);
        var rps = elapsedMs > 0 ? (completed / (elapsedMs / 1000)).toFixed(1) : '0';

        var crawledUrls = status.crawled_urls || 0;
        var generatedAttacks = status.generated_attacks || 0;

        if (phase === 'crawling') {
          var crawlCount = crawledUrls > 0 ? crawledUrls : completed;
          document.getElementById('builtin-progress-bar').style.width = '100%%';
          document.getElementById('builtin-progress-bar').style.background = 'linear-gradient(90deg,#0aa,#066,#0aa)';
          document.getElementById('builtin-progress-bar').style.backgroundSize = '200%% 100%%';
          document.getElementById('builtin-progress-bar').style.animation = 'shimmer 1.5s linear infinite';
          document.getElementById('builtin-progress-text').textContent = 'Crawling... ' + crawlCount + ' URLs discovered';
          document.getElementById('builtin-status-text').textContent = 'Phase: Crawling target site';
          document.getElementById('builtin-req-count').textContent = crawlCount + ' URLs';
          document.getElementById('builtin-finding-count').textContent = '-';
        } else if (phase === 'generating') {
          var attackCount = generatedAttacks > 0 ? generatedAttacks : 0;
          document.getElementById('builtin-progress-bar').style.width = '100%%';
          document.getElementById('builtin-progress-bar').style.background = '#ffaa00';
          document.getElementById('builtin-progress-bar').style.animation = '';
          document.getElementById('builtin-progress-text').textContent = 'Generating attacks... ' + attackCount + ' requests';
          document.getElementById('builtin-status-text').textContent = 'Phase: Building attack requests';
          document.getElementById('builtin-req-count').textContent = attackCount + ' attacks';
          document.getElementById('builtin-finding-count').textContent = '-';
        } else {
          document.getElementById('builtin-progress-bar').style.width = pct.toFixed(0) + '%%';
          document.getElementById('builtin-progress-bar').style.background = '';
          document.getElementById('builtin-progress-bar').style.animation = '';
          document.getElementById('builtin-progress-text').textContent = 'Scanning... ' + completed + '/' + total + ' (' + pct.toFixed(0) + '%%) \u2014 ' + findings + ' findings';
          document.getElementById('builtin-status-text').textContent = 'Scanning: ' + completed + '/' + total + ' tests';
          document.getElementById('builtin-req-count').textContent = completed + ' reqs (' + rps + '/s)';
          document.getElementById('builtin-finding-count').textContent = findings + ' findings';
        }
        document.getElementById('builtin-elapsed').textContent = elapsedSec + 's';
      } else {
        if (builtinPollTimer) { clearInterval(builtinPollTimer); builtinPollTimer = null; }
        document.getElementById('builtin-run-btn').style.display = '';
        document.getElementById('builtin-stop-btn').style.display = 'none';
        if (status.state === 'completed') {
          document.getElementById('builtin-progress-bar').style.width = '100%%';
          document.getElementById('builtin-progress-text').textContent = 'Complete';
          document.getElementById('builtin-status-text').textContent = 'Scan completed';
          try {
            var results = await api('/admin/api/scanner/builtin/results');
            renderBuiltinResults(results);
          } catch(e) { /* no results */ }
          // Refresh history list only (not full scanner panel to avoid filter reset)
          try {
            var histData = await api('/admin/api/scanner/builtin/history');
            var history = histData.history || histData || [];
            var tbody = document.getElementById('builtin-history-body');
            if (Array.isArray(history) && history.length > 0) {
              var rows = history.slice().reverse().map(function(h) {
                var covPct = h.coverage_pct !== undefined ? h.coverage_pct.toFixed(1) + '%%' : '-';
                var resPct = h.resilience_pct !== undefined ? h.resilience_pct.toFixed(1) + '%%' : '-';
                return '<tr class="history-clickable" onclick="loadHistoryReport(\'' + escapeHtml(h.id || '') + '\')">' +
                  '<td style="color:#888">' + (h.timestamp ? new Date(h.timestamp).toLocaleString() : '-') + '</td>' +
                  '<td>' + escapeHtml(h.profile || '-') + '</td>' +
                  '<td>' + (h.findings || 0) + '</td>' +
                  '<td>' + covPct + '</td>' +
                  '<td>' + resPct + '</td>' +
                  '</tr>';
              }).join('');
              tbody.innerHTML = rows;
            }
          } catch(e) { /* history refresh failed */ }
        } else {
          document.getElementById('builtin-progress-wrap').style.display = 'none';
        }
      }
    } catch(e) { console.error('pollBuiltinStatus:', e); }
  }

  window.runBuiltinScan = async function() {
    var profile = document.querySelector('input[name="builtin-profile"]:checked');
    var profileName = profile ? profile.value : 'compliance';
    var modules = [];
    document.querySelectorAll('#builtin-modules input[type="checkbox"]:checked').forEach(function(cb) {
      modules.push(cb.value);
    });
    var target = document.getElementById('builtin-target').value || 'http://' + window.location.hostname + ':8765';

    if (modules.length === 0) { toast('Select at least one module'); return; }

    document.getElementById('builtin-run-btn').style.display = 'none';
    document.getElementById('builtin-stop-btn').style.display = '';
    document.getElementById('builtin-progress-wrap').style.display = '';
    document.getElementById('builtin-progress-bar').style.width = '0%%';
    document.getElementById('builtin-progress-text').textContent = '0%%';
    document.getElementById('builtin-status-text').textContent = 'Starting...';
    document.getElementById('builtin-results-section').style.display = 'none';
    viewingHistoryReport = false;

    try {
      await api('/admin/api/scanner/builtin/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({profile: profileName, modules: modules, target: target})
      });
      toast('Built-in scan started (' + profileName + ')');
      builtinPollTimer = setInterval(pollBuiltinStatus, 1500);
    } catch(e) {
      toast('Failed to start scan: ' + e.message);
      document.getElementById('builtin-run-btn').style.display = '';
      document.getElementById('builtin-stop-btn').style.display = 'none';
      document.getElementById('builtin-progress-wrap').style.display = 'none';
    }
  };

  window.stopBuiltinScan = async function() {
    try {
      await api('/admin/api/scanner/builtin/stop', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: '{}'
      });
      toast('Scan stopped');
      if (builtinPollTimer) { clearInterval(builtinPollTimer); builtinPollTimer = null; }
      document.getElementById('builtin-run-btn').style.display = '';
      document.getElementById('builtin-stop-btn').style.display = 'none';
      document.getElementById('builtin-status-text').textContent = 'Stopped';
    } catch(e) { toast('Failed to stop scan'); }
  };

  function renderBuiltinResults(report, historyId) {
    var findings = report.findings || [];
    var coverage = report.coverage || {};
    var categories = report.categories || [];
    var overallCoverage = (report.summary && report.summary.overall_coverage_pct) || 0;
    var resilience = (report.summary && report.summary.overall_resilience_pct) || 0;

    // Count by severity
    var sevCounts = {critical:0, high:0, medium:0, low:0, info:0};
    findings.forEach(function(f) {
      var s = (f.severity || 'info').toLowerCase();
      if (sevCounts[s] !== undefined) sevCounts[s]++;
      else sevCounts.info++;
    });

    document.getElementById('builtin-results-section').style.display = '';

    // Banner for historical report viewing
    var bannerHtml = '';
    if (historyId) {
      bannerHtml = '<div class="history-viewing-banner">' +
        '<span>Viewing historical scan: ' + escapeHtml(historyId) + '</span>' +
        '<button onclick="clearHistoryView()">Close</button>' +
        '</div>';
    }

    // Findings count cards
    document.getElementById('builtin-results-cards').innerHTML = bannerHtml +
      '<div class="grid">' +
      '<div class="card"><div class="label">Critical</div><div class="value" style="color:#ff2244">' + sevCounts.critical + '</div></div>' +
      '<div class="card"><div class="label">High</div><div class="value" style="color:#ff8800">' + sevCounts.high + '</div></div>' +
      '<div class="card"><div class="label">Medium</div><div class="value" style="color:#ffcc00">' + sevCounts.medium + '</div></div>' +
      '<div class="card"><div class="label">Low</div><div class="value" style="color:#4488ff">' + sevCounts.low + '</div></div>' +
      '<div class="card"><div class="label">Info</div><div class="value" style="color:#888">' + sevCounts.info + '</div></div>' +
      '<div class="card"><div class="label">Total</div><div class="value v-ok">' + findings.length + '</div></div>' +
      '</div>';

    // Coverage by category
    if (Array.isArray(categories) && categories.length > 0) {
      var catHtml = '<table><thead><tr><th>Category</th><th>Tested</th><th>Found</th><th>Coverage</th></tr></thead><tbody>';
      categories.forEach(function(c) {
        var pct = c.coverage !== undefined ? (c.coverage * 100).toFixed(1) + '%%' : '-';
        catHtml += '<tr><td>' + escapeHtml(c.name || '') + '</td><td>' + (c.tested || 0) + '</td><td>' + (c.found || 0) + '</td><td>' + pct + '</td></tr>';
      });
      catHtml += '</tbody></table>';
      document.getElementById('builtin-coverage-table').innerHTML = catHtml;
    } else {
      document.getElementById('builtin-coverage-table').innerHTML = '';
    }

    // Overall scores — clamp width to 100%% max for display
    var covPct = overallCoverage.toFixed(1);
    var resPct = resilience.toFixed(1);
    var covWidth = Math.min(parseFloat(covPct), 100).toFixed(1);
    var resWidth = Math.min(parseFloat(resPct), 100).toFixed(1);
    document.getElementById('builtin-scores').innerHTML =
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">' +
        '<div><div style="color:#aaa;font-size:0.85em;margin-bottom:4px">Overall Coverage</div>' +
          '<div class="prog-bar"><div class="prog-fill prog-green" style="width:' + covWidth + '%%"></div></div>' +
          '<div style="color:#0f8;font-size:0.85em">' + covPct + '%%</div></div>' +
        '<div><div style="color:#aaa;font-size:0.85em;margin-bottom:4px">Resilience Score</div>' +
          '<div class="prog-bar"><div class="prog-fill prog-yellow" style="width:' + resWidth + '%%"></div></div>' +
          '<div style="color:#ffcc00;font-size:0.85em">' + resPct + '%%</div></div>' +
      '</div>';

    // Findings table — grouped by category with search + severity filter
    if (findings.length > 0) {
      // Build severity filter bar + search input
      var sevNames = ['critical','high','medium','low','info'];
      var sevColors = {critical:'sf-critical',high:'sf-high',medium:'sf-medium',low:'sf-low',info:'sf-info'};
      var filterHtml = '<input class="findings-search" id="findings-search" placeholder="Filter findings by URL, category, or description..." />';
      filterHtml += '<div id="severity-filters" style="margin-bottom:10px">';
      sevNames.forEach(function(s) {
        var cnt = sevCounts[s] || 0;
        filterHtml += '<span class="severity-filter active ' + sevColors[s] + '" data-sev="' + s + '" onclick="toggleSevFilter(this)">' + s.charAt(0).toUpperCase() + s.slice(1) + ' (' + cnt + ')</span>';
      });
      filterHtml += '</div>';

      // Group findings by category
      var groups = {};
      var groupOrder = [];
      findings.forEach(function(f) {
        var cat = f.category || 'Uncategorized';
        if (!groups[cat]) { groups[cat] = []; groupOrder.push(cat); }
        groups[cat].push(f);
      });

      // Sort groups: highest severity first, then by count
      var sevOrder = {critical:0,high:1,medium:2,low:3,info:4};
      groupOrder.sort(function(a, b) {
        var aItems = groups[a], bItems = groups[b];
        var aMax = 4, bMax = 4;
        aItems.forEach(function(f) { var s = sevOrder[(f.severity||'info').toLowerCase()]; if (s !== undefined && s < aMax) aMax = s; });
        bItems.forEach(function(f) { var s = sevOrder[(f.severity||'info').toLowerCase()]; if (s !== undefined && s < bMax) bMax = s; });
        if (aMax !== bMax) return aMax - bMax;
        return bItems.length - aItems.length;
      });

      var showLimit = 200;
      var totalShown = 0;
      var groupHtml = '<div class="findings-container" id="findings-container">';
      groupOrder.forEach(function(cat) {
        var items = groups[cat];
        // Severity breakdown for group header
        var gSev = {critical:0,high:0,medium:0,low:0,info:0};
        items.forEach(function(f) {
          var s = (f.severity || 'info').toLowerCase();
          if (gSev[s] !== undefined) gSev[s]++; else gSev.info++;
        });
        var sevSummary = '';
        sevNames.forEach(function(s) {
          if (gSev[s] > 0) sevSummary += '<span class="severity-badge sev-' + s + '" style="margin-left:4px">' + gSev[s] + '</span>';
        });

        groupHtml += '<details class="findings-group" data-category="' + escapeHtml(cat) + '">';
        groupHtml += '<summary><span class="fg-arrow">\u25B6</span><span>' + escapeHtml(cat) + '</span><span class="fg-count">(' + items.length + ')</span>' + sevSummary + '</summary>';
        groupHtml += '<table><thead><tr><th>Severity</th><th>URL</th><th>Description</th></tr></thead><tbody>';
        items.forEach(function(f) {
          var sev = (f.severity || 'info').toLowerCase();
          var rawUrl = f.url || f.endpoint || '-';
          var truncUrl = rawUrl.length > 60 ? rawUrl.substring(0,57) + '...' : rawUrl;
          totalShown++;
          var hidden = totalShown > showLimit ? ' style="display:none" data-overflow="1"' : '';
          groupHtml += '<tr class="finding-row" data-sev="' + sev + '" data-search="' + escapeHtml((cat + ' ' + rawUrl + ' ' + (f.description || f.name || '')).toLowerCase()) + '"' + hidden + '>' +
            '<td><span class="severity-badge sev-' + sev + '">' + escapeHtml(f.severity || 'info') + '</span></td>' +
            '<td><span class="findings-url" title="' + escapeHtml(rawUrl) + '" style="font-size:0.78em;color:#44aaff">' + escapeHtml(truncUrl) + '</span></td>' +
            '<td style="color:#aaa;font-size:0.82em">' + escapeHtml(f.description || f.name || '-') + '</td>' +
            '</tr>';
        });
        groupHtml += '</tbody></table></details>';
      });
      groupHtml += '</div>';

      var showAllBtn = '';
      if (totalShown > showLimit) {
        showAllBtn = '<div style="text-align:center;margin-top:8px"><button onclick="showAllFindings()" id="show-all-findings-btn" style="padding:6px 18px;background:#222;border:1px solid #555;color:#aaa;border-radius:4px;cursor:pointer">Show all ' + findings.length + ' findings</button></div>';
      }

      document.getElementById('builtin-findings-table').innerHTML = filterHtml + groupHtml + showAllBtn;
    } else {
      document.getElementById('builtin-findings-table').innerHTML = '<div style="color:#555;text-align:center;padding:12px">No findings</div>';
    }
  }

  // Severity filter toggle (global so onclick can reach it)
  window.toggleSevFilter = function(el) {
    el.classList.toggle('active');
    applyFindingsFilters();
  };

  // Show all findings (remove overflow limit, global for onclick)
  window.showAllFindings = function() {
    var rows = document.querySelectorAll('.finding-row[data-overflow]');
    rows.forEach(function(r) { r.style.display = ''; r.removeAttribute('data-overflow'); });
    var btn = document.getElementById('show-all-findings-btn');
    if (btn) btn.parentNode.remove();
    applyFindingsFilters();
  };

  // Apply search + severity filters to findings
  function applyFindingsFilters() {
    var searchEl = document.getElementById('findings-search');
    var query = searchEl ? searchEl.value.toLowerCase() : '';
    var activeSevs = {};
    document.querySelectorAll('.severity-filter.active').forEach(function(el) {
      activeSevs[el.getAttribute('data-sev')] = true;
    });
    var groups = document.querySelectorAll('.findings-group');
    groups.forEach(function(g) {
      var rows = g.querySelectorAll('.finding-row');
      var matchCount = 0;
      rows.forEach(function(r) {
        if (r.hasAttribute('data-overflow')) return;
        var sev = r.getAttribute('data-sev');
        var searchData = r.getAttribute('data-search') || '';
        var show = activeSevs[sev] && (query === '' || searchData.indexOf(query) !== -1);
        r.style.display = show ? '' : 'none';
        if (show) matchCount++;
      });
      // Hide group entirely if no rows match, but don't force open/close
      if (matchCount === 0) {
        g.style.display = 'none';
      } else {
        g.style.display = '';
      }
      // Update the group count to reflect filtered results
      var countEl = g.querySelector('.fg-count');
      if (countEl) countEl.textContent = '(' + matchCount + ')';
    });
  }

  // Bind search input event
  document.addEventListener('input', function(e) {
    if (e.target && e.target.id === 'findings-search') applyFindingsFilters();
  });

  // Load a historical report by ID (global so onclick can reach it)
  window.loadHistoryReport = async function(id) {
    try {
      var report = await api('/admin/api/scanner/builtin/history/detail?id=' + encodeURIComponent(id));
      if (report && report.findings) {
        viewingHistoryReport = true;
        renderBuiltinResults(report, id);
        document.getElementById('builtin-results-section').style.display = '';
        document.getElementById('builtin-results-section').scrollIntoView({behavior:'smooth'});
      } else {
        toast('No detailed report available for this scan');
      }
    } catch(e) {
      toast('Failed to load historical report');
    }
  };

  window.clearHistoryView = function() {
    viewingHistoryReport = false;
    document.getElementById('builtin-results-section').style.display = 'none';
  };

  // ------ Proxy Tab ------
  var proxyModeDescriptions = {
    transparent: 'Pass-through mode. All requests and responses flow without any modification. Useful as a baseline or when you want zero interference.',
    waf: 'Web Application Firewall mode. Inspects requests for SQL injection, XSS, path traversal, and other attack patterns. Matching requests are handled according to the configured block action.',
    chaos: 'Chaos engineering mode. Randomly injects latency, corrupts responses, drops connections, and resets sockets based on configured probabilities. Useful for resilience testing.',
    gateway: 'API gateway mode. Combines WAF filtering with rate limiting. Requests exceeding the rate limit are throttled or rejected.',
    nightmare: 'Maximum chaos mode. Activates WAF, chaos injection, and all glitch behaviors simultaneously. Every request is subjected to the full gauntlet of unreliability.',
    mirror: 'Mirror server mode. The proxy copies the server\'s behavior settings (error weights, page types, delays, corruption level) and applies them to proxied responses. Use "Refresh from Server" to re-snapshot.'
  };

  async function refreshProxy() {
    try {
      const data = await api('/admin/api/proxy/status');
      const stats = data.pipeline_stats || {};
      const chaosConf = data.chaos_config || {};
      const mode = data.mode || 'transparent';

      // Mode badge color
      var modeColors = {transparent:'#00ff88',waf:'#ffaa00',chaos:'#ff4444',gateway:'#4488ff',nightmare:'#ff44ff',mirror:'#44ddff'};
      var modeColor = modeColors[mode] || '#888';

      // Show/hide mirror settings section
      var mirrorSection = document.getElementById('proxy-mirror-section');
      if (mirrorSection) {
        mirrorSection.style.display = (mode === 'mirror') ? '' : 'none';
        if (mode === 'mirror' && data.mirror) {
          renderMirrorInfo(data.mirror);
        }
      }

      // Update metric cards with colored mode badge
      document.getElementById('proxy-metrics').innerHTML =
        '<div class="card"><div class="label">Current Mode</div><div class="value" style="color:' + modeColor + '">' +
          '<span style="display:inline-block;background:' + modeColor + '22;border:1px solid ' + modeColor + ';padding:4px 14px;border-radius:20px;font-size:0.75em;letter-spacing:1px">' +
          (mode || 'transparent').toUpperCase() + '</span></div></div>' +
        card('Requests Processed', (stats.requests_processed || 0).toLocaleString(), 'v-ok') +
        card('Responses Processed', (stats.responses_processed || 0).toLocaleString(), 'v-ok') +
        card('Requests Blocked', (stats.requests_blocked || 0).toLocaleString(), (stats.requests_blocked || 0) > 0 ? 'v-err' : 'v-ok') +
        card('Responses Modified', (stats.responses_modified || 0).toLocaleString(), 'v-warn');

      // Update radio buttons
      var radios = document.querySelectorAll('input[name="proxy-mode"]');
      radios.forEach(function(r) { r.checked = r.value === mode; });

      // Update mode description
      var descEl = document.getElementById('proxy-mode-desc');
      if (descEl) {
        descEl.innerHTML = '<span style="color:' + modeColor + ';font-weight:bold">' + (mode || 'transparent').toUpperCase() + ':</span> ' + (proxyModeDescriptions[mode] || 'Unknown mode.');
      }

      // WAF status
      var wafEl = document.getElementById('proxy-waf-status');
      var wafSettingsEl = document.getElementById('proxy-waf-settings');
      if (data.waf_enabled) {
        var wafStats = data.waf_stats || {};
        wafEl.innerHTML =
          '<div class="grid" style="margin-bottom:12px">' +
            card('Detections', (wafStats.detections || 0).toLocaleString(), 'v-warn') +
            card('Rate Limited', (wafStats.rate_limited || 0).toLocaleString(), 'v-err') +
            card('Block Action', wafStats.block_action || 'reject', 'v-info') +
          '</div>';
        if (wafSettingsEl) {
          wafSettingsEl.style.display = 'block';
          var actionSelect = document.getElementById('proxy-waf-action');
          if (actionSelect && wafStats.block_action) {
            actionSelect.value = wafStats.block_action;
          }
        }
      } else {
        wafEl.innerHTML = '<div style="color:#555">WAF not enabled. Select WAF, Gateway, or Nightmare mode to activate.</div>';
        if (wafSettingsEl) wafSettingsEl.style.display = 'none';
      }

      // Chaos sliders
      document.getElementById('proxy-chaos-sliders').innerHTML =
        slider('proxy_latency_prob', 'Latency Probability', chaosConf.latency_prob || 0, 0, 1, 0.01) +
        slider('proxy_corrupt_prob', 'Corruption Probability', chaosConf.corrupt_prob || 0, 0, 1, 0.01) +
        slider('proxy_drop_prob', 'Drop Probability', chaosConf.drop_prob || 0, 0, 1, 0.01) +
        slider('proxy_reset_prob', 'Reset Probability', chaosConf.reset_prob || 0, 0, 1, 0.01);

      // Connection info
      var connEl = document.getElementById('proxy-active-conns');
      if (connEl) connEl.textContent = (stats.active_connections || 0).toLocaleString();
      var fwdEl = document.getElementById('proxy-fwd-reqs');
      if (fwdEl) fwdEl.textContent = (stats.requests_processed || 0).toLocaleString();
      var blkEl = document.getElementById('proxy-blocked-reqs');
      if (blkEl) blkEl.textContent = (stats.requests_blocked || 0).toLocaleString();

      // Pipeline table
      var interceptors = data.interceptors || [];
      var pipeBody = document.getElementById('proxy-pipeline-body');
      if (interceptors.length > 0) {
        pipeBody.innerHTML = interceptors.map(function(ic) {
          return '<tr>' +
            '<td>' + escapeHtml(ic.name || 'unknown') + '</td>' +
            '<td>' + (ic.requests || 0) + '</td>' +
            '<td>' + (ic.responses || 0) + '</td>' +
            '<td>' + (ic.blocked || 0) + '</td>' +
            '<td>' + (ic.avg_latency_ms || 0).toFixed(1) + ' ms</td>' +
            '</tr>';
        }).join('');
      } else {
        pipeBody.innerHTML = '<tr><td colspan="5" style="color:#555;text-align:center">No interceptors registered</td></tr>';
      }

      // Proxy runtime status
      try {
        var rt = await api('/admin/api/proxy/runtime');
        var badge = document.getElementById('proxy-runtime-badge');
        var startBtn = document.getElementById('proxy-rt-start-btn');
        var stopBtn = document.getElementById('proxy-rt-stop-btn');
        var restartBtn = document.getElementById('proxy-rt-restart-btn');
        var statsDiv = document.getElementById('proxy-rt-stats');
        if (rt.running) {
          badge.textContent = 'RUNNING';
          badge.style.background = '#00aa6633'; badge.style.color = '#00ff88'; badge.style.border = '1px solid #00ff88';
          startBtn.style.display = 'none'; stopBtn.style.display = ''; restartBtn.style.display = '';
          statsDiv.style.display = '';
          document.getElementById('proxy-rt-reqs').textContent = (rt.requests || 0).toLocaleString();
          document.getElementById('proxy-rt-uptime-card').textContent = fmtUptime(Math.floor(rt.uptime_seconds || 0));
          document.getElementById('proxy-rt-mode').textContent = (rt.mode || 'transparent').toUpperCase();
          document.getElementById('proxy-rt-uptime').textContent = fmtUptime(Math.floor(rt.uptime_seconds || 0));
          // Update proxy status text
          var pst = document.getElementById('proxy-status-text');
          if (pst) pst.textContent = (rt.mode || 'transparent').toUpperCase();
          var psd = document.getElementById('proxy-status-detail');
          if (psd) psd.textContent = ':' + (rt.port || 8080) + ' | ' + (rt.requests || 0) + ' reqs';
        } else {
          badge.textContent = 'STOPPED';
          badge.style.background = '#33000033'; badge.style.color = '#666'; badge.style.border = '1px solid #333';
          startBtn.style.display = ''; stopBtn.style.display = 'none'; restartBtn.style.display = 'none';
          statsDiv.style.display = 'none';
          var pst2 = document.getElementById('proxy-status-text');
          if (pst2) pst2.textContent = 'STOPPED';
          var psd2 = document.getElementById('proxy-status-detail');
          if (psd2) psd2.textContent = 'Proxy not running';
        }
      } catch(pe) { /* proxy runtime API may not exist */ }

      // Recorder status (shared with server)
      await refreshRecorderUI();
    } catch(e) { console.error('proxy:', e); }
  }

  window.setProxyMode = async function(mode) {
    try {
      await fetch(API + '/admin/api/proxy/mode', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode: mode})
      });
      toast('Proxy mode: ' + mode.toUpperCase());
      refreshProxy();
    } catch(e) { console.error('setProxyMode:', e); }
  };

  function renderMirrorInfo(mirror) {
    var infoEl = document.getElementById('proxy-mirror-info');
    var timeEl = document.getElementById('proxy-mirror-time');
    if (!infoEl) return;
    var ewCount = mirror.error_weights ? Object.keys(mirror.error_weights).length : 0;
    var pwCount = mirror.page_type_weights ? Object.keys(mirror.page_type_weights).length : 0;
    infoEl.innerHTML =
      card('Error Rate Multiplier', (mirror.error_rate_multiplier || 0).toFixed(1) + 'x', 'v-warn') +
      card('Error Weights', ewCount + ' types', 'v-info') +
      card('Page Type Weights', pwCount + ' types', 'v-info') +
      card('Header Corrupt Level', mirror.header_corrupt_level || 0, 'v-warn') +
      card('Protocol Glitch', (mirror.protocol_glitch_enabled ? 'ON L' + mirror.protocol_glitch_level : 'OFF'), mirror.protocol_glitch_enabled ? 'v-warn' : 'v-ok') +
      card('Delay Range', (mirror.delay_min_ms || 0) + '-' + (mirror.delay_max_ms || 0) + ' ms', 'v-info') +
      card('Content Theme', mirror.content_theme || 'default', 'v-info');
    if (timeEl && mirror.snapshot_time) {
      timeEl.textContent = 'Snapshot taken: ' + new Date(mirror.snapshot_time).toLocaleString();
    }
  }

  window.refreshMirror = async function() {
    try {
      var resp = await fetch(API + '/admin/api/proxy/mirror/refresh', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
      });
      var data = await resp.json();
      if (data.mirror) {
        renderMirrorInfo(data.mirror);
        toast('Mirror settings refreshed from server');
      }
    } catch(e) { console.error('refreshMirror:', e); }
  };

  window.setWafBlockAction = async function(action) {
    try {
      await fetch(API + '/admin/api/proxy/mode', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({waf_block_action: action})
      });
      toast('WAF block action: ' + action);
    } catch(e) { console.error('setWafBlockAction:', e); }
  };

  // ------ Replay Tab ------
  window.refreshReplayFiles = async function() {
    try {
      const d = await api('/admin/api/replay/files');
      const tb = document.getElementById('replay-files-body');
      if (!d.files || d.files.length === 0) {
        tb.innerHTML = '<tr><td colspan="4" style="color:#666">No capture files found</td></tr>';
        return;
      }
      tb.innerHTML = d.files.map(f =>
        '<tr><td>' + escapeHtml(f.name) + '</td><td>' + f.size + '</td><td>' + f.modified + '</td>' +
        '<td><button class="scanner-btn" style="padding:4px 12px;font-size:0.78em" onclick="replayLoad(\'' + escapeHtml(f.name) + '\')">Load</button></td></tr>'
      ).join('');
    } catch(e) { console.error('refreshReplayFiles:', e); }
  };

  async function refreshReplay() {
    await refreshReplayFiles();
    await refreshReplayStatus();
  }

  async function refreshReplayStatus() {
    try {
      const d = await api('/admin/api/replay/status');
      var loaded = d.packets_loaded || 0;
      var played = d.packets_played || 0;
      var errors = d.errors || 0;
      var elapsed = d.elapsed_ms || 0;
      var isPlaying = d.playing;
      var loadedFile = d.loaded_file || '';

      // State badge
      var badge = document.getElementById('replay-state-badge');
      var detail = document.getElementById('replay-state-detail');
      if (badge) {
        if (isPlaying) {
          badge.textContent = 'PLAYING';
          badge.style.background = '#00aa6633';
          badge.style.color = '#00ff88';
          badge.style.border = '1px solid #00ff88';
          detail.textContent = played + ' / ' + loaded + ' packets';
        } else if (loaded > 0 && played > 0 && played < loaded) {
          badge.textContent = 'PAUSED';
          badge.style.background = '#ffaa0033';
          badge.style.color = '#ffaa00';
          badge.style.border = '1px solid #ffaa00';
          detail.textContent = played + ' / ' + loaded + ' packets';
        } else if (loaded > 0 && played >= loaded && played > 0) {
          badge.textContent = 'COMPLETED';
          badge.style.background = '#4488ff33';
          badge.style.color = '#4488ff';
          badge.style.border = '1px solid #4488ff';
          detail.textContent = played + ' / ' + loaded + ' packets done';
        } else {
          badge.textContent = 'STOPPED';
          badge.style.background = '#222';
          badge.style.color = '#666';
          badge.style.border = '1px solid #333';
          detail.textContent = loaded > 0 ? loaded + ' packets loaded' : 'No capture loaded';
        }
      }

      // Progress bar
      var pct = loaded > 0 ? Math.min(100, (played / loaded) * 100) : 0;
      var progBar = document.getElementById('replay-progress-bar');
      if (progBar) progBar.style.width = pct.toFixed(1) + '%%';
      var progText = document.getElementById('replay-progress-text');
      if (progText) progText.textContent = played + ' / ' + loaded + ' packets';

      // Stats cards
      document.getElementById('replay-loaded').textContent = loaded;
      document.getElementById('replay-played').textContent = played;
      document.getElementById('replay-errors').textContent = errors;
      document.getElementById('replay-elapsed').textContent = elapsed > 1000 ? (elapsed / 1000).toFixed(1) + 's' : elapsed + 'ms';
      var fileEl = document.getElementById('replay-loaded-file');
      if (fileEl) fileEl.textContent = loadedFile || 'None';

      // Target display
      var targetInput = document.getElementById('replay-target');
      var targetVal = targetInput ? (targetInput.value || 'http://localhost:8765') : 'http://localhost:8765';
      var isSelf = targetVal.indexOf('localhost:8765') !== -1 || targetVal.indexOf('127.0.0.1:8765') !== -1;
      var targetDisp = document.getElementById('replay-target-display');
      if (targetDisp) targetDisp.innerHTML = 'Target: <span style="color:#00ffcc">' + escapeHtml(targetVal) + '</span>' + (isSelf ? ' <span style="color:#888">(self)</span>' : '');

      // Play button state
      var playBtn = document.getElementById('replay-play-btn');
      if (playBtn) {
        playBtn.textContent = isPlaying ? 'Playing...' : 'Play';
        playBtn.disabled = isPlaying;
      }

      // Metadata display
      if (d.metadata) {
        renderReplayMetadata(d.metadata);
      } else if (loaded > 0) {
        try {
          var meta = await api('/admin/api/replay/metadata');
          renderReplayMetadata(meta);
        } catch(me) {}
      } else {
        var metaSec = document.getElementById('replay-metadata-section');
        if (metaSec) metaSec.style.display = 'none';
      }
    } catch(e) { console.error('refreshReplayStatus:', e); }
  }

  function renderReplayMetadata(meta) {
    var metaSec = document.getElementById('replay-metadata-section');
    if (!meta || !meta.total_packets) {
      if (metaSec) metaSec.style.display = 'none';
      return;
    }
    if (metaSec) metaSec.style.display = 'block';

    // Time span formatting
    var spanMs = meta.time_span_ms || 0;
    var spanStr = '';
    if (spanMs > 3600000) spanStr = (spanMs / 3600000).toFixed(1) + ' hours';
    else if (spanMs > 60000) spanStr = (spanMs / 60000).toFixed(1) + ' minutes';
    else if (spanMs > 1000) spanStr = (spanMs / 1000).toFixed(1) + ' seconds';
    else spanStr = spanMs + ' ms';

    var hosts = meta.unique_hosts || [];

    var cardsEl = document.getElementById('replay-metadata-cards');
    if (cardsEl) {
      cardsEl.innerHTML =
        card('Total Packets', (meta.total_packets || 0).toLocaleString(), 'v-info') +
        card('Total Requests', (meta.total_requests || 0).toLocaleString(), 'v-ok') +
        card('Total Responses', (meta.total_responses || 0).toLocaleString(), 'v-ok') +
        card('Unique Hosts', (Array.isArray(hosts) ? hosts.length : hosts || 0).toLocaleString(), 'v-warn') +
        card('Unique Paths', (meta.unique_paths || 0).toLocaleString(), 'v-info') +
        card('Time Span', spanStr, 'v-info');
    }

    // Method distribution bar
    var methods = meta.methods || {};
    var methodKeys = Object.keys(methods).sort(function(a,b) { return methods[b] - methods[a] || a.localeCompare(b); });
    var totalMethods = methodKeys.reduce(function(s,k) { return s + methods[k]; }, 0) || 1;
    var methodColors = {GET:'#00ff88',POST:'#4488ff',PUT:'#ffaa00',DELETE:'#ff4444',PATCH:'#aa44ff',HEAD:'#44ffaa',OPTIONS:'#888'};
    var methodHtml = '<div style="font-size:0.78em;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px">Method Distribution</div>';
    methodHtml += '<div style="display:flex;height:18px;border-radius:4px;overflow:hidden;margin-bottom:8px">';
    methodKeys.forEach(function(m) {
      var pctVal = (methods[m] / totalMethods * 100).toFixed(1);
      var col = methodColors[m] || '#888';
      methodHtml += '<div style="width:' + pctVal + '%%;background:' + col + ';min-width:' + (pctVal > 3 ? '0' : '2') + 'px" title="' + m + ': ' + methods[m] + ' (' + pctVal + '%%' + ')"></div>';
    });
    methodHtml += '</div>';
    methodKeys.forEach(function(m) {
      var col = methodColors[m] || '#888';
      methodHtml += '<span style="margin-right:12px;font-size:0.78em"><span style="display:inline-block;width:8px;height:8px;background:' + col + ';border-radius:2px;margin-right:4px"></span>' + m + ': ' + methods[m] + '</span>';
    });
    var methodsEl = document.getElementById('replay-meta-methods');
    if (methodsEl) methodsEl.innerHTML = methodHtml;

    // Top paths
    var topPaths = meta.top_paths || [];
    var pathsHtml = '<div style="font-size:0.78em;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px">Top Paths</div>';
    if (topPaths.length > 0) {
      topPaths.slice(0, 10).forEach(function(p) {
        var name = p.path || p.Path || '';
        var count = p.count || p.Count || 0;
        pathsHtml += '<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:0.78em;border-bottom:1px solid #1a1a1a">' +
          '<span style="color:#aaa;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%%">' + escapeHtml(name) + '</span>' +
          '<span style="color:#00ffcc">' + count + '</span></div>';
      });
    } else {
      pathsHtml += '<div style="color:#555;font-size:0.78em">No paths recorded</div>';
    }
    var pathsEl = document.getElementById('replay-meta-paths');
    if (pathsEl) pathsEl.innerHTML = pathsHtml;

    // Protocols
    var protocols = meta.protocols || [];
    var protoEl = document.getElementById('replay-meta-protocols');
    if (protoEl) {
      if (protocols.length > 0) {
        protoEl.innerHTML = 'Protocols: ' + protocols.map(function(p) {
          return '<span style="background:#1a1a1a;border:1px solid #333;padding:2px 8px;border-radius:4px;margin-right:4px;color:#aaa">' + escapeHtml(p) + '</span>';
        }).join('');
      } else {
        protoEl.innerHTML = '';
      }
    }
  }

  window.replayLoad = async function(file) {
    try {
      toast('Loading ' + file + '...');
      const d = await fetch(API + '/admin/api/replay/load', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file: file})
      }).then(r => r.json());
      if (d.ok) {
        toast('Loaded ' + d.packets + ' packets from ' + file);
        refreshReplayStatus();
      } else {
        toast('Error: ' + (d.error || 'unknown'));
      }
    } catch(e) { console.error('replayLoad:', e); }
  };

  window.replayUpload = async function() {
    var fileInput = document.getElementById('replay-upload-file');
    if (!fileInput.files || fileInput.files.length === 0) {
      toast('Select a file first');
      return;
    }
    var formData = new FormData();
    formData.append('file', fileInput.files[0]);
    try {
      toast('Uploading...');
      var resp = await fetch(API + '/admin/api/replay/upload', {
        method: 'POST',
        body: formData
      }).then(r => r.json());
      if (resp.ok) {
        toast('Uploaded: ' + resp.file + ' (' + resp.size + ')');
        fileInput.value = '';
        document.getElementById('replay-upload-filename').textContent = 'No file chosen';
        refreshReplayFiles();
      } else {
        toast('Upload error: ' + (resp.error || 'unknown'));
      }
    } catch(e) {
      toast('Upload failed: ' + e.message);
      console.error('replayUpload:', e);
    }
  };

  window.replayFetchURL = async function() {
    var urlVal = document.getElementById('replay-fetch-url').value;
    if (!urlVal) {
      toast('Enter a URL first');
      return;
    }
    try {
      toast('Fetching from URL...');
      var resp = await fetch(API + '/admin/api/replay/fetch-url', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: urlVal})
      }).then(r => r.json());
      if (resp.ok) {
        toast('Downloaded: ' + resp.file + ' (' + resp.size + ')');
        document.getElementById('replay-fetch-url').value = '';
        refreshReplayFiles();
      } else {
        toast('Fetch error: ' + (resp.error || 'unknown'));
      }
    } catch(e) {
      toast('Fetch failed: ' + e.message);
      console.error('replayFetchURL:', e);
    }
  };

  window.replayCleanup = async function() {
    var maxMB = parseFloat(document.getElementById('replay-cleanup-size').value) || 500;
    try {
      var resp = await fetch(API + '/admin/api/replay/cleanup', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({max_size_mb: maxMB})
      }).then(r => r.json());
      if (resp.ok) {
        toast('Cleaned up: ' + resp.deleted + ' files, freed ' + (resp.freed_mb || 0).toFixed(1) + ' MB');
        refreshReplayFiles();
      } else {
        toast('Cleanup error: ' + (resp.error || 'unknown'));
      }
    } catch(e) {
      toast('Cleanup failed: ' + e.message);
      console.error('replayCleanup:', e);
    }
  };

  window.setReplaySpeed = function(speed) {
    var el = document.getElementById('replay-speed');
    el.value = speed;
    document.getElementById('replay-speed-val').textContent = speed + 'x';
  };

  window.replayStart = async function() {
    var target = document.getElementById('replay-target').value || 'http://localhost:8765';
    var timing = document.getElementById('replay-timing').value;
    var speed = parseFloat(document.getElementById('replay-speed').value) || 1.0;
    var filter = document.getElementById('replay-filter').value;
    var loop = document.getElementById('replay-loop') ? document.getElementById('replay-loop').checked : false;
    try {
      const d = await fetch(API + '/admin/api/replay/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target, timing: timing, speed: speed, filter_path: filter, loop: loop})
      }).then(r => r.json());
      if (d.ok) {
        toast('Replay started against ' + target);
        refreshReplayStatus();
      } else {
        toast('Error: ' + (d.error || 'unknown'));
      }
    } catch(e) { console.error('replayStart:', e); }
  };

  window.replayPause = async function() {
    await window.replayStop();
  };

  window.replayStop = async function() {
    try {
      await fetch(API + '/admin/api/replay/stop', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: '{}'
      });
      toast('Replay stopped');
      refreshReplayStatus();
    } catch(e) { console.error('replayStop:', e); }
  };

  // ------ Nightmare mode ------
  window.toggleNightmareAll = async function() {
    try {
      var d = await api('/admin/api/nightmare');
      var anyActive = d.server || d.scanner || d.proxy;
      var resp = await fetch(API + '/admin/api/nightmare', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode: 'all', enabled: !anyActive})
      }).then(r => r.json());
      if (resp.ok) {
        toast(!anyActive ? 'NIGHTMARE MODE ACTIVATED' : 'Nightmare mode deactivated');
        refreshNightmareBar();
        refresh();
      }
    } catch(e) { console.error('nightmare:', e); }
  };

  window.toggleNightmareMode = async function(mode) {
    try {
      var d = await api('/admin/api/nightmare');
      var current = d[mode] || false;
      await fetch(API + '/admin/api/nightmare', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode: mode, enabled: !current})
      });
      refreshNightmareBar();
      refresh();
    } catch(e) { console.error('nightmare:', e); }
  };

  async function refreshNightmareBar() {
    try {
      var d = await api('/admin/api/nightmare');
      var bar = document.getElementById('nightmare-bar');
      var label = document.getElementById('nightmare-label');
      var modes = document.getElementById('nightmare-modes');
      var anyActive = d.server || d.scanner || d.proxy;
      bar.className = 'nightmare-bar ' + (anyActive ? 'on' : 'off');
      if (anyActive) {
        var active = [];
        if (d.server) active.push('Server');
        if (d.scanner) active.push('Scanner');
        if (d.proxy) active.push('Proxy');
        label.textContent = 'NIGHTMARE MODE ACTIVE';
        modes.textContent = active.join(' + ');
      } else {
        label.textContent = 'NIGHTMARE: OFF';
        modes.textContent = '';
      }
      var btn = document.getElementById('dash-nightmare-btn');
      if (btn) btn.textContent = anyActive ? 'Disable Nightmare' : 'Enable Nightmare';
      // Body nightmare class
      if (anyActive) document.body.classList.add('nightmare-active');
      else document.body.classList.remove('nightmare-active');
      // Per-mode nightmare buttons
      var srvBtn = document.getElementById('srv-nightmare-btn');
      if (srvBtn) srvBtn.textContent = 'Nightmare: ' + (d.server ? 'ON' : 'OFF');
      var scanBtn = document.getElementById('scan-nightmare-btn');
      if (scanBtn) scanBtn.textContent = 'Nightmare: ' + (d.scanner ? 'ON' : 'OFF');
      var proxyBtn = document.getElementById('proxy-nightmare-btn');
      if (proxyBtn) proxyBtn.textContent = 'Nightmare: ' + (d.proxy ? 'ON' : 'OFF');
    } catch(e) {}
  }

  // ------ Password change ------
  window.changePassword = async function() {
    var current = document.getElementById('settings-current-pw').value;
    var newPw = document.getElementById('settings-new-pw').value;
    var confirmPw = document.getElementById('settings-confirm-pw').value;
    var status = document.getElementById('settings-pw-status');
    if (!current || !newPw) { status.style.color = '#ff4444'; status.textContent = 'All fields required'; return; }
    if (newPw !== confirmPw) { status.style.color = '#ff4444'; status.textContent = 'New passwords do not match'; return; }
    try {
      var resp = await fetch(API + '/admin/api/password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({current: current, new: newPw})
      }).then(r => r.json());
      if (resp.ok) {
        status.style.color = '#00ff88';
        status.textContent = 'Password changed. You may need to re-login.';
        document.getElementById('settings-current-pw').value = '';
        document.getElementById('settings-new-pw').value = '';
        document.getElementById('settings-confirm-pw').value = '';
      } else {
        status.style.color = '#ff4444';
        status.textContent = resp.error || 'Failed';
      }
    } catch(e) {
      status.style.color = '#ff4444';
      status.textContent = 'Error: ' + e.message;
    }
  };

  // ------ Proxy Runtime Controls ------
  window.startProxy = async function() {
    var port = parseInt(document.getElementById('proxy-rt-port').value) || 8080;
    var target = document.getElementById('proxy-rt-target').value || 'http://localhost:8765';
    try {
      await api('/admin/api/proxy/runtime', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'start', port: port, target: target})
      });
      toast('Proxy started on :' + port);
      refreshProxy();
    } catch(e) { toast('Failed to start proxy: ' + e.message); }
  };

  window.stopProxy = async function() {
    try {
      await api('/admin/api/proxy/runtime', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'stop'})
      });
      toast('Proxy stopped');
      refreshProxy();
    } catch(e) { toast('Failed to stop proxy: ' + e.message); }
  };

  window.restartProxy = async function() {
    try {
      await api('/admin/api/proxy/runtime', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'restart'})
      });
      toast('Proxy restarted');
      refreshProxy();
    } catch(e) { toast('Failed to restart proxy: ' + e.message); }
  };

  // ------ Recording Controls ------
  window.startRecording = async function() {
    var fmt = document.getElementById('rec-format');
    var format = fmt ? fmt.value : 'jsonl';
    var dur = parseInt(document.getElementById('rec-max-dur')?.value || '0');
    var reqs = parseInt(document.getElementById('rec-max-reqs')?.value || '0');
    try {
      await api('/admin/api/recorder/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({format: format, max_duration_sec: dur, max_requests: reqs})
      });
      toast('Recording started (' + format + ')');
      refreshRecorderUI();
    } catch(e) { toast('Failed to start recording: ' + e.message); }
  };

  window.stopRecording = async function() {
    try {
      await api('/admin/api/recorder/stop', { method: 'POST' });
      toast('Recording stopped');
      refreshRecorderUI();
    } catch(e) { toast('Failed to stop recording: ' + e.message); }
  };

  function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    return (b/1048576).toFixed(1) + ' MB';
  }

  async function refreshRecorderUI() {
    try {
      var st = await api('/admin/api/recorder/status');
      // Server tab elements
      var startBtn = document.getElementById('rec-start-btn');
      var stopBtn = document.getElementById('rec-stop-btn');
      var statusEl = document.getElementById('rec-status');
      var statsDiv = document.getElementById('rec-stats');
      // Proxy tab elements
      var pStartBtn = document.getElementById('proxy-rec-start-btn');
      var pStopBtn = document.getElementById('proxy-rec-stop-btn');
      var pStatusEl = document.getElementById('proxy-rec-status');

      if (st.recording) {
        if (startBtn) startBtn.style.display = 'none';
        if (stopBtn) stopBtn.style.display = '';
        if (statusEl) { statusEl.style.color = '#00ff88'; statusEl.textContent = 'Recording (' + (st.format || 'jsonl') + ')'; }
        if (statsDiv) statsDiv.style.display = '';
        var countEl = document.getElementById('rec-count');
        if (countEl) countEl.textContent = (st.records || 0).toLocaleString();
        var sizeEl = document.getElementById('rec-size');
        if (sizeEl) sizeEl.textContent = fmtBytes(st.size_bytes || 0);
        var elapEl = document.getElementById('rec-elapsed');
        if (elapEl) elapEl.textContent = (st.elapsed_sec || 0).toFixed(0) + 's';
        var fileEl = document.getElementById('rec-file');
        if (fileEl) fileEl.textContent = st.file_name || '--';
        // Proxy tab
        if (pStartBtn) pStartBtn.style.display = 'none';
        if (pStopBtn) pStopBtn.style.display = '';
        if (pStatusEl) { pStatusEl.style.color = '#00ff88'; pStatusEl.textContent = 'Recording: ' + (st.records||0) + ' records'; }
      } else {
        if (startBtn) startBtn.style.display = '';
        if (stopBtn) stopBtn.style.display = 'none';
        if (statusEl) { statusEl.style.color = '#555'; statusEl.textContent = 'Idle'; }
        if (statsDiv) statsDiv.style.display = 'none';
        if (pStartBtn) pStartBtn.style.display = '';
        if (pStopBtn) pStopBtn.style.display = 'none';
        if (pStatusEl) { pStatusEl.style.color = '#555'; pStatusEl.textContent = 'Idle'; }
      }
    } catch(e) { /* recorder API may not exist */ }
  }

  // ------ Server panel refresh ------
  async function refreshServer() {
    // Update server status bar
    try {
      var m = await api('/api/metrics');
      var statusText = document.getElementById('srv-status-text');
      if (statusText) statusText.textContent = 'RUNNING';
      var errRate = document.getElementById('srv-status-errrate');
      if (errRate) errRate.textContent = ((m.error_rate_pct||0).toFixed(1)) + '%%';
      var clients = document.getElementById('srv-status-clients');
      if (clients) clients.textContent = m.unique_clients || 0;
    } catch(e) {}
    // Count enabled features
    try {
      var f = await api('/admin/api/features');
      var total = Object.keys(f).length;
      var enabled = Object.values(f).filter(function(v){return v}).length;
      var featEl = document.getElementById('srv-status-features');
      if (featEl) featEl.textContent = enabled + '/' + total + ' enabled';
    } catch(e) {}

    // Only refresh the open sections to avoid unnecessary API calls
    var sections = document.querySelectorAll('.srv-section.open');
    for (var i = 0; i < sections.length; i++) {
      var id = sections[i].id;
      if (id === 'srv-features' || id === 'srv-errors' || id === 'srv-content' || id === 'srv-labyrinth' || id === 'srv-adaptive' || id === 'srv-traps' || id === 'srv-spider') await refreshControls();
      else if (id === 'srv-vulns') await refreshVulns();
      else if (id === 'srv-sessions') await refreshSessions();
      // srv-log and srv-traffic moved to dashboard
      else if (id === 'srv-recording') await refreshRecorderUI();
    }
  }

  // ------ Settings refresh ------
  async function refreshSettings() {
    try {
      var d = await api('/api/metrics');
      var upEl = document.getElementById('settings-uptime');
      if (upEl && d.uptime_seconds) upEl.textContent = fmtUptime(d.uptime_seconds);
      // Set port info from current location
      var dashPort = document.getElementById('settings-dash-port');
      if (dashPort) dashPort.textContent = window.location.port || '8766';
      var srvPort = document.getElementById('settings-server-port');
      if (srvPort) srvPort.textContent = (parseInt(window.location.port || '8766') - 1) + '';
    } catch(e) {}
  }

  // ------ Main loop ------
  async function refresh() {
    refreshNightmareBar();
    const active = document.querySelector('.panel.active');
    if (!active) return;
    const id = active.id;
    if (id === 'panel-dashboard') await refreshDashboard();
    else if (id === 'panel-server') await refreshServer();
    else if (id === 'panel-scanner') {
      var replayPanel = document.getElementById('scanner-replay-panel');
      if (replayPanel && replayPanel.style.display !== 'none') await refreshReplay();
      else if (document.getElementById('scanner-builtin-panel').style.display !== 'none') await refreshBuiltinScanner();
      else await refreshScannerTab();
    }
    else if (id === 'panel-proxy') await refreshProxy();
    else if (id === 'panel-settings') await refreshSettings();
  }

  // Initial load — restore tab from URL hash
  (async function init() {
    var hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById('panel-' + hash)) {
      showTab(hash, false);
    }
    await refresh();
  })();

  setInterval(refresh, 3000);
})();
</script>
</body>
</html>`)
