# QA Screenshots

Baseline screenshots of all admin panels. Capture using a browser or `agent-browser` CLI.

## Expected Screenshots

| File | Description |
|------|-------------|
| `01-login.png` | Login page |
| `02-dashboard-overview.png` | Dashboard tab with metrics |
| `03-server-features.png` | Server tab — Features section expanded |
| `04-server-errors.png` | Server tab — Errors section expanded |
| `05-server-mcp.png` | Server tab — MCP Honeypot section expanded |
| `06-server-vulns.png` | Server tab — Vulnerabilities section |
| `07-server-apichaos.png` | Server tab — API Chaos section |
| `08-server-mediachaos.png` | Server tab — Media Chaos section |
| `09-scanner-eval.png` | Scanner tab — Evaluate External |
| `10-scanner-builtin.png` | Scanner tab — Built-in Scanner |
| `11-scanner-replay.png` | Scanner tab — PCAP Replay |
| `12-scanner-mcp.png` | Scanner tab — MCP Scanner |
| `13-proxy.png` | Proxy tab |
| `14-settings.png` | Settings tab |
| `15-nightmare-active.png` | Nightmare mode active (red bar) |

## Capture Command

```bash
# Using agent-browser (if available)
agent-browser screenshot http://localhost:8766/admin --output 02-dashboard-overview.png
```
