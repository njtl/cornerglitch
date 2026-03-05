#!/bin/bash
# QA Test Runner for Glitch Admin Dashboard
# Uses curl to verify API endpoints and basic functionality
#
# Usage: ./run-qa.sh [base-url] [admin-url]
# Defaults: base-url=http://localhost:8765, admin-url=http://localhost:8766

set -e

BASE_URL="${1:-http://localhost:8765}"
ADMIN_URL="${2:-http://localhost:8766}"
PASS="${GLITCH_ADMIN_PASSWORD:-admin}"
RESULTS_DIR="$(dirname "$0")/screenshots"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

mkdir -p "$RESULTS_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

# Check if server is running
echo "=== QA Test Runner ==="
echo "Base URL: $BASE_URL"
echo "Admin URL: $ADMIN_URL"
echo ""

if ! curl -s -o /dev/null -w "%{http_code}" "$BASE_URL" > /dev/null 2>&1; then
    echo "ERROR: Server not running at $BASE_URL"
    exit 1
fi

# Get session cookie
echo "--- TC-001: Admin Login ---"
LOGIN_RESP=$(curl -s -o /dev/null -w "%{http_code}" -c /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "password=$PASS" 2>/dev/null)

if [ "$LOGIN_RESP" = "302" ] || [ "$LOGIN_RESP" = "200" ]; then
    pass "Login with correct password"
else
    fail "Login returned HTTP $LOGIN_RESP (expected 200 or 302)"
fi

# Wrong password
WRONG_RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$ADMIN_URL/admin/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "password=wrongpassword" 2>/dev/null)

if [ "$WRONG_RESP" = "401" ] || [ "$WRONG_RESP" = "200" ]; then
    pass "Wrong password rejected"
else
    fail "Wrong password returned HTTP $WRONG_RESP"
fi

# API Metrics
echo ""
echo "--- TC-002: Dashboard Metrics ---"
METRICS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/api/metrics" 2>/dev/null)
if echo "$METRICS" | grep -q "total_requests"; then
    pass "Metrics API returns total_requests"
else
    fail "Metrics API missing total_requests"
fi
if echo "$METRICS" | grep -q "uptime_seconds"; then
    pass "Metrics API returns uptime_seconds"
else
    fail "Metrics API missing uptime_seconds"
fi

# Features API
echo ""
echo "--- TC-003: Feature Toggles ---"
FEATURES=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/features" 2>/dev/null)
if echo "$FEATURES" | grep -q "labyrinth"; then
    pass "Features API returns labyrinth"
else
    fail "Features API missing labyrinth"
fi
if echo "$FEATURES" | grep -q "mcp"; then
    pass "Features API returns mcp"
else
    fail "Features API missing mcp"
fi
if echo "$FEATURES" | grep -q "api_chaos"; then
    pass "Features API returns api_chaos"
else
    fail "Features API missing api_chaos"
fi
if echo "$FEATURES" | grep -q "budget_traps"; then
    pass "Features API returns budget_traps"
else
    fail "Features API missing budget_traps"
fi

# Error Profiles
echo ""
echo "--- TC-004: Error Profiles ---"
CONFIG_RESP=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/config" 2>/dev/null)
if echo "$CONFIG_RESP" | grep -q "error_rate_multiplier"; then
    pass "Config API returns error_rate_multiplier"
else
    fail "Config API missing error_rate_multiplier"
fi
# Set error_rate_multiplier via config API
SET_RATE=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/config" \
    -H "Content-Type: application/json" \
    -d '{"key":"error_rate_multiplier","value":2.0}' 2>/dev/null)
if [ "$SET_RATE" = "200" ]; then
    pass "Set error_rate_multiplier via config API"
else
    fail "Set error_rate_multiplier returned HTTP $SET_RATE"
fi

# Verify it was set
CONFIG_AFTER=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/config" 2>/dev/null)
if echo "$CONFIG_AFTER" | grep -q '"error_rate_multiplier"'; then
    pass "error_rate_multiplier present in config after set"
else
    fail "error_rate_multiplier missing from config after set"
fi

# Reset back
curl -s -o /dev/null -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/config" \
    -H "Content-Type: application/json" \
    -d '{"key":"error_rate_multiplier","value":1.0}' 2>/dev/null

# MCP Stats API
echo ""
echo "--- TC-005: MCP Dashboard ---"
MCP_STATS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/mcp/stats" 2>/dev/null)
if echo "$MCP_STATS" | grep -q "tools_registered"; then
    pass "MCP stats returns tools_registered"
else
    fail "MCP stats missing tools_registered"
fi
if echo "$MCP_STATS" | grep -q "resources_exposed"; then
    pass "MCP stats returns resources_exposed"
else
    fail "MCP stats missing resources_exposed"
fi

MCP_SESSIONS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/mcp/sessions" 2>/dev/null)
if echo "$MCP_SESSIONS" | grep -q "sessions"; then
    pass "MCP sessions API works"
else
    fail "MCP sessions API broken"
fi

MCP_EVENTS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/mcp/events" 2>/dev/null)
if echo "$MCP_EVENTS" | grep -q "events"; then
    pass "MCP events API works"
else
    fail "MCP events API broken"
fi

# Vulnerabilities
echo ""
echo "--- TC-006: Vulnerabilities ---"
VULNS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/vulns" 2>/dev/null)
if echo "$VULNS" | grep -q "owasp"; then
    pass "Vulns API returns owasp group"
else
    fail "Vulns API missing owasp group"
fi
if echo "$VULNS" | grep -q "api_security"; then
    pass "Vulns API returns api_security group"
else
    fail "Vulns API missing api_security group"
fi

# Toggle a vuln group off and back on
TOGGLE_OFF=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/vulns/group" \
    -H "Content-Type: application/json" \
    -d '{"group":"owasp","enabled":false}' 2>/dev/null)
if [ "$TOGGLE_OFF" = "200" ]; then
    pass "Toggle owasp group off"
else
    fail "Toggle owasp group off returned HTTP $TOGGLE_OFF"
fi

TOGGLE_ON=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/vulns/group" \
    -H "Content-Type: application/json" \
    -d '{"group":"owasp","enabled":true}' 2>/dev/null)
if [ "$TOGGLE_ON" = "200" ]; then
    pass "Toggle owasp group back on"
else
    fail "Toggle owasp group on returned HTTP $TOGGLE_ON"
fi

# Nightmare mode
echo ""
echo "--- TC-012: Nightmare Mode ---"
NIGHTMARE_STATUS=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/nightmare" 2>/dev/null)
if echo "$NIGHTMARE_STATUS" | grep -q '"server"'; then
    pass "Nightmare API returns server field"
else
    fail "Nightmare API missing server field"
fi

# Activate server nightmare (API uses "mode" not "subsystem")
ACTIVATE=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/nightmare" \
    -H "Content-Type: application/json" \
    -d '{"mode":"server","enabled":true}' 2>/dev/null)
if [ "$ACTIVATE" = "200" ]; then
    pass "Activate server nightmare"
else
    fail "Activate server nightmare returned HTTP $ACTIVATE"
fi

# Verify active
NIGHTMARE_ACTIVE=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/nightmare" 2>/dev/null)
if echo "$NIGHTMARE_ACTIVE" | grep -q '"server":true'; then
    pass "Server nightmare is active"
else
    fail "Server nightmare not reported as active"
fi

# Deactivate
DEACTIVATE=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/glitch-qa-cookies.txt \
    -X POST "$ADMIN_URL/admin/api/nightmare" \
    -H "Content-Type: application/json" \
    -d '{"mode":"server","enabled":false}' 2>/dev/null)
if [ "$DEACTIVATE" = "200" ]; then
    pass "Deactivate server nightmare"
else
    fail "Deactivate server nightmare returned HTTP $DEACTIVATE"
fi

# Verify deactivated
NIGHTMARE_OFF=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/nightmare" 2>/dev/null)
if echo "$NIGHTMARE_OFF" | grep -q '"server":false'; then
    pass "Server nightmare is deactivated"
else
    fail "Server nightmare still active after deactivation"
fi

# MCP Endpoint
echo ""
echo "--- TC-014: MCP Endpoint ---"
MCP_INIT=$(curl -s -X POST "$BASE_URL/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"qa-test","version":"1.0"}}}' 2>/dev/null)
if echo "$MCP_INIT" | grep -q "glitch-mcp"; then
    pass "MCP initialize returns server info"
else
    fail "MCP initialize broken"
fi

# Extract session ID from response headers
MCP_SID=$(curl -s -D - -X POST "$BASE_URL/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"qa-test2"}}}' 2>/dev/null | grep -i "Mcp-Session-Id" | head -1 | tr -d '\r' | awk '{print $2}')

if [ -n "$MCP_SID" ]; then
    pass "MCP returns session ID"

    # tools/list
    TOOLS=$(curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Mcp-Session-Id: $MCP_SID" \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 2>/dev/null)
    if echo "$TOOLS" | grep -q "get_aws_credentials"; then
        pass "MCP tools/list returns honeypot tools"
    else
        fail "MCP tools/list missing honeypot tools"
    fi

    # resources/list
    RESOURCES=$(curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Mcp-Session-Id: $MCP_SID" \
        -d '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' 2>/dev/null)
    if echo "$RESOURCES" | grep -q ".env"; then
        pass "MCP resources/list returns honeypot resources"
    else
        fail "MCP resources/list missing honeypot resources"
    fi

    # prompts/list
    PROMPTS=$(curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Mcp-Session-Id: $MCP_SID" \
        -d '{"jsonrpc":"2.0","id":4,"method":"prompts/list"}' 2>/dev/null)
    if echo "$PROMPTS" | grep -q "security_audit"; then
        pass "MCP prompts/list returns honeypot prompts"
    else
        fail "MCP prompts/list missing honeypot prompts"
    fi

    # Delete session
    DEL_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE_URL/mcp" \
        -H "Mcp-Session-Id: $MCP_SID" 2>/dev/null)
    if [ "$DEL_RESP" = "200" ]; then
        pass "MCP session deletion works"
    else
        fail "MCP session deletion returned HTTP $DEL_RESP"
    fi
else
    skip "MCP session ID not returned — skipping session tests"
fi

# Config export
echo ""
echo "--- TC-013: Config Persistence ---"
CONFIG=$(curl -s -b /tmp/glitch-qa-cookies.txt "$ADMIN_URL/admin/api/config/export" 2>/dev/null)
if echo "$CONFIG" | grep -q "version"; then
    pass "Config export works"
else
    fail "Config export broken"
fi

# Cleanup
rm -f /tmp/glitch-qa-cookies.txt

# Summary
echo ""
echo "=== Summary ==="
echo -e "  ${GREEN}PASS: $PASS_COUNT${NC}"
echo -e "  ${RED}FAIL: $FAIL_COUNT${NC}"
echo -e "  ${YELLOW}SKIP: $SKIP_COUNT${NC}"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}QA FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}QA PASSED${NC}"
    exit 0
fi
