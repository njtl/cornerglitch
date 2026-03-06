#!/bin/bash
# WAF Testing Helper Script
# Tests ModSecurity PL2 (8083), ModSecurity PL4 (8084), NAXSI (8085)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MODSEC_PL2_PORT=8083
MODSEC_PL4_PORT=8084
NAXSI_PORT=8085

log() { echo -e "${CYAN}[waf-test]${NC} $1"; }
pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
bypass() { echo -e "  ${GREEN}BYPASS${NC} $1"; }
blocked() { echo -e "  ${YELLOW}BLOCKED${NC} $1"; }

# Test a single request and report if it was blocked or passed
test_request() {
    local name=$1
    local port=$2
    local method=${3:-GET}
    local url=$4
    local extra_args=$5
    local expect_block=${6:-true}

    local cmd="curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X $method"
    if [ -n "$extra_args" ]; then
        cmd="$cmd $extra_args"
    fi
    cmd="$cmd 'http://127.0.0.1:${port}${url}'"

    local status=$(eval $cmd 2>/dev/null || echo "000")

    if [ "$status" = "403" ] || [ "$status" = "000" ]; then
        if [ "$expect_block" = "true" ]; then
            blocked "$name (${status})" >&2
        else
            fail "$name — false positive (${status})" >&2
        fi
        echo "BLOCKED"
    else
        if [ "$expect_block" = "true" ]; then
            bypass "$name (${status})" >&2
        else
            pass "$name (${status})" >&2
        fi
        echo "PASSED"
    fi
}

# Run comprehensive bypass tests against a single WAF
run_bypass_suite() {
    local waf_name=$1
    local port=$2
    local bypasses=0
    local total=0
    local result=""

    log "=== Bypass Testing: ${waf_name} (port ${port}) ==="
    echo ""

    # --- Category 1: Encoding Bypasses ---
    log "Category 1: Encoding Bypasses"

    total=$((total + 1))
    result=$(test_request "Double URL encoded SQLi (%2527)" $port GET "/?id=%2527%2520OR%25201%253D1--" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Unicode fullwidth XSS" $port GET "/?q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "HTML entity with leading zeros" $port POST "/comment" "-H 'Content-Type: application/x-www-form-urlencoded' -d 'body=%26%230000060%3Bscript%26%230000062%3Balert(1)%26%230000060%3B/script%26%230000062%3B'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "UTF-7 XSS (+ADw-script)" $port POST "/comment" "-H 'Content-Type: text/html; charset=utf-7' -d '+ADw-script+AD4-alert(1)+ADw-/script+AD4-'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Mixed case SQL (SeLeCt)" $port GET "/?q=SeLeCt%20*%20FrOm%20users" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Comment-injected SQL" $port GET "/?q=SEL/**/ECT%20*%20FROM%20users" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Overlong UTF-8 path traversal" $port GET "/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    echo ""

    # --- Category 2: Parser Confusion ---
    log "Category 2: Parser Confusion"

    total=$((total + 1))
    result=$(test_request "SQLi via JSON body" $port POST "/api/data" "-H 'Content-Type: application/json' -d '{\"q\":\"SELECT * FROM users WHERE 1=1\"}'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Content-Type confusion" $port POST "/api/data" "-H 'Content-Type: text/plain' -d 'SELECT * FROM users WHERE id=1 OR 1=1'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Parameter pollution" $port GET "/?id=1&id=OR%201=1--" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Double-slash path confusion" $port GET "//admin/../../etc/passwd" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Method override (X-HTTP-Method-Override)" $port POST "/api/users/1" "-H 'X-HTTP-Method-Override: DELETE'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "X-Original-URL header override" $port GET "/safe-page" "-H 'X-Original-URL: /admin'" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    echo ""

    # --- Category 3: CVE-Specific ---
    log "Category 3: CVE-Specific Bypasses"

    total=$((total + 1))
    result=$(test_request "CVE-2024-1019: percent-encoded path bypass" $port GET "/%2561dmin?cmd=id" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Null byte truncation" $port GET "/admin%00.jpg" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "CRLF injection" $port GET "/?q=%0d%0aX-Injected:%20true" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    echo ""

    # --- Category 4: Evasion Techniques ---
    log "Category 4: Evasion Techniques"

    total=$((total + 1))
    result=$(test_request "SQL concat bypass" $port GET "/?q=CONCAT(0x73656c656374)" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "SQL alternative syntax (exec)" $port GET "/?q=EXEC('sel'%2B'ect%201')" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "XSS via data: URI" $port GET "/?url=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "XSS via event handler" $port GET "/?q=%3Cimg%20src=x%20onerror=alert(1)%3E" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Path traversal with dot encoding" $port GET "/%2e%2e/%2e%2e/etc/passwd" "" true)
    [ "$result" = "PASSED" ] && bypasses=$((bypasses + 1))

    echo ""

    # --- Category 5: False Positive Check ---
    log "Category 5: False Positive Check (should NOT block)"

    total=$((total + 1))
    result=$(test_request "Normal GET request" $port GET "/index.html" "" false)
    [ "$result" != "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Normal POST form" $port POST "/api/contact" "-H 'Content-Type: application/x-www-form-urlencoded' -d 'name=John&email=john@example.com'" false)
    [ "$result" != "PASSED" ] && bypasses=$((bypasses + 1))

    total=$((total + 1))
    result=$(test_request "Normal JSON API" $port POST "/api/users" "-H 'Content-Type: application/json' -d '{\"name\":\"John\",\"age\":30}'" false)
    [ "$result" != "PASSED" ] && bypasses=$((bypasses + 1))

    echo ""
    echo -e "  ${CYAN}==============================${NC}"
    echo -e "  ${CYAN}${waf_name} Score: ${bypasses}/${total} bypasses/issues${NC}"
    echo -e "  ${CYAN}==============================${NC}"
    echo ""
}

# Resource usage
monitor() {
    log "WAF Container Resource Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
        modsec-waf modsec-waf-pl4 naxsi-waf 2>/dev/null || echo "Some containers not running"
    echo ""
}

case "${1:-all}" in
    modsec)
        run_bypass_suite "ModSecurity PL2" $MODSEC_PL2_PORT
        ;;
    modsec-pl4)
        run_bypass_suite "ModSecurity PL4" $MODSEC_PL4_PORT
        ;;
    naxsi)
        run_bypass_suite "NAXSI" $NAXSI_PORT
        ;;
    monitor)
        monitor
        ;;
    all)
        run_bypass_suite "ModSecurity PL2" $MODSEC_PL2_PORT
        run_bypass_suite "ModSecurity PL4" $MODSEC_PL4_PORT
        run_bypass_suite "NAXSI" $NAXSI_PORT
        monitor
        ;;
    *)
        echo "Usage: $0 {modsec|modsec-pl4|naxsi|monitor|all}"
        exit 1
        ;;
esac
