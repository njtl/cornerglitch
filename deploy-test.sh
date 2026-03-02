#!/bin/bash
# deploy-test.sh — Test all supported deployment methods from clean checkout
# Usage: ./deploy-test.sh [method]
# Methods: bare, makefile, docker, compose, all (default)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
RESULTS_FILE="$REPO_ROOT/deploy-test-results.md"
MASTER_BRANCH="master"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[deploy-test]${NC} $*"; }
warn() { echo -e "${YELLOW}[deploy-test]${NC} $*"; }
fail() { echo -e "${RED}[deploy-test]${NC} $*"; }

# Wait for HTTP endpoint to be ready
wait_for_http() {
    local url=$1 max_wait=${2:-30} i=0
    while [ $i -lt $max_wait ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# Helper: test with retries for chaos-affected endpoints
# Returns 0 on first success, 1 if all attempts fail
curl_with_retry() {
    local url=$1 pattern=$2 max=${3:-10}
    for attempt in $(seq 1 "$max"); do
        local body
        body=$(curl -sf "$url" 2>&1 || true)
        if echo "$body" | grep -qi "$pattern"; then
            return 0
        fi
        sleep 0.3
    done
    return 1
}

# Record a test result
declare -a TEST_RESULTS=()
record_result() {
    local num=$1 name=$2 status=$3
    TEST_RESULTS+=("| $num | $name | $status |")
}

# Run tests against a running server
run_tests() {
    local server_port=$1 admin_port=$2 admin_pass=$3 method=$4
    local pass=0 fail_count=0
    TEST_RESULTS=()

    log "Running tests against localhost:$server_port (admin: $admin_port)"

    # Test 1: Health endpoint
    if curl -sf "http://localhost:$server_port/health" > /dev/null 2>&1; then
        log "  PASS: Health endpoint responds"
        record_result 1 "Health endpoint" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Health endpoint not responding"
        record_result 1 "Health endpoint" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 2: Health/live endpoint
    if curl -sf "http://localhost:$server_port/health/live" > /dev/null 2>&1; then
        log "  PASS: Health/live endpoint responds"
        record_result 2 "Health/live endpoint" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Health/live endpoint not responding"
        record_result 2 "Health/live endpoint" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 3: Main page returns HTML (retry — chaos server injects errors on /)
    if curl_with_retry "http://localhost:$server_port/" "html" 10; then
        log "  PASS: Main page returns HTML"
        record_result 3 "Main page returns HTML" "**Pass** (with retry)"
        pass=$((pass + 1))
    else
        fail "  FAIL: Main page does not return HTML after 10 attempts"
        record_result 3 "Main page returns HTML" "**Fail** — chaos errors on all 10 attempts"
        fail_count=$((fail_count + 1))
    fi

    # Test 4: Admin panel requires auth (redirects to login)
    local admin_status
    admin_status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:$admin_port/admin/" 2>&1 || true)
    if [ "$admin_status" = "302" ] || [ "$admin_status" = "401" ]; then
        log "  PASS: Admin panel requires authentication ($admin_status)"
        record_result 4 "Admin requires auth" "**Pass** ($admin_status)"
        pass=$((pass + 1))
    else
        fail "  FAIL: Admin panel returned $admin_status instead of 302/401"
        record_result 4 "Admin requires auth" "**Fail** — got $admin_status"
        fail_count=$((fail_count + 1))
    fi

    # Test 5: Admin login works
    local admin_config
    admin_config=$(curl -sf -u "admin:$admin_pass" "http://localhost:$admin_port/admin/api/config" 2>&1 || true)
    if echo "$admin_config" | grep -q "error_rate_multiplier"; then
        log "  PASS: Admin API returns config"
        record_result 5 "Admin API config" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Admin API config not accessible"
        record_result 5 "Admin API config" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 6: Metrics endpoint (via /api/metrics on admin port)
    local metrics
    metrics=$(curl -sf -u "admin:$admin_pass" "http://localhost:$admin_port/api/metrics" 2>&1 || true)
    if echo "$metrics" | grep -q "total_requests"; then
        log "  PASS: Metrics endpoint works"
        record_result 6 "Metrics endpoint" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Metrics endpoint not working"
        record_result 6 "Metrics endpoint" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 7: Feature flags endpoint
    local features
    features=$(curl -sf -u "admin:$admin_pass" "http://localhost:$admin_port/admin/api/features" 2>&1 || true)
    if echo "$features" | grep -q "labyrinth"; then
        log "  PASS: Feature flags endpoint works"
        record_result 7 "Feature flags" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Feature flags endpoint not working"
        record_result 7 "Feature flags" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 8: Vuln endpoints accessible
    local vuln_status
    vuln_status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:$server_port/vuln/" 2>&1 || true)
    if [ "$vuln_status" = "200" ]; then
        log "  PASS: Vulnerability endpoints accessible"
        record_result 8 "Vuln endpoints" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Vulnerability endpoints returned $vuln_status"
        record_result 8 "Vuln endpoints" "**Fail** — got $vuln_status"
        fail_count=$((fail_count + 1))
    fi

    # Test 9: API endpoints work
    local api_users
    api_users=$(curl -sf "http://localhost:$server_port/api/v1/users" 2>&1 || true)
    if echo "$api_users" | grep -q "users\|id\|name"; then
        log "  PASS: API endpoints work"
        record_result 9 "API endpoints" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: API endpoints not working"
        record_result 9 "API endpoints" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 10: Feature toggle round-trip
    local toggle_resp
    toggle_resp=$(curl -sf -X POST -u "admin:$admin_pass" \
        -H "Content-Type: application/json" \
        -d '{"feature":"labyrinth","enabled":false}' \
        "http://localhost:$admin_port/admin/api/features" 2>&1 || true)
    if echo "$toggle_resp" | grep -q "ok\|labyrinth"; then
        local check_resp
        check_resp=$(curl -sf -u "admin:$admin_pass" "http://localhost:$admin_port/admin/api/features" 2>&1 || true)
        if echo "$check_resp" | grep -q '"labyrinth":false'; then
            curl -sf -X POST -u "admin:$admin_pass" \
                -H "Content-Type: application/json" \
                -d '{"feature":"labyrinth","enabled":true}' \
                "http://localhost:$admin_port/admin/api/features" > /dev/null 2>&1 || true
            log "  PASS: Feature toggle round-trip works"
            record_result 10 "Feature toggle round-trip" "**Pass**"
            pass=$((pass + 1))
        else
            fail "  FAIL: Feature toggle did not persist"
            record_result 10 "Feature toggle round-trip" "**Fail** — toggle not persisted"
            fail_count=$((fail_count + 1))
        fi
    else
        fail "  FAIL: Feature toggle round-trip failed"
        record_result 10 "Feature toggle round-trip" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 11: Config update round-trip
    local config_resp
    config_resp=$(curl -sf -X POST -u "admin:$admin_pass" \
        -H "Content-Type: application/json" \
        -d '{"key":"error_rate_multiplier","value":2.0}' \
        "http://localhost:$admin_port/admin/api/config" 2>&1 || true)
    if echo "$config_resp" | grep -q "ok\|success\|error_rate"; then
        curl -sf -X POST -u "admin:$admin_pass" \
            -H "Content-Type: application/json" \
            -d '{"key":"error_rate_multiplier","value":1.0}' \
            "http://localhost:$admin_port/admin/api/config" > /dev/null 2>&1 || true
        log "  PASS: Config update round-trip works"
        record_result 11 "Config update round-trip" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Config update round-trip failed"
        record_result 11 "Config update round-trip" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 12: Honeypot endpoints
    local honeypot
    honeypot=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:$server_port/.env" 2>&1 || true)
    if [ "$honeypot" = "200" ] || [ "$honeypot" = "403" ]; then
        log "  PASS: Honeypot endpoint responds ($honeypot)"
        record_result 12 "Honeypot endpoints" "**Pass** ($honeypot)"
        pass=$((pass + 1))
    else
        fail "  FAIL: Honeypot endpoint returned $honeypot"
        record_result 12 "Honeypot endpoints" "**Fail** — got $honeypot"
        fail_count=$((fail_count + 1))
    fi

    # Test 13: Spider/robots.txt
    local robots
    robots=$(curl -sf "http://localhost:$server_port/robots.txt" 2>&1 || true)
    if echo "$robots" | grep -qi "user-agent\|disallow\|sitemap"; then
        log "  PASS: robots.txt is served"
        record_result 13 "robots.txt" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: robots.txt not served properly"
        record_result 13 "robots.txt" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    # Test 14: Labyrinth generates pages (retry — chaos may inject errors)
    if curl_with_retry "http://localhost:$server_port/deep/path/to/nowhere" "html\|href" 10; then
        log "  PASS: Labyrinth generates pages"
        record_result 14 "Labyrinth pages" "**Pass** (with retry)"
        pass=$((pass + 1))
    else
        fail "  FAIL: Labyrinth not generating pages after 10 attempts"
        record_result 14 "Labyrinth pages" "**Fail** — chaos errors on all 10 attempts"
        fail_count=$((fail_count + 1))
    fi

    # Test 15: Export/import config
    local export_resp
    export_resp=$(curl -sf -u "admin:$admin_pass" "http://localhost:$admin_port/admin/api/config/export" 2>&1 || true)
    if echo "$export_resp" | grep -q "features\|config\|vuln"; then
        log "  PASS: Config export works"
        record_result 15 "Config export" "**Pass**"
        pass=$((pass + 1))
    else
        fail "  FAIL: Config export not working"
        record_result 15 "Config export" "**Fail**"
        fail_count=$((fail_count + 1))
    fi

    log "Results: $pass passed, $fail_count failed (total: $((pass + fail_count)))"

    # Write per-test results to file
    {
        echo ""
        echo "### $method"
        echo ""
        echo "| # | Test | Status |"
        echo "|---|------|--------|"
        for r in "${TEST_RESULTS[@]}"; do
            echo "$r"
        done
        echo ""
        echo "**Result: $pass/15 passed**"
    } >> "$RESULTS_FILE"

    return $fail_count
}

# =========================================================================
# Method 1: Bare metal — direct binary
# =========================================================================
test_bare() {
    local dir="$REPO_ROOT/deploy-test-bare"
    local port=9100 admin_port=9101 pass="bare-test-pass"

    log "=== Testing: Bare metal (direct binary) ==="
    log "Ports: $port/$admin_port"

    # Clean checkout
    mkdir -p "$dir"
    rm -rf "$dir"/*
    git archive HEAD | tar -x -C "$dir"

    # Create .env
    cat > "$dir/.env" <<ENVEOF
GLITCH_ADMIN_PASSWORD=$pass
ENVEOF

    # Build
    cd "$dir"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o glitch ./cmd/glitch
    if [ ! -f "$dir/glitch" ]; then
        fail "Build failed for bare metal"
        cd "$REPO_ROOT"
        return 1
    fi
    log "Binary built successfully"

    # Start
    GLITCH_ADMIN_PASSWORD="$pass" nohup "$dir/glitch" -port "$port" -dash-port "$admin_port" > "$dir/server.log" 2>&1 &
    local pid=$!
    echo $pid > "$dir/server.pid"

    if ! wait_for_http "http://localhost:$port/health/live" 15; then
        fail "Server failed to start"
        cat "$dir/server.log"
        kill $pid 2>/dev/null || true
        cd "$REPO_ROOT"
        return 1
    fi
    log "Server started (PID $pid)"

    # Run tests
    local failures=0
    run_tests "$port" "$admin_port" "$pass" "bare" || failures=$?

    # Cleanup
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    log "Server stopped"
    cd "$REPO_ROOT"

    return $failures
}

# =========================================================================
# Method 2: Makefile background service
# =========================================================================
test_makefile() {
    local dir="$REPO_ROOT/deploy-test-makefile"
    local port=9200 admin_port=9201 pass="make-test-pass"

    log "=== Testing: Makefile build + custom ports ==="
    log "Ports: $port/$admin_port"

    # Clean checkout
    mkdir -p "$dir"
    rm -rf "$dir"/*
    git archive HEAD | tar -x -C "$dir"

    # Create .env
    cat > "$dir/.env" <<ENVEOF
GLITCH_ADMIN_PASSWORD=$pass
ENVEOF

    cd "$dir"

    # Use make to build (verifies Makefile build target works)
    make build 2>&1 || {
        fail "make build failed"
        cd "$REPO_ROOT"
        return 1
    }
    log "Binary built via Makefile"

    # Start with custom ports to avoid conflicts with any running server
    GLITCH_ADMIN_PASSWORD="$pass" nohup "$dir/glitch" -port "$port" -dash-port "$admin_port" > "$dir/server.log" 2>&1 &
    local pid=$!

    if ! wait_for_http "http://localhost:$port/health/live" 15; then
        fail "Server failed to start"
        cat "$dir/server.log"
        kill $pid 2>/dev/null || true
        cd "$REPO_ROOT"
        return 1
    fi
    log "Server started (PID $pid)"

    # Run tests
    local failures=0
    run_tests "$port" "$admin_port" "$pass" "makefile" || failures=$?

    # Cleanup
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    log "Server stopped"
    cd "$REPO_ROOT"

    return $failures
}

# =========================================================================
# Method 3: Docker Compose
# =========================================================================
test_compose() {
    local dir="$REPO_ROOT/deploy-test-compose"
    local pass="compose-test-pass"

    log "=== Testing: Docker Compose ==="

    # Check Docker daemon access
    if ! docker info > /dev/null 2>&1; then
        warn "Docker daemon not accessible (permission denied or not running)"
        warn "SKIP: Docker Compose test"
        {
            echo ""
            echo "### compose"
            echo ""
            echo "**SKIPPED** — Docker daemon not accessible"
        } >> "$RESULTS_FILE"
        return 0
    fi

    # Clean checkout
    mkdir -p "$dir"
    rm -rf "$dir"/*
    git archive HEAD | tar -x -C "$dir"

    # Create .env with custom ports to avoid conflicts
    cat > "$dir/.env" <<ENVEOF
GLITCH_ADMIN_PASSWORD=$pass
GLITCH_PORT=9300
GLITCH_DASH_PORT=9301
GLITCH_DB_PORT=9302
ENVEOF

    cd "$dir"

    # Create empty config.json if it doesn't exist (required by volume mount)
    touch "$dir/config.json"
    mkdir -p "$dir/captures"

    # Build and start
    docker compose up -d --build 2>&1 || {
        fail "docker compose up failed"
        docker compose logs 2>&1 || true
        cd "$REPO_ROOT"
        return 1
    }

    # Wait for services
    log "Waiting for services to start..."
    if ! wait_for_http "http://localhost:9300/health/live" 60; then
        fail "Server failed to start via Docker Compose"
        docker compose logs 2>&1 | tail -30
        docker compose down -v 2>/dev/null || true
        cd "$REPO_ROOT"
        return 1
    fi
    log "Docker Compose services are up"

    # Run tests
    local failures=0
    run_tests "9300" "9301" "$pass" "compose" || failures=$?

    # Cleanup
    docker compose down -v 2>&1 || true
    log "Docker Compose stopped and cleaned up"
    cd "$REPO_ROOT"

    return $failures
}

# =========================================================================
# Method 4: Standalone Docker
# =========================================================================
test_docker() {
    local dir="$REPO_ROOT/deploy-test-docker"
    local pass="docker-test-pass"
    local container_name="glitch-deploy-test"

    log "=== Testing: Standalone Docker ==="

    # Check Docker daemon access
    if ! docker info > /dev/null 2>&1; then
        warn "Docker daemon not accessible (permission denied or not running)"
        warn "SKIP: Docker test"
        {
            echo ""
            echo "### docker"
            echo ""
            echo "**SKIPPED** — Docker daemon not accessible"
        } >> "$RESULTS_FILE"
        return 0
    fi

    # Clean checkout
    mkdir -p "$dir"
    rm -rf "$dir"/*
    git archive HEAD | tar -x -C "$dir"

    cd "$dir"

    # Build image
    docker build -t glitch-deploy-test:latest . 2>&1 || {
        fail "Docker build failed"
        cd "$REPO_ROOT"
        return 1
    }
    log "Docker image built"

    # Remove old container if exists
    docker rm -f "$container_name" 2>/dev/null || true

    # Run container
    docker run -d \
        --name "$container_name" \
        -p 9400:8765 \
        -p 9401:8766 \
        -e GLITCH_ADMIN_PASSWORD="$pass" \
        glitch-deploy-test:latest 2>&1 || {
        fail "Docker run failed"
        cd "$REPO_ROOT"
        return 1
    }

    # Wait for server
    if ! wait_for_http "http://localhost:9400/health/live" 30; then
        fail "Server failed to start in Docker"
        docker logs "$container_name" 2>&1 | tail -20
        docker rm -f "$container_name" 2>/dev/null || true
        cd "$REPO_ROOT"
        return 1
    fi
    log "Docker container running"

    # Run tests
    local failures=0
    run_tests "9400" "9401" "$pass" "docker" || failures=$?

    # Cleanup
    docker rm -f "$container_name" 2>/dev/null || true
    docker rmi glitch-deploy-test:latest 2>/dev/null || true
    log "Docker container removed"
    cd "$REPO_ROOT"

    return $failures
}

# =========================================================================
# Main
# =========================================================================

# Initialize results file
cat > "$RESULTS_FILE" <<EOF
# Deployment Test Results

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Branch:** $(git rev-parse --abbrev-ref HEAD)
**Commit:** $(git rev-parse --short HEAD)

## Test Matrix

Each deployment method is tested with 15 endpoint/API tests covering:
health, admin auth, config API, metrics, features, vulns, API endpoints,
feature toggle round-trip, config update round-trip, honeypot, robots.txt,
labyrinth, and config export.

Tests 3 (main page) and 14 (labyrinth) use retries because the chaos
server injects random errors on these paths by design.
EOF

METHOD=${1:-all}
total_pass=0
total_fail=0
total_skip=0

run_method() {
    local method=$1
    local start_time end_time duration

    log ""
    start_time=$(date +%s)

    if "test_$method"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        total_pass=$((total_pass + 1))
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        total_fail=$((total_fail + 1))
    fi
}

case "$METHOD" in
    bare) run_method bare ;;
    makefile) run_method makefile ;;
    docker) run_method docker ;;
    compose) run_method compose ;;
    all)
        run_method bare
        run_method makefile
        run_method docker
        run_method compose
        ;;
    *) echo "Usage: $0 [bare|makefile|docker|compose|all]"; exit 1 ;;
esac

{
    echo ""
    echo "## Summary"
    echo ""
    echo "- **Passed:** $total_pass"
    echo "- **Failed:** $total_fail"
    echo ""
    echo "## Notes"
    echo ""
    echo "- Docker and Docker Compose tests require Docker daemon access"
    echo "- Main page and labyrinth tests use retry logic due to intentional chaos error injection"
    echo "- All tests use env-only configuration (GLITCH_ADMIN_PASSWORD via .env file)"
} >> "$RESULTS_FILE"

log ""
log "=== DEPLOYMENT TEST COMPLETE ==="
log "Results: $total_pass passed, $total_fail failed"
log "Full report: $RESULTS_FILE"

exit $total_fail
