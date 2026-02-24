package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// getFreePort returns a free TCP port on localhost.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// startBackendServer starts a simple HTTP server on a random port that returns
// 200 OK. It returns the port and a cleanup function.
func startBackendServer(t *testing.T) (int, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startBackendServer: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	port := l.Addr().(*net.TCPAddr).Port
	return port, func() { srv.Close() }
}

func TestProxyManager_DefaultState(t *testing.T) {
	pm := NewProxyManager()

	if pm.IsRunning() {
		t.Error("expected proxy manager to not be running by default")
	}

	status := pm.Status()
	if status["running"].(bool) {
		t.Error("expected status running to be false")
	}
	if status["port"].(int) != 0 {
		t.Errorf("expected default port 0, got %d", status["port"].(int))
	}
	if status["target"].(string) != "" {
		t.Errorf("expected empty target, got %q", status["target"].(string))
	}
	if status["requests"].(int64) != 0 {
		t.Errorf("expected 0 requests, got %d", status["requests"].(int64))
	}
}

func TestProxyManager_StartStop(t *testing.T) {
	backendPort, cleanup := startBackendServer(t)
	defer cleanup()

	pm := NewProxyManager()
	port := getFreePort(t)
	target := "http://127.0.0.1:" + strconv.Itoa(backendPort)

	err := pm.Start(port, target)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !pm.IsRunning() {
		t.Error("expected proxy to be running after Start")
	}

	status := pm.Status()
	if !status["running"].(bool) {
		t.Error("expected status running to be true")
	}
	if status["port"].(int) != port {
		t.Errorf("expected port %d, got %d", port, status["port"].(int))
	}
	if status["target"].(string) != target {
		t.Errorf("expected target %q, got %q", target, status["target"].(string))
	}

	// Verify the proxy is actually listening by making a request to it
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	resp.Body.Close()

	// Verify request count incremented
	reqCount := pm.Status()["requests"].(int64)
	if reqCount < 1 {
		t.Errorf("expected at least 1 request, got %d", reqCount)
	}

	// Stop
	err = pm.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if pm.IsRunning() {
		t.Error("expected proxy to not be running after Stop")
	}
}

func TestProxyManager_Restart(t *testing.T) {
	backendPort, cleanup := startBackendServer(t)
	defer cleanup()

	pm := NewProxyManager()
	port := getFreePort(t)
	target := "http://127.0.0.1:" + strconv.Itoa(backendPort)

	err := pm.Start(port, target)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer pm.Stop()

	if !pm.IsRunning() {
		t.Error("expected proxy to be running after Start")
	}

	err = pm.Restart()
	if err != nil {
		t.Fatalf("Restart failed: %v", err)
	}

	if !pm.IsRunning() {
		t.Error("expected proxy to be running after Restart")
	}

	// Verify port and target are preserved
	status := pm.Status()
	if status["port"].(int) != port {
		t.Errorf("expected port %d after restart, got %d", port, status["port"].(int))
	}
	if status["target"].(string) != target {
		t.Errorf("expected target %q after restart, got %q", target, status["target"].(string))
	}
}

func TestProxyManager_DoubleStart(t *testing.T) {
	backendPort, cleanup := startBackendServer(t)
	defer cleanup()

	pm := NewProxyManager()
	port := getFreePort(t)
	target := "http://127.0.0.1:" + strconv.Itoa(backendPort)

	err := pm.Start(port, target)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer pm.Stop()

	// Second start should return an error
	err = pm.Start(port, target)
	if err == nil {
		t.Error("expected error on double start, got nil")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected 'already running' error, got: %v", err)
	}
}

func TestProxyManager_StopWhenNotRunning(t *testing.T) {
	pm := NewProxyManager()

	// Stop when not running should not return an error
	err := pm.Stop()
	if err != nil {
		t.Errorf("expected no error when stopping a non-running proxy, got: %v", err)
	}
}

func TestProxyManager_Status(t *testing.T) {
	backendPort, cleanup := startBackendServer(t)
	defer cleanup()

	pm := NewProxyManager()
	port := getFreePort(t)
	target := "http://127.0.0.1:" + strconv.Itoa(backendPort)

	// Status when not running
	status := pm.Status()
	requiredKeys := []string{"running", "port", "target", "requests", "uptime_seconds", "mode"}
	for _, key := range requiredKeys {
		if _, ok := status[key]; !ok {
			t.Errorf("status map missing key %q", key)
		}
	}

	// Status when running
	err := pm.Start(port, target)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer pm.Stop()

	time.Sleep(100 * time.Millisecond)

	status = pm.Status()
	for _, key := range requiredKeys {
		if _, ok := status[key]; !ok {
			t.Errorf("status map missing key %q when running", key)
		}
	}

	if !status["running"].(bool) {
		t.Error("expected running to be true")
	}
	if status["uptime_seconds"].(int) < 0 {
		t.Errorf("expected non-negative uptime, got %d", status["uptime_seconds"].(int))
	}
	if status["mode"].(string) == "" {
		t.Error("expected non-empty mode when running")
	}
}

func TestAPI_ProxyRuntime_Get(t *testing.T) {
	// Reset the global proxy manager for a clean test
	originalPM := globalProxyManager
	globalProxyManager = NewProxyManager()
	defer func() { globalProxyManager = originalPM }()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/proxy/runtime", nil)
	w := httptest.NewRecorder()

	adminAPIProxyRuntime(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var status map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if _, ok := status["running"]; !ok {
		t.Error("response missing 'running' field")
	}
	if _, ok := status["port"]; !ok {
		t.Error("response missing 'port' field")
	}
	if _, ok := status["target"]; !ok {
		t.Error("response missing 'target' field")
	}

	// Should not be running by default
	if status["running"].(bool) {
		t.Error("expected proxy to not be running")
	}
}

func TestAPI_ProxyRuntime_Start(t *testing.T) {
	backendPort, cleanup := startBackendServer(t)
	defer cleanup()

	// Reset the global proxy manager for a clean test
	originalPM := globalProxyManager
	globalProxyManager = NewProxyManager()
	defer func() {
		globalProxyManager.Stop()
		globalProxyManager = originalPM
	}()

	proxyPort := getFreePort(t)
	body := `{"action":"start","port":` + strconv.Itoa(proxyPort) + `,"target":"http://127.0.0.1:` + strconv.Itoa(backendPort) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/proxy/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	adminAPIProxyRuntime(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var status map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if !status["running"].(bool) {
		t.Error("expected proxy to be running after start")
	}

	portFloat, ok := status["port"].(float64)
	if !ok {
		t.Fatalf("expected port to be a number, got %T", status["port"])
	}
	if int(portFloat) != proxyPort {
		t.Errorf("expected port %d, got %d", proxyPort, int(portFloat))
	}
}
