package dashboard

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cornerglitch/internal/proxy"
	"github.com/cornerglitch/internal/proxy/modes"
)

// ProxyManager controls the lifecycle of an embedded reverse proxy instance.
// It allows the admin panel to start, stop, and restart the proxy without
// requiring the standalone glitch-proxy binary.
type ProxyManager struct {
	mu        sync.Mutex
	running   bool
	port      int
	target    string
	proxy     *proxy.ReverseProxy
	server    *http.Server
	startTime time.Time
	reqCount  atomic.Int64
}

// NewProxyManager creates a new ProxyManager in the stopped state.
func NewProxyManager() *ProxyManager {
	return &ProxyManager{}
}

// Start creates a new ReverseProxy and starts an HTTP server on the given port,
// proxying traffic to the specified target. It uses the current globalProxyConfig
// mode to configure the proxy pipeline.
func (pm *ProxyManager) Start(port int, target string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("proxy is already running on port %d", pm.port)
	}

	// Determine the current proxy mode from globalProxyConfig
	modeName := globalProxyConfig.GetMode()

	opts := proxy.Options{
		Target:        target,
		InterceptMode: "glitch",
		EnableLogging: true,
	}

	rp := proxy.NewReverseProxy(target, opts)

	// Configure the pipeline based on the current proxy mode
	pipeline := proxy.NewPipeline()
	chaosCfg := modes.ChaosConfig{}
	wafCfg := modes.WAFConfig{}

	selectedMode, err := modes.Get(modeName)
	if err != nil {
		// Fall back to transparent if the mode is unknown
		selectedMode, _ = modes.Get("transparent")
	}
	selectedMode.Configure(pipeline, &chaosCfg, &wafCfg)
	rp.Pipeline = pipeline

	// If mirror mode, apply the server's mirrored settings to the proxy
	if modeName == "mirror" {
		mc := globalProxyConfig.GetMirror()
		if mc == nil {
			mc = SnapshotMirrorFromServer()
			globalProxyConfig.SetMirror(mc)
		}
		rp.SetMirrorSettings(&proxy.MirrorSettings{
			ErrorWeights:          mc.ErrorWeights,
			ErrorRateMultiplier:   mc.ErrorRateMultiplier,
			PageTypeWeights:       mc.PageTypeWeights,
			HeaderCorruptLevel:    mc.HeaderCorruptLevel,
			ProtocolGlitchEnabled: mc.ProtocolGlitchEnabled,
			ProtocolGlitchLevel:   mc.ProtocolGlitchLevel,
			DelayMinMs:            mc.DelayMinMs,
			DelayMaxMs:            mc.DelayMaxMs,
			ContentTheme:          mc.ContentTheme,
		})
	}

	// Wrap the proxy handler to count requests
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pm.reqCount.Add(1)
		rp.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start listening in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			log.Printf("[proxy-manager] listen error on port %d: %v", port, err)
		}
	}()

	// Give the server a moment to fail on bind errors
	select {
	case err := <-errCh:
		rp.Shutdown()
		return fmt.Errorf("failed to start proxy on port %d: %w", port, err)
	case <-time.After(50 * time.Millisecond):
		// No immediate error, assume successful bind
	}

	pm.running = true
	pm.port = port
	pm.target = target
	pm.proxy = rp
	pm.server = srv
	pm.startTime = time.Now()
	pm.reqCount.Store(0)

	log.Printf("[proxy-manager] Started proxy on :%d -> %s (mode: %s)", port, target, modeName)
	return nil
}

// Stop gracefully shuts down the proxy server with a 5-second timeout.
func (pm *ProxyManager) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var shutdownErr error
	if pm.server != nil {
		shutdownErr = pm.server.Shutdown(ctx)
	}
	if pm.proxy != nil {
		pm.proxy.Shutdown()
	}

	log.Printf("[proxy-manager] Stopped proxy on :%d (served %d requests)", pm.port, pm.reqCount.Load())

	pm.running = false
	pm.server = nil
	pm.proxy = nil

	return shutdownErr
}

// Restart stops the proxy (if running) and starts it again with the same
// port and target configuration.
func (pm *ProxyManager) Restart() error {
	pm.mu.Lock()
	port := pm.port
	target := pm.target
	pm.mu.Unlock()

	if port == 0 || target == "" {
		return fmt.Errorf("cannot restart: proxy has never been started")
	}

	if err := pm.Stop(); err != nil {
		return fmt.Errorf("restart stop failed: %w", err)
	}

	// Small delay to allow the port to be released
	time.Sleep(50 * time.Millisecond)

	return pm.Start(port, target)
}

// IsRunning returns whether the proxy is currently running.
func (pm *ProxyManager) IsRunning() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.running
}

// Status returns a map describing the current state of the proxy manager,
// including port, target, running state, uptime, and request count.
func (pm *ProxyManager) Status() map[string]interface{} {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	status := map[string]interface{}{
		"running":  pm.running,
		"port":     pm.port,
		"target":   pm.target,
		"requests": pm.reqCount.Load(),
	}

	if pm.running {
		status["uptime_seconds"] = int(time.Since(pm.startTime).Seconds())
		status["mode"] = globalProxyConfig.GetMode()
	} else {
		status["uptime_seconds"] = 0
		status["mode"] = ""
	}

	return status
}

// ResetStats zeroes the proxy request counter.
func (pm *ProxyManager) ResetStats() {
	pm.reqCount.Store(0)
}

// IncrementRequests increments the proxy request counter. This can be called
// externally if additional request tracking is needed.
func (pm *ProxyManager) IncrementRequests() {
	pm.reqCount.Add(1)
}
