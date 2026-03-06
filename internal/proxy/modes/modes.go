package modes

import (
	"fmt"
	"net/http"
	"time"

	"github.com/glitchWebServer/internal/proxy"
	"github.com/glitchWebServer/internal/proxy/chaos"
	"github.com/glitchWebServer/internal/proxy/waf"
)

// ChaosConfig holds tuning parameters for chaos injection modules.
type ChaosConfig struct {
	LatencyMin  time.Duration
	LatencyMax  time.Duration
	LatencyProb float64
	CorruptProb float64
	DropProb    float64
	ResetProb   float64
}

// WAFConfig holds tuning parameters for WAF modules.
type WAFConfig struct {
	Enabled      bool
	BlockAction  string
	RateLimitRPS int
}

// Mode describes a named proxy configuration preset that configures the
// interception pipeline, chaos injection, and WAF modules.
type Mode struct {
	Name        string
	Description string
	Configure   func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig)
}

// registry holds all defined modes.
var registry = map[string]*Mode{
	"transparent": {
		Name:        "transparent",
		Description: "No chaos, no WAF — pure pass-through proxy",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// No interceptors, no chaos, no WAF
			*chaosCfg = ChaosConfig{}
			*wafCfg = WAFConfig{}
		},
	},

	"waf": {
		Name:        "waf",
		Description: "WAF signatures and rate limiting, no chaos injection",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// No chaos
			*chaosCfg = ChaosConfig{}

			// Enable WAF with blocking and moderate rate limits
			*wafCfg = WAFConfig{
				Enabled:      true,
				BlockAction:  "block",
				RateLimitRPS: 100,
			}

			// Add WAF interceptor to the pipeline
			detector := waf.NewSignatureDetector()
			detector.BlockAction = "block"
			pipeline.Add(&wafInterceptor{detector: detector})
		},
	},

	"chaos": {
		Name:        "chaos",
		Description: "Chaos injection at moderate levels, no WAF",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// No WAF
			*wafCfg = WAFConfig{}

			// Moderate chaos
			*chaosCfg = ChaosConfig{
				LatencyMin:  50 * time.Millisecond,
				LatencyMax:  500 * time.Millisecond,
				LatencyProb: 0.3,
				CorruptProb: 0.1,
				DropProb:    0.05,
				ResetProb:   0.02,
			}

			// Add latency injector
			pipeline.Add(chaos.NewLatencyInjector(
				chaosCfg.LatencyMin,
				chaosCfg.LatencyMax,
				chaosCfg.LatencyProb,
			))

			// Add response corruption
			pipeline.Add(chaos.NewResponseCorruptor(
				chaosCfg.CorruptProb,
				0.01,  // flip 1% of bytes
				0.3,   // 30% chance of truncation (when corrupting)
				0.2,   // 20% chance of wrong Content-Type (when corrupting)
			))

			// Add client killer at moderate probability
			pipeline.Add(chaos.NewClientKiller(0.1))
		},
	},

	"gateway": {
		Name:        "gateway",
		Description: "Rate limiting and basic header manipulation, light chaos",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// Light chaos — only latency
			*chaosCfg = ChaosConfig{
				LatencyMin:  10 * time.Millisecond,
				LatencyMax:  100 * time.Millisecond,
				LatencyProb: 0.1,
			}

			// Rate limiting only
			*wafCfg = WAFConfig{
				Enabled:      true,
				BlockAction:  "log",
				RateLimitRPS: 50,
			}

			// Add latency injector
			pipeline.Add(chaos.NewLatencyInjector(
				chaosCfg.LatencyMin,
				chaosCfg.LatencyMax,
				chaosCfg.LatencyProb,
			))

			// Add header manipulation interceptor
			pipeline.Add(&headerInterceptor{})
		},
	},

	"nightmare": {
		Name:        "nightmare",
		Description: "Everything at maximum — WAF + extreme chaos injection",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// Extreme chaos
			*chaosCfg = ChaosConfig{
				LatencyMin:  200 * time.Millisecond,
				LatencyMax:  5 * time.Second,
				LatencyProb: 0.6,
				CorruptProb: 0.3,
				DropProb:    0.15,
				ResetProb:   0.1,
			}

			// Aggressive WAF
			*wafCfg = WAFConfig{
				Enabled:      true,
				BlockAction:  "block",
				RateLimitRPS: 20,
			}

			// WAF interceptor
			detector := waf.NewSignatureDetector()
			detector.BlockAction = "block"
			pipeline.Add(&wafInterceptor{detector: detector})

			// Heavy latency injection
			pipeline.Add(chaos.NewLatencyInjector(
				chaosCfg.LatencyMin,
				chaosCfg.LatencyMax,
				chaosCfg.LatencyProb,
			))

			// Aggressive response corruption
			pipeline.Add(chaos.NewResponseCorruptor(
				chaosCfg.CorruptProb,
				0.05,  // flip 5% of bytes
				0.4,   // 40% chance of truncation (when corrupting)
				0.3,   // 30% chance of wrong Content-Type (when corrupting)
			))

			// Client killer at high probability
			pipeline.Add(chaos.NewClientKiller(0.4))

			// Header chaos
			pipeline.Add(&headerInterceptor{})
		},
	},

	"killer": {
		Name:        "killer",
		Description: "Maximum client destruction — every response is weaponized",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// No WAF — let everything through so we can destroy the client
			*wafCfg = WAFConfig{}

			// Extreme chaos
			*chaosCfg = ChaosConfig{
				LatencyMin:  100 * time.Millisecond,
				LatencyMax:  3 * time.Second,
				LatencyProb: 0.4,
				CorruptProb: 0.5,
				DropProb:    0.1,
				ResetProb:   0.1,
			}

			// Client killer on every response
			pipeline.Add(chaos.NewClientKiller(1.0))

			// Layer on corruption for responses that survive the killer
			pipeline.Add(chaos.NewResponseCorruptor(
				0.5,
				0.1,  // flip 10% of bytes
				0.5,  // 50% truncation
				0.3,  // 30% wrong content-type
			))

			// Latency to slow client down
			pipeline.Add(chaos.NewLatencyInjector(
				chaosCfg.LatencyMin,
				chaosCfg.LatencyMax,
				chaosCfg.LatencyProb,
			))
		},
	},

	"mirror": {
		Name:        "mirror",
		Description: "Mirror server mode — copies the server's behavior settings to the proxy",
		Configure: func(pipeline *proxy.Pipeline, chaosCfg *ChaosConfig, wafCfg *WAFConfig) {
			// No WAF in mirror mode; the proxy mirrors server error/page behavior
			// which is handled by ReverseProxy.applyGlitchTreatment via MirrorSettings
			*chaosCfg = ChaosConfig{}
			*wafCfg = WAFConfig{}
		},
	},
}

// Get returns a mode by name, or an error if the mode doesn't exist.
func Get(name string) (*Mode, error) {
	m, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown mode %q; available modes: %v", name, List())
	}
	return m, nil
}

// List returns the names of all available modes.
func List() []string {
	return []string{"transparent", "waf", "chaos", "gateway", "nightmare", "killer", "mirror"}
}

// wafInterceptor adapts the WAF SignatureDetector into a proxy.Interceptor.
type wafInterceptor struct {
	detector *waf.SignatureDetector
}

func (w *wafInterceptor) Name() string {
	return "waf/signatures"
}

func (w *wafInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	detections := w.detector.Check(req)
	if w.detector.ShouldBlock(detections) {
		// Return an error to signal blocking
		ids := ""
		for i, d := range detections {
			if i > 0 {
				ids += ", "
			}
			ids += d.SignatureID
		}
		return nil, fmt.Errorf("WAF blocked: matched signatures [%s]", ids)
	}
	return req, nil
}

func (w *wafInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	return resp, nil
}

// headerInterceptor adds proxy-related headers and optionally manipulates
// existing headers for gateway and nightmare modes.
type headerInterceptor struct{}

func (h *headerInterceptor) Name() string {
	return "modes/headers"
}

func (h *headerInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	// Add standard proxy headers
	req.Header.Set("X-Glitch-Proxy", "true")
	req.Header.Set("X-Proxy-Mode", "glitch-enhanced")
	return req, nil
}

func (h *headerInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	// Add diagnostic response headers
	resp.Header.Set("X-Glitch-Proxy", "true")
	resp.Header.Set("X-Served-By", "glitch-proxy")
	return resp, nil
}
