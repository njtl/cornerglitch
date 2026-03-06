package modes

import (
	"testing"
	"time"

	"github.com/glitchWebServer/internal/proxy"
)

func TestList(t *testing.T) {
	names := List()
	expected := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "killer", "mirror"}

	if len(names) != len(expected) {
		t.Fatalf("List() returned %d modes, want %d", len(names), len(expected))
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("List()[%d] = %q, want %q", i, names[i], name)
		}
	}
}

func TestGetAllModes(t *testing.T) {
	for _, name := range List() {
		m, err := Get(name)
		if err != nil {
			t.Errorf("Get(%q) returned error: %v", name, err)
			continue
		}
		if m == nil {
			t.Errorf("Get(%q) returned nil mode", name)
			continue
		}
		if m.Name != name {
			t.Errorf("Get(%q).Name = %q, want %q", name, m.Name, name)
		}
		if m.Description == "" {
			t.Errorf("Get(%q).Description is empty", name)
		}
		if m.Configure == nil {
			t.Errorf("Get(%q).Configure is nil", name)
		}
	}
}

func TestGetUnknownMode(t *testing.T) {
	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("Get(\"nonexistent\") should return an error")
	}
}

func TestTransparentMode(t *testing.T) {
	m, err := Get("transparent")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Transparent: no chaos, no WAF
	if chaosCfg.LatencyProb != 0 || chaosCfg.CorruptProb != 0 || chaosCfg.DropProb != 0 || chaosCfg.ResetProb != 0 {
		t.Error("transparent mode should have zero chaos probabilities")
	}
	if wafCfg.Enabled {
		t.Error("transparent mode should have WAF disabled")
	}
}

func TestWAFMode(t *testing.T) {
	m, err := Get("waf")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// WAF: no chaos, WAF enabled with blocking
	if chaosCfg.LatencyProb != 0 || chaosCfg.CorruptProb != 0 {
		t.Error("waf mode should have zero chaos probabilities")
	}
	if !wafCfg.Enabled {
		t.Error("waf mode should have WAF enabled")
	}
	if wafCfg.BlockAction != "block" {
		t.Errorf("waf mode BlockAction = %q, want %q", wafCfg.BlockAction, "block")
	}
	if wafCfg.RateLimitRPS != 100 {
		t.Errorf("waf mode RateLimitRPS = %d, want 100", wafCfg.RateLimitRPS)
	}
}

func TestChaosMode(t *testing.T) {
	m, err := Get("chaos")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Chaos: moderate chaos, no WAF
	if wafCfg.Enabled {
		t.Error("chaos mode should have WAF disabled")
	}
	if chaosCfg.LatencyProb == 0 {
		t.Error("chaos mode should have non-zero latency probability")
	}
	if chaosCfg.CorruptProb == 0 {
		t.Error("chaos mode should have non-zero corrupt probability")
	}
	if chaosCfg.LatencyMin >= chaosCfg.LatencyMax {
		t.Error("chaos mode LatencyMin should be less than LatencyMax")
	}
}

func TestGatewayMode(t *testing.T) {
	m, err := Get("gateway")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Gateway: light chaos (latency only), rate limiting
	if chaosCfg.LatencyProb == 0 {
		t.Error("gateway mode should have non-zero latency probability")
	}
	if chaosCfg.CorruptProb != 0 {
		t.Error("gateway mode should have zero corrupt probability")
	}
	if !wafCfg.Enabled {
		t.Error("gateway mode should have WAF enabled")
	}
	if wafCfg.BlockAction != "log" {
		t.Errorf("gateway mode BlockAction = %q, want %q", wafCfg.BlockAction, "log")
	}
}

func TestNightmareMode(t *testing.T) {
	m, err := Get("nightmare")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Nightmare: extreme chaos + aggressive WAF
	if !wafCfg.Enabled {
		t.Error("nightmare mode should have WAF enabled")
	}
	if wafCfg.BlockAction != "block" {
		t.Errorf("nightmare mode BlockAction = %q, want %q", wafCfg.BlockAction, "block")
	}

	// Nightmare should have higher chaos than chaos mode
	chaosMode, _ := Get("chaos")
	var chaosCfgRef ChaosConfig
	var wafCfgRef WAFConfig
	chaosMode.Configure(proxy.NewPipeline(), &chaosCfgRef, &wafCfgRef)

	if chaosCfg.LatencyProb <= chaosCfgRef.LatencyProb {
		t.Error("nightmare LatencyProb should exceed chaos mode")
	}
	if chaosCfg.CorruptProb <= chaosCfgRef.CorruptProb {
		t.Error("nightmare CorruptProb should exceed chaos mode")
	}
	if chaosCfg.LatencyMax <= chaosCfgRef.LatencyMax {
		t.Error("nightmare LatencyMax should exceed chaos mode")
	}
}

func TestKillerMode(t *testing.T) {
	m, err := Get("killer")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Killer: no WAF, extreme corruption
	if wafCfg.Enabled {
		t.Error("killer mode should have WAF disabled (let everything through)")
	}
	if chaosCfg.CorruptProb < 0.5 {
		t.Errorf("killer mode CorruptProb = %f, want >= 0.5", chaosCfg.CorruptProb)
	}
}

func TestMirrorMode(t *testing.T) {
	m, err := Get("mirror")
	if err != nil {
		t.Fatal(err)
	}

	pipeline := proxy.NewPipeline()
	var chaosCfg ChaosConfig
	var wafCfg WAFConfig
	m.Configure(pipeline, &chaosCfg, &wafCfg)

	// Mirror: no chaos, no WAF (mirrors server behavior instead)
	if chaosCfg.LatencyProb != 0 || chaosCfg.CorruptProb != 0 || chaosCfg.DropProb != 0 {
		t.Error("mirror mode should have zero chaos probabilities")
	}
	if wafCfg.Enabled {
		t.Error("mirror mode should have WAF disabled")
	}
}

func TestModeNamesMatchRegistryKeys(t *testing.T) {
	for _, name := range List() {
		m, err := Get(name)
		if err != nil {
			t.Errorf("Get(%q) error: %v", name, err)
			continue
		}
		if m.Name != name {
			t.Errorf("registry key %q has mode.Name = %q", name, m.Name)
		}
	}
}

func TestChaosConfigLatencyRanges(t *testing.T) {
	modesWithLatency := []string{"chaos", "gateway", "nightmare", "killer"}
	for _, name := range modesWithLatency {
		m, _ := Get(name)
		pipeline := proxy.NewPipeline()
		var chaosCfg ChaosConfig
		var wafCfg WAFConfig
		m.Configure(pipeline, &chaosCfg, &wafCfg)

		if chaosCfg.LatencyMin < 0 {
			t.Errorf("%s: LatencyMin is negative", name)
		}
		if chaosCfg.LatencyMax < chaosCfg.LatencyMin {
			t.Errorf("%s: LatencyMax (%v) < LatencyMin (%v)", name, chaosCfg.LatencyMax, chaosCfg.LatencyMin)
		}
		if chaosCfg.LatencyProb < 0 || chaosCfg.LatencyProb > 1 {
			t.Errorf("%s: LatencyProb = %f, should be in [0, 1]", name, chaosCfg.LatencyProb)
		}
	}
}

func TestChaosProbabilitiesInRange(t *testing.T) {
	for _, name := range List() {
		m, _ := Get(name)
		pipeline := proxy.NewPipeline()
		var chaosCfg ChaosConfig
		var wafCfg WAFConfig
		m.Configure(pipeline, &chaosCfg, &wafCfg)

		probs := map[string]float64{
			"LatencyProb": chaosCfg.LatencyProb,
			"CorruptProb": chaosCfg.CorruptProb,
			"DropProb":    chaosCfg.DropProb,
			"ResetProb":   chaosCfg.ResetProb,
		}
		for pName, pVal := range probs {
			if pVal < 0 || pVal > 1 {
				t.Errorf("%s.%s = %f, should be in [0, 1]", name, pName, pVal)
			}
		}
	}
}

func TestNightmareHasHigherLatencyMax(t *testing.T) {
	nm, _ := Get("nightmare")
	pipeline := proxy.NewPipeline()
	var nmCfg ChaosConfig
	var nmWaf WAFConfig
	nm.Configure(pipeline, &nmCfg, &nmWaf)

	if nmCfg.LatencyMax < 5*time.Second {
		t.Errorf("nightmare LatencyMax = %v, expected >= 5s", nmCfg.LatencyMax)
	}
}

func TestNightmareHasLowerRateLimit(t *testing.T) {
	nm, _ := Get("nightmare")
	pipeline := proxy.NewPipeline()
	var nmCfg ChaosConfig
	var nmWaf WAFConfig
	nm.Configure(pipeline, &nmCfg, &nmWaf)

	wafMode, _ := Get("waf")
	var wafChaos ChaosConfig
	var wafWafCfg WAFConfig
	wafMode.Configure(proxy.NewPipeline(), &wafChaos, &wafWafCfg)

	if nmWaf.RateLimitRPS >= wafWafCfg.RateLimitRPS {
		t.Errorf("nightmare RateLimitRPS (%d) should be lower than waf (%d)", nmWaf.RateLimitRPS, wafWafCfg.RateLimitRPS)
	}
}
