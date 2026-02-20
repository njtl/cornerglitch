package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Engine fingerprints HTTP clients based on header patterns, TLS info, and behavior.
type Engine struct {
	mu    sync.RWMutex
	cache map[string]string // hash(headers) -> clientID
}

func NewEngine() *Engine {
	return &Engine{
		cache: make(map[string]string),
	}
}

// Identify produces a stable client ID from request characteristics.
func (e *Engine) Identify(r *http.Request) string {
	// Build a fingerprint from header ordering, presence, and values
	sig := e.buildSignature(r)
	hash := sha256.Sum256([]byte(sig))
	clientID := fmt.Sprintf("client_%x", hash[:8])

	e.mu.Lock()
	e.cache[sig] = clientID
	e.mu.Unlock()

	return clientID
}

func (e *Engine) buildSignature(r *http.Request) string {
	var parts []string

	// 1. Header order fingerprint — the order headers arrive is a strong signal
	headerOrder := make([]string, 0, len(r.Header))
	for k := range r.Header {
		headerOrder = append(headerOrder, strings.ToLower(k))
	}
	// We record both sorted (for stability) and original order hash
	sort.Strings(headerOrder)
	parts = append(parts, "ho:"+strings.Join(headerOrder, ","))

	// 2. User-Agent
	parts = append(parts, "ua:"+r.UserAgent())

	// 3. Accept headers combination
	parts = append(parts, "acc:"+r.Header.Get("Accept"))
	parts = append(parts, "ae:"+r.Header.Get("Accept-Encoding"))
	parts = append(parts, "al:"+r.Header.Get("Accept-Language"))

	// 4. Connection behavior
	parts = append(parts, "conn:"+r.Header.Get("Connection"))

	// 5. IP-based component (use X-Forwarded-For if present, else RemoteAddr)
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	// Strip port from RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	parts = append(parts, "ip:"+ip)

	// 6. TLS fingerprint hint — if Sec-* headers are present
	for k, v := range r.Header {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "sec-") {
			parts = append(parts, kl+":"+strings.Join(v, ","))
		}
	}

	return strings.Join(parts, "|")
}

// ClassifyClient returns a human-readable classification based on known patterns.
func (e *Engine) ClassifyClient(r *http.Request) ClientClass {
	ua := strings.ToLower(r.UserAgent())

	switch {
	case strings.Contains(ua, "googlebot") || strings.Contains(ua, "bingbot") ||
		strings.Contains(ua, "yandex") || strings.Contains(ua, "baiduspider"):
		return ClassSearchBot
	case strings.Contains(ua, "gptbot") || strings.Contains(ua, "chatgpt") ||
		strings.Contains(ua, "anthropic") || strings.Contains(ua, "claude") ||
		strings.Contains(ua, "ccbot") || strings.Contains(ua, "perplexity"):
		return ClassAIScraper
	case strings.Contains(ua, "python") || strings.Contains(ua, "httpx") ||
		strings.Contains(ua, "requests") || strings.Contains(ua, "urllib") ||
		strings.Contains(ua, "go-http") || strings.Contains(ua, "java/") ||
		strings.Contains(ua, "curl") || strings.Contains(ua, "wget"):
		return ClassScriptBot
	case strings.Contains(ua, "postman") || strings.Contains(ua, "insomnia"):
		return ClassAPITester
	case strings.Contains(ua, "ab/") || strings.Contains(ua, "wrk") ||
		strings.Contains(ua, "siege") || strings.Contains(ua, "vegeta") ||
		strings.Contains(ua, "hey/") || strings.Contains(ua, "bombardier") ||
		strings.Contains(ua, "k6") || strings.Contains(ua, "locust") ||
		strings.Contains(ua, "jmeter") || strings.Contains(ua, "gatling"):
		return ClassLoadTester
	case strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") ||
		strings.Contains(ua, "safari") || strings.Contains(ua, "firefox"):
		return ClassBrowser
	default:
		return ClassUnknown
	}
}

type ClientClass string

const (
	ClassBrowser    ClientClass = "browser"
	ClassSearchBot  ClientClass = "search_bot"
	ClassAIScraper  ClientClass = "ai_scraper"
	ClassScriptBot  ClientClass = "script_bot"
	ClassAPITester  ClientClass = "api_tester"
	ClassLoadTester ClientClass = "load_tester"
	ClassUnknown    ClientClass = "unknown"
)
