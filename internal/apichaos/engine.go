package apichaos

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChaosCategory identifies a chaos behavior category.
type ChaosCategory string

const (
	MalformedJSON ChaosCategory = "malformed_json"
	WrongFormat   ChaosCategory = "wrong_format"
	WrongStatus   ChaosCategory = "wrong_status"
	WrongHeaders  ChaosCategory = "wrong_headers"
	RedirectChaos ChaosCategory = "redirect_chaos"
	ErrorFormats  ChaosCategory = "error_formats"
	SlowPartial   ChaosCategory = "slow_partial"
	DataEdgeCases ChaosCategory = "data_edge_cases"
	EncodingChaos ChaosCategory = "encoding_chaos"
	AuthChaos     ChaosCategory = "auth_chaos"
)

// allCategories defines canonical ordering for consistent selection.
var allCategories = []ChaosCategory{
	MalformedJSON, WrongFormat, WrongStatus, WrongHeaders,
	RedirectChaos, ErrorFormats, SlowPartial, DataEdgeCases,
	EncodingChaos, AuthChaos,
}

// Engine applies API-level chaos to HTTP responses.
// It is safe for concurrent use from multiple goroutines.
type Engine struct {
	mu          sync.RWMutex
	probability float64
	categories  map[ChaosCategory]bool
}

// New creates an Engine with all categories enabled and 20% default probability.
func New() *Engine {
	cats := make(map[ChaosCategory]bool, len(allCategories))
	for _, c := range allCategories {
		cats[c] = true
	}
	return &Engine{
		probability: 0.2,
		categories:  cats,
	}
}

// SetProbability sets the probability (0.0–1.0) that chaos is applied on each request.
// Values outside [0,1] are clamped.
func (e *Engine) SetProbability(p float64) {
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	e.mu.Lock()
	e.probability = p
	e.mu.Unlock()
}

// GetProbability returns the current chaos probability.
func (e *Engine) GetProbability() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.probability
}

// SetCategoryEnabled enables or disables a specific chaos category.
func (e *Engine) SetCategoryEnabled(cat ChaosCategory, enabled bool) {
	e.mu.Lock()
	e.categories[cat] = enabled
	e.mu.Unlock()
}

// IsCategoryEnabled reports whether a category is currently enabled.
func (e *Engine) IsCategoryEnabled(cat ChaosCategory) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.categories[cat]
}

// Categories returns a snapshot copy of the category enable/disable map.
func (e *Engine) Categories() map[ChaosCategory]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[ChaosCategory]bool, len(e.categories))
	for k, v := range e.categories {
		out[k] = v
	}
	return out
}

// ShouldApply returns true if chaos should be applied this request.
func (e *Engine) ShouldApply() bool {
	e.mu.RLock()
	p := e.probability
	e.mu.RUnlock()
	return rand.Float64() < p
}

// Apply writes a chaotic API response to w, picking from all enabled categories.
func (e *Engine) Apply(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	var enabled []ChaosCategory
	for _, c := range allCategories {
		if e.categories[c] {
			enabled = append(enabled, c)
		}
	}
	e.mu.RUnlock()

	if len(enabled) == 0 {
		http.Error(w, `{"error":"internal","message":"chaos engine has no enabled categories"}`, http.StatusInternalServerError)
		return
	}

	cat := enabled[rand.Intn(len(enabled))]
	switch cat {
	case MalformedJSON:
		e.applyMalformedJSON(w, r)
	case WrongFormat:
		e.applyWrongFormat(w, r)
	case WrongStatus:
		e.applyWrongStatus(w, r)
	case WrongHeaders:
		e.applyWrongHeaders(w, r)
	case RedirectChaos:
		e.applyRedirectChaos(w, r)
	case ErrorFormats:
		e.applyErrorFormats(w, r)
	case SlowPartial:
		e.applySlowPartial(w, r)
	case DataEdgeCases:
		e.applyDataEdgeCases(w, r)
	case EncodingChaos:
		e.applyEncodingChaos(w, r)
	case AuthChaos:
		e.applyAuthChaos(w, r)
	}
}

// Snapshot returns a serializable config snapshot for export/import.
func (e *Engine) Snapshot() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cats := make(map[string]bool, len(e.categories))
	for k, v := range e.categories {
		cats[string(k)] = v
	}
	return map[string]interface{}{
		"probability": e.probability,
		"categories":  cats,
	}
}

// Restore loads config from a snapshot produced by Snapshot().
// Unknown keys are ignored. Partial snapshots are applied incrementally.
func (e *Engine) Restore(cfg map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := cfg["probability"].(float64); ok {
		if p < 0 {
			p = 0
		}
		if p > 1 {
			p = 1
		}
		e.probability = p
	}
	if raw, ok := cfg["categories"]; ok {
		switch cats := raw.(type) {
		case map[string]bool:
			for k, v := range cats {
				e.categories[ChaosCategory(k)] = v
			}
		case map[string]interface{}:
			for k, v := range cats {
				if enabled, ok := v.(bool); ok {
					e.categories[ChaosCategory(k)] = enabled
				}
			}
		}
	}
}

// --- Category implementations ---

// applyMalformedJSON sends syntactically broken JSON with application/json content-type.
// Variants: truncated, trailing comma, single-quoted keys, unquoted keys,
// duplicate keys, NaN value, Infinity value, mismatched brackets.
func (e *Engine) applyMalformedJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	variants := []string{
		// Truncated mid-object
		`{"id": 42, "name": "test-resource", "status": "activ`,
		// Trailing comma in object
		`{"id": 42, "name": "test-resource", "tags": ["a", "b",],}`,
		// Single-quoted keys (JavaScript style, invalid JSON)
		`{'id': 42, 'name': 'test-resource', 'active': true}`,
		// Unquoted keys (JavaScript style, invalid JSON)
		`{id: 42, name: "test-resource", active: true, score: 9.5}`,
		// Duplicate keys
		`{"id": 1, "id": 2, "name": "duplicate-key-test", "name": "also-duplicate"}`,
		// NaN value (valid in JS, invalid in JSON)
		`{"value": NaN, "ratio": 0.5, "valid": true}`,
		// Infinity (valid in JS, invalid in JSON)
		`{"score": Infinity, "floor": -Infinity, "computed": true}`,
		// Mismatched brackets
		`{"data": [1, 2, 3}, "ok": true, "count": 3]`,
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(variants[rand.Intn(len(variants))]))
}

// applyWrongFormat sends a body in a format that does not match the Content-Type header.
// Variants: XML, HTML, plain text, YAML, MessagePack-like binary, CSV — all with JSON content-type.
func (e *Engine) applyWrongFormat(w http.ResponseWriter, r *http.Request) {
	variant := rand.Intn(6)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	switch variant {
	case 0: // XML body
		w.Write([]byte(`<?xml version="1.0"?><response><id>42</id><name>test-resource</name><status>active</status></response>`))
	case 1: // HTML error page
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Internal Server Error</h1><p>Something went wrong processing your request.</p></body></html>`))
	case 2: // Plain text
		w.Write([]byte("Error: resource not found at path " + r.URL.Path + "\nPlease check the documentation."))
	case 3: // YAML
		w.Write([]byte("id: 42\nname: test-resource\nstatus: active\ntags:\n  - alpha\n  - beta\ncreated_at: 2024-01-01T00:00:00Z\n"))
	case 4: // MessagePack-like binary (fixmap with 3 fields)
		w.Write([]byte{0x83, 0xa2, 0x69, 0x64, 0x2a, 0xa4, 0x6e, 0x61, 0x6d, 0x65, 0xa4, 0x74, 0x65, 0x73, 0x74, 0xa6, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0xa6, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65})
	case 5: // CSV
		w.Write([]byte("id,name,status,created_at\n1,resource-a,active,2024-01-01\n2,resource-b,inactive,2024-01-02\n3,resource-c,pending,2024-01-03\n"))
	}
}

// applyWrongStatus sends responses with semantically mismatched or unusual status codes.
// Variants: 200+error body, 500+valid data, 418, 451, 103, 207, 226, 204+body.
func (e *Engine) applyWrongStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	variant := rand.Intn(8)
	switch variant {
	case 0: // 200 OK with error body
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"error":"Internal Server Error","code":500,"message":"Something went wrong","request_id":"req-abc-123"}`))
	case 1: // 500 with fully valid data
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"id":42,"name":"test-resource","status":"active","data":[1,2,3],"created_at":"2024-01-01T00:00:00Z"}`))
	case 2: // 418 I'm a teapot
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte(`{"error":"I'm a teapot","short":true,"stout":true,"message":"This server refuses to brew coffee"}`))
	case 3: // 451 Unavailable For Legal Reasons
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
		w.Write([]byte(`{"error":"Unavailable For Legal Reasons","message":"This resource has been removed following a legal request","blocked_by":"court-order-2024-001"}`))
	case 4: // 103 Early Hints
		w.WriteHeader(103)
		w.Write([]byte(`{"hint":"resource is available","link":"/api/v2/resource","preload":true}`))
	case 5: // 207 Multi-Status
		w.WriteHeader(207)
		w.Write([]byte(`{"responses":[{"status":200,"body":{"id":1,"name":"ok"}},{"status":404,"body":{"error":"Not found"}},{"status":403,"body":{"error":"Forbidden"}}]}`))
	case 6: // 226 IM Used
		w.Header().Set("IM", "feed")
		w.WriteHeader(226)
		w.Write([]byte(`{"delta":{"changed_fields":["name","status"],"version":42},"applied_im":"feed"}`))
	case 7: // 204 No Content with a body (spec violation)
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte(`{"message":"Deleted successfully","id":42}`))
	}
}

// applyWrongHeaders sends responses with header anomalies.
// Variants: content-type mismatch, content-length too short, content-length too long,
// duplicate headers, missing content-type.
func (e *Engine) applyWrongHeaders(w http.ResponseWriter, r *http.Request) {
	variant := rand.Intn(5)
	switch variant {
	case 0: // Content-Type says JSON, body is XML
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><result><status>ok</status><id>42</id></result>`))
	case 1: // Content-Length too short (client will truncate or error)
		body := `{"id":42,"name":"test-resource","status":"active","data":"more content here that gets cut off"}`
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	case 2: // Content-Length too long (client will hang waiting for more bytes)
		body := `{"id":42,"name":"test-resource"}`
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "99999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	case 3: // Duplicate headers with conflicting values
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("X-Request-ID", "req-abc-123")
		w.Header().Add("X-Request-ID", "req-def-456")
		w.Header().Add("X-RateLimit-Limit", "100")
		w.Header().Add("X-RateLimit-Limit", "200")
		w.Header().Add("Cache-Control", "no-cache")
		w.Header().Add("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":42,"status":"ok"}`))
	case 4: // No Content-Type header at all
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":42,"name":"test-resource","no_content_type":true}`))
	}
}

// applyRedirectChaos sends redirect responses with problematic targets.
// Variants: infinite loop (301 to self), redirect chain, protocol redirect,
// 308 with body, relative-path redirect, redirect with no Location.
func (e *Engine) applyRedirectChaos(w http.ResponseWriter, r *http.Request) {
	variant := rand.Intn(6)
	switch variant {
	case 0: // 301 redirect to same URL — infinite loop
		http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
	case 1: // 302 into a multi-hop chain
		hopPath := fmt.Sprintf("/api/redirect-chain/hop-%d", rand.Intn(1000))
		http.Redirect(w, r, hopPath, http.StatusFound)
	case 2: // 307 redirect with explicit http:// target (protocol-level redirect)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		http.Redirect(w, r, scheme+"://"+r.Host+r.URL.Path+"?redirected=protocol", http.StatusTemporaryRedirect)
	case 3: // 308 Permanent Redirect with a body (non-standard: spec says ignore body)
		w.Header().Set("Location", r.URL.Path+"?redirected=permanent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPermanentRedirect)
		w.Write([]byte(`{"message":"Permanently moved","new_location":"` + r.URL.Path + `?redirected=permanent","permanent":true}`))
	case 4: // 301 to relative parent path
		http.Redirect(w, r, "../resource", http.StatusMovedPermanently)
	case 5: // 302 with no Location header (invalid — clients will be confused)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte(`{"redirect":true,"message":"You should be redirected but no Location header was set"}`))
	}
}

// applyErrorFormats emulates vendor-specific error response formats.
// Variants: AWS XML, GCP JSON, Stripe JSON, GitHub JSON, Azure JSON,
// Spring Boot JSON, Django HTML debug page, SOAP Fault XML.
func (e *Engine) applyErrorFormats(w http.ResponseWriter, r *http.Request) {
	variant := rand.Intn(8)
	reqID := fmt.Sprintf("%016X", rand.Int63())
	path := r.URL.Path
	switch variant {
	case 0: // AWS XML error (IAM/S3 style)
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-amzn-RequestId", reqID)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidParameterValue</Code>
    <Message>Value (%s) for parameter Action is invalid. Must be one of: Get, List, Describe.</Message>
  </Error>
  <RequestId>%s</RequestId>
</ErrorResponse>`, path, reqID)))

	case 1: // GCP JSON error (googleapis style)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf(`{
  "error": {
    "code": 400,
    "message": "Invalid request: field 'name' is required at path %s",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.BadRequest",
        "fieldViolations": [
          {"field": "name", "description": "must be non-empty"},
          {"field": "parent", "description": "must be a valid resource path"}
        ]
      }
    ]
  }
}`, path)))

	case 2: // Stripe JSON error
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Request-Id", "req_"+reqID[:12])
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`{
  "error": {
    "type": "card_error",
    "code": "card_declined",
    "decline_code": "insufficient_funds",
    "message": "Your card has insufficient funds.",
    "param": "amount",
    "charge": "ch_` + reqID[:16] + `",
    "doc_url": "https://stripe.com/docs/error-codes/card-declined"
  }
}`))

	case 3: // GitHub JSON error
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", reqID)
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{
  "message": "Validation Failed",
  "errors": [
    {"resource": "Issue", "field": "title", "code": "missing_field"},
    {"resource": "Issue", "field": "body", "code": "too_short", "message": "body is too short (minimum is 10 characters)"}
  ],
  "documentation_url": "https://docs.github.com/rest/reference/issues#create-an-issue"
}`))

	case 4: // Azure JSON error (ARM style)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-ms-request-id", reqID)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf(`{
  "error": {
    "code": "InvalidTemplate",
    "message": "Deployment template validation failed: '%s'.",
    "target": "template",
    "details": [
      {"code": "InvalidParameter", "message": "The parameter 'location' is required but was not provided."}
    ],
    "innererror": {
      "exceptionType": "TemplateValidationException",
      "errorDetail": "Template syntax error near line 42"
    }
  }
}`, path)))

	case 5: // Spring Boot JSON error
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{
  "timestamp": "%s",
  "status": 500,
  "error": "Internal Server Error",
  "exception": "org.springframework.web.HttpMediaTypeNotAcceptableException",
  "message": "Could not find acceptable representation",
  "trace": "org.springframework.web.HttpMediaTypeNotAcceptableException: Could not find acceptable representation\n\tat org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodProcessor.writeWithMessageConverters(AbstractMessageConverterMethodProcessor.java:324)",
  "path": "%s"
}`, time.Now().UTC().Format(time.RFC3339), path)))

	case 6: // Django HTML debug page
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta http-equiv="content-type" content="text/html; charset=utf-8"><title>DoesNotExist at %s</title>
<style>html*{padding:0;margin:0}body{background:#fff;color:#000;font-family:verdana,sans-serif}#summary{background:#fcc;border-bottom:1px solid #f0f}#summary h1{color:#900;margin-left:1em}pre.exception_value{font-size:1.5em;margin-left:1em}table{border:none;border-collapse:collapse;width:100%%}th,td{vertical-align:top;padding:2px 3px}th{width:12em;text-align:right;color:#666;padding-right:.5em}#info{background:#f6f6f6}
</style></head><body>
<div id="summary"><h1>DoesNotExist at %s</h1>
<pre class="exception_value">Resource matching query does not exist.</pre>
<table class="meta"><tr><th>Request Method:</th><td>%s</td></tr>
<tr><th>Request URL:</th><td>http://%s%s</td></tr>
<tr><th>Django Version:</th><td>4.2.7</td></tr>
<tr><th>Exception Type:</th><td>DoesNotExist</td></tr>
<tr><th>Exception Value:</th><td><pre>Resource matching query does not exist.</pre></td></tr>
<tr><th>Python Executable:</th><td>/usr/bin/python3</td></tr>
<tr><th>Python Version:</th><td>3.11.6</td></tr></table></div>
<div id="info"><h2>Request information</h2><h3>GET</h3><p>No GET data</p></div>
</body></html>`, path, path, r.Method, r.Host, path)))

	case 7: // SOAP Fault XML
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring xml:lang="en">Internal Server Error</faultstring>
      <faultactor>http://api.example.com/services/resource</faultactor>
      <detail>
        <errorcode>SVC0001</errorcode>
        <description>Service temporarily unavailable. Please retry later.</description>
        <transactionId>` + reqID + `</transactionId>
        <moreInfo>http://api.example.com/docs/errors#SVC0001</moreInfo>
      </detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`))
	}
}

// applySlowPartial sends slow or incomplete responses.
// Variants: byte-at-a-time drip, headers-first then delayed body,
// partial JSON then connection close, chunked with long inter-chunk pauses.
func (e *Engine) applySlowPartial(w http.ResponseWriter, r *http.Request) {
	variant := rand.Intn(4)
	switch variant {
	case 0: // Slow drip: 1 byte every 100ms
		flusher, hasFlusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		msg := `{"id":42,"name":"slow-resource","status":"loading"}`
		for i := 0; i < len(msg); i++ {
			w.Write([]byte{msg[i]})
			if hasFlusher {
				flusher.Flush()
			}
			time.Sleep(100 * time.Millisecond)
		}

	case 1: // Send headers immediately, then delay body
		flusher, hasFlusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Processing", "true")
		w.WriteHeader(http.StatusOK)
		if hasFlusher {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rand.Intn(4)+3) * time.Second)
		w.Write([]byte(`{"id":42,"status":"completed","processing_ms":` + fmt.Sprintf("%d", rand.Intn(4000)+3000) + `}`))

	case 2: // Partial JSON body then close (via hijack if available)
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n")
				buf.WriteString(`{"id":42,"name":"partial-resource","data":[1,2,3,`)
				buf.Flush()
				time.Sleep(300 * time.Millisecond)
				conn.Close()
				return
			}
		}
		// Fallback without hijack
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":42,"name":"partial-resource","data":[1,2,3,`))

	case 3: // Chunked with long inter-chunk pauses
		flusher, hasFlusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunks := []string{
			`{"id":42,`,
			`"name":"chunked-resource",`,
			`"items":[`,
			`{"id":1,"value":"alpha"},`,
			`{"id":2,"value":"beta"}`,
			`]}`,
		}
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			if hasFlusher {
				flusher.Flush()
			}
			time.Sleep(time.Duration(rand.Intn(1500)+500) * time.Millisecond)
		}
	}
}

// applyDataEdgeCases sends responses with extreme or edge-case data values.
// Variants: deeply nested JSON, huge array, very long string, number precision,
// unicode edge cases, null bytes in strings, empty/null responses.
func (e *Engine) applyDataEdgeCases(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	variant := rand.Intn(7)
	switch variant {
	case 0: // Deeply nested JSON (55 levels)
		var sb strings.Builder
		depth := 55
		for i := 0; i < depth; i++ {
			sb.WriteString(fmt.Sprintf(`{"level":%d,"data":`, i+1))
		}
		sb.WriteString(`{"value":"deepest","leaf":true}`)
		for i := 0; i < depth; i++ {
			sb.WriteByte('}')
		}
		w.Write([]byte(sb.String()))

	case 1: // Huge array with 10k elements
		var sb strings.Builder
		sb.WriteString(`{"count":10000,"data":[`)
		for i := 0; i < 10000; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(fmt.Sprintf(`{"id":%d,"value":"item-%d","active":%v}`, i, i, i%2 == 0))
		}
		sb.WriteString(`]}`)
		w.Write([]byte(sb.String()))

	case 2: // Extremely long string value (100k chars)
		longStr := strings.Repeat("a", 100000)
		w.Write([]byte(`{"id":42,"description":"` + longStr + `","status":"ok"}`))

	case 3: // Number precision edge cases
		w.Write([]byte(`{"max_float64":1.7976931348623157e+308,"min_positive_float64":5e-324,"large_safe_integer":9007199254740993,"neg_large_safe_integer":-9007199254740993,"neg_zero":-0.0,"very_small":1.401298464324817e-45,"scientific":6.022e23}`))

	case 4: // Unicode edge cases: BOM, zero-width space, RTL mark, combining chars
		bom := "\ufeff"   // UTF-8 BOM
		zwsp := "\u200b"  // zero-width space
		rtl := "\u200f"   // right-to-left mark
		zwnj := "\u200c"  // zero-width non-joiner
		w.Write([]byte(bom + `{"id":42,"name":"` + zwsp + `resource` + rtl + `","tag":"` + zwnj + `alpha","status":"active"}`))

	case 5: // Null bytes encoded in JSON string values (\u0000)
		w.Write([]byte(`{"id":42,"data":"value\u0000with\u0000null\u0000bytes","binary":"\u0000\u0001\u0002","count":3}`))

	case 6: // Empty/null/minimal responses
		empties := []string{
			`{}`,
			`[]`,
			`null`,
			`""`,
			`{"data":[],"total":0}`,
			`{"results":{},"count":0,"next":null,"previous":null}`,
		}
		w.Write([]byte(empties[rand.Intn(len(empties))]))
	}
}

// applyEncodingChaos sends responses with encoding anomalies.
// Variants: gzip body without Content-Encoding, double-gzipped, claim gzip but plain text,
// UTF-16LE body with UTF-8 charset header, UTF-8 BOM prefix.
func (e *Engine) applyEncodingChaos(w http.ResponseWriter, r *http.Request) {
	body := `{"id":42,"name":"encoded-resource","status":"active","data":"test payload"}`
	variant := rand.Intn(5)
	switch variant {
	case 0: // Gzip-compressed body but no Content-Encoding header (client won't decompress)
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(body))
		gz.Close()
		w.Header().Set("Content-Type", "application/json")
		// Intentionally NOT setting Content-Encoding: gzip
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())

	case 1: // Double-gzipped: Content-Encoding says gzip once, but body is compressed twice
		var buf1, buf2 bytes.Buffer
		gz1 := gzip.NewWriter(&buf1)
		gz1.Write([]byte(body))
		gz1.Close()
		gz2 := gzip.NewWriter(&buf2)
		gz2.Write(buf1.Bytes())
		gz2.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip") // only declares one layer
		w.WriteHeader(http.StatusOK)
		w.Write(buf2.Bytes())

	case 2: // Claim Content-Encoding: gzip but body is plain uncompressed text
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))

	case 3: // UTF-16LE encoded body with UTF-8 charset declared in Content-Type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		var buf bytes.Buffer
		buf.Write([]byte{0xFF, 0xFE}) // UTF-16LE BOM
		for _, c := range body {
			buf.Write([]byte{byte(c & 0xFF), byte(c >> 8)})
		}
		w.Write(buf.Bytes())

	case 4: // UTF-8 BOM prefix on JSON (many parsers reject or mishandle this)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
		w.Write([]byte(body))
	}
}

// applyAuthChaos sends authentication and authorization error responses.
// Variants: 401 Bearer, 401 Basic, 401 Negotiate/NTLM, 401 custom scheme,
// expired JWT in body, OAuth2 invalid_grant, OAuth2 invalid_client, API key error.
func (e *Engine) applyAuthChaos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	variant := rand.Intn(8)
	switch variant {
	case 0: // 401 with Bearer challenge
		w.Header().Set("WWW-Authenticate", `Bearer realm="api", charset="UTF-8", error="invalid_token", error_description="The access token is invalid or has expired"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","error_description":"Bearer token is required or has expired"}`))

	case 1: // 401 with Basic challenge
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted API", charset="UTF-8"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"Basic authentication is required for this resource"}`))

	case 2: // 401 with Negotiate/NTLM (Windows auth)
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"Windows authentication (Kerberos or NTLM) is required"}`))

	case 3: // 401 with custom/non-standard scheme
		w.Header().Set("WWW-Authenticate", `ApiKey realm="production-api", charset="UTF-8", algorithm="sha256"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"API key authentication required","hint":"Pass your key in the X-API-Key header","docs":"https://api.example.com/docs/auth"}`))

	case 4: // Expired JWT token embedded in error response body
		// Realistic-looking expired JWT (header.payload — not cryptographically valid)
		expiredJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20ifQ.invalid_signature"
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"token_expired","message":"The JWT has expired","token":"` + expiredJWT + `","expired_at":"2018-01-18T00:00:22Z","issued_at":"2018-01-18T00:00:22Z"}`))

	case 5: // OAuth2 error: invalid_grant (RFC 6749 §5.2)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"The provided authorization grant is invalid, expired, revoked, does not match the redirection URI, or was issued to another client","error_uri":"https://tools.ietf.org/html/rfc6749#section-5.2"}`))

	case 6: // OAuth2 error: invalid_client (RFC 6749 §5.2)
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2-server"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method","error_uri":"https://tools.ietf.org/html/rfc6749#section-5.2"}`))

	case 7: // API key / forbidden error (403)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","code":"API_KEY_INVALID","message":"The API key provided is invalid, has been revoked, or does not have permission to access this resource","documentation":"https://api.example.com/docs/authentication#errors"}`))
	}
}
