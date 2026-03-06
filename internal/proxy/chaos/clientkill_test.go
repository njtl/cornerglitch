package chaos

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeResp(body string) *http.Response {
	return &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

func TestClientKiller_Name(t *testing.T) {
	ck := NewClientKiller(1.0)
	if ck.Name() != "chaos/clientkill" {
		t.Errorf("expected name 'chaos/clientkill', got %q", ck.Name())
	}
}

func TestClientKiller_RequestPassthrough(t *testing.T) {
	ck := NewClientKiller(1.0)
	req, _ := http.NewRequest("GET", "/test", nil)
	result, err := ck.InterceptRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != req {
		t.Error("InterceptRequest should pass through unchanged")
	}
}

func TestClientKiller_NoAttackWhenProbabilityZero(t *testing.T) {
	ck := NewClientKiller(0.0)
	original := "original body content"
	resp := makeResp(original)
	resp.Header.Set("Content-Type", "text/plain")

	result, err := ck.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != resp {
		t.Error("expected same response when probability=0")
	}
}

func TestClientKiller_AlwaysAttacksWhenProbabilityOne(t *testing.T) {
	ck := NewClientKiller(1.0)
	modified := 0
	for i := 0; i < 20; i++ {
		resp := makeResp("test body")
		resp.Header.Set("Content-Type", "text/plain")

		result, err := ck.InterceptResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Read limited body to avoid hanging on infinite readers or OOM on bombs
		body, _ := io.ReadAll(io.LimitReader(result.Body, 4096))
		result.Body.Close()

		if string(body) != "test body" ||
			result.Header.Get("Content-Encoding") != "" ||
			result.Header.Get("X-Glitch") != "" ||
			result.Header.Get("X-Flood-0000") != "" ||
			result.Header.Get("Transfer-Encoding") != "" ||
			result.ContentLength != int64(len("test body")) {
			modified++
		}
	}
	if modified == 0 {
		t.Error("expected at least some responses to be modified with probability=1.0")
	}
}

func TestClientKiller_GzipBomb(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("small body")
	result := ck.attackGzipBomb(resp)

	if result.Header.Get("Content-Encoding") != "gzip" {
		t.Error("expected Content-Encoding: gzip")
	}

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("error reading body: %v", err)
	}

	// The gzip data should be much smaller than what it decompresses to
	if len(body) < 100 {
		t.Error("expected substantial gzip payload")
	}

	// Verify it's valid gzip by reading just the header
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("not valid gzip: %v", err)
	}
	// Read just 64KB to verify it decompresses (don't decompress the whole bomb)
	buf := make([]byte, 65536)
	n, _ := io.ReadFull(gr, buf)
	gr.Close()
	if n < 65536 {
		t.Errorf("expected at least 64KB decompressed, got %d bytes", n)
	}
}

func TestClientKiller_XMLBomb(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("small body")
	result := ck.attackXMLBomb(resp)

	if result.Header.Get("Content-Type") != "application/xml" {
		t.Error("expected Content-Type: application/xml")
	}

	body, _ := io.ReadAll(result.Body)
	if !strings.Contains(string(body), "<!ENTITY lol9") {
		t.Error("expected billion laughs XML entities")
	}
}

func TestClientKiller_JSONDepthBomb(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("small body")
	result := ck.attackJSONDepthBomb(resp)

	if result.Header.Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type: application/json")
	}

	body, _ := io.ReadAll(result.Body)
	// Should start with deeply nested JSON
	if !strings.HasPrefix(string(body), `{"a":{"a":`) {
		t.Error("expected deeply nested JSON")
	}
	// Should be very large
	if len(body) < 100000 {
		t.Error("expected large JSON body for depth bomb")
	}
}

func TestClientKiller_HeaderNullBytes(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("body")
	result := ck.attackHeaderNullBytes(resp)

	glitch := result.Header.Get("X-Glitch")
	if !strings.Contains(glitch, "\x00") {
		t.Error("expected null byte in X-Glitch header")
	}
}

func TestClientKiller_HeaderFlood(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("body")
	result := ck.attackHeaderFlood(resp)

	count := 0
	for key := range result.Header {
		if strings.HasPrefix(key, "X-Flood-") {
			count++
		}
	}
	if count < 100 {
		t.Errorf("expected hundreds of flood headers, got %d", count)
	}
}

func TestClientKiller_FalseCompression(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("plain text body")
	result := ck.attackFalseCompression(resp)

	if result.Header.Get("Content-Encoding") != "br" {
		t.Error("expected Content-Encoding: br")
	}

	// Body should still be plain text (not actually brotli compressed)
	body, _ := io.ReadAll(result.Body)
	if string(body) != "plain text body" {
		t.Error("expected original body preserved (false compression)")
	}
}

func TestClientKiller_CLTooLarge(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("short body")
	result := ck.attackCLTooLarge(resp)

	if result.ContentLength <= int64(len("short body")) {
		t.Error("expected Content-Length larger than actual body")
	}
}

func TestClientKiller_InfiniteBody(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("original")
	result := ck.attackInfiniteBody(resp)

	if result.ContentLength != -1 {
		t.Errorf("expected ContentLength=-1 for infinite body, got %d", result.ContentLength)
	}

	// Read a bit to confirm it produces data
	buf := make([]byte, 1024)
	n, err := result.Body.Read(buf)
	if err != nil {
		t.Fatalf("error reading infinite body: %v", err)
	}
	if n == 0 {
		t.Error("expected non-zero read from infinite body")
	}
	if !strings.Contains(string(buf[:n]), "padding") {
		t.Error("expected padding content from infinite reader")
	}
}

func TestClientKiller_BothCLAndTE(t *testing.T) {
	ck := NewClientKiller(1.0)
	resp := makeResp("body")
	resp.ContentLength = 4
	result := ck.attackBothCLAndTE(resp)

	if result.Header.Get("Transfer-Encoding") != "chunked" {
		t.Error("expected Transfer-Encoding: chunked")
	}
	cl := result.Header.Get("Content-Length")
	if cl == "" {
		t.Error("expected Content-Length to be set alongside Transfer-Encoding")
	}
}

func TestClientKiller_AllAttacksCovered(t *testing.T) {
	ck := NewClientKiller(1.0)
	attacks := ck.allAttacks()

	if len(attacks) < 15 {
		t.Errorf("expected at least 15 attacks, got %d", len(attacks))
	}

	// Verify all attacks have names and positive weights
	for _, a := range attacks {
		if a.name == "" {
			t.Error("attack has empty name")
		}
		if a.weight <= 0 {
			t.Errorf("attack %q has non-positive weight: %f", a.name, a.weight)
		}
	}

	// Run each attack to verify no panics
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			resp := makeResp("test body content for attack")
			resp.Header.Set("Content-Type", "text/html")
			result := a.apply(resp)
			if result == nil {
				t.Error("attack returned nil response")
			}
			// Read limited amount of body to avoid hanging on infinite readers
			if result.Body != nil {
				limited := io.LimitReader(result.Body, 4096)
				io.Copy(io.Discard, limited)
				result.Body.Close()
			}
		})
	}
}

func TestInfiniteReader(t *testing.T) {
	r := &infiniteReader{}
	buf := make([]byte, 4096)

	// Read multiple times — should never return io.EOF
	for i := 0; i < 10; i++ {
		n, err := r.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error on read %d: %v", i, err)
		}
		if n == 0 {
			t.Errorf("expected non-zero read on iteration %d", i)
		}
	}
}
