package fingerprint

import (
	"net/http/httptest"
	"testing"
)

func TestFingerprint_DifferentHeaders(t *testing.T) {
	e := NewEngine()

	r1 := httptest.NewRequest("GET", "/", nil)
	r1.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	r1.Header.Set("Accept-Language", "en-US")

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("User-Agent", "python-requests/2.31")
	r2.Header.Set("Accept-Language", "de-DE")

	id1 := e.Identify(r1)
	id2 := e.Identify(r2)
	if id1 == id2 {
		t.Fatalf("different headers should produce different IDs, both got %s", id1)
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	e := NewEngine()

	makeReq := func() *httptest.ResponseRecorder {
		return httptest.NewRecorder()
	}
	_ = makeReq

	r1 := httptest.NewRequest("GET", "/page", nil)
	r1.Header.Set("User-Agent", "TestBot/1.0")
	r1.Header.Set("Accept", "text/html")
	r1.RemoteAddr = "10.0.0.1:12345"

	r2 := httptest.NewRequest("GET", "/page", nil)
	r2.Header.Set("User-Agent", "TestBot/1.0")
	r2.Header.Set("Accept", "text/html")
	r2.RemoteAddr = "10.0.0.1:12345"

	id1 := e.Identify(r1)
	id2 := e.Identify(r2)
	if id1 != id2 {
		t.Fatalf("same request should produce same ID: %s vs %s", id1, id2)
	}
}

func TestClassify_Browser(t *testing.T) {
	e := NewEngine()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	class := e.ClassifyClient(r)
	if class != ClassBrowser {
		t.Fatalf("expected browser, got %s", class)
	}
}

func TestClassify_Bot(t *testing.T) {
	e := NewEngine()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "python-requests/2.31.0")
	class := e.ClassifyClient(r)
	if class != ClassScriptBot {
		t.Fatalf("expected script_bot, got %s", class)
	}
}

func TestClassify_SearchBot(t *testing.T) {
	e := NewEngine()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Googlebot/2.1 (+http://www.google.com/bot.html)")
	class := e.ClassifyClient(r)
	if class != ClassSearchBot {
		t.Fatalf("expected search_bot, got %s", class)
	}
}
