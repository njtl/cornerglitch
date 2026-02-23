package labyrinth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeHTTP_ReturnsHTML(t *testing.T) {
	l := NewLabyrinth()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/articles/machine-learning/intro", nil)
	status := l.Serve(w, r)
	if status != 200 {
		t.Fatalf("expected status 200, got %d", status)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content-type, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("response should contain HTML doctype")
	}
}

func TestServeHTTP_Deterministic(t *testing.T) {
	l := NewLabyrinth()
	path := "/articles/distributed-computing/deep-dive"

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", path, nil)
	l.Serve(w1, r1)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", path, nil)
	l.Serve(w2, r2)

	// The title/structure should be the same (seeded from path).
	// We compare a stable portion: the <title> tag content.
	body1 := w1.Body.String()
	body2 := w2.Body.String()
	title1 := extractBetween(body1, "<title>", "</title>")
	title2 := extractBetween(body2, "<title>", "</title>")
	if title1 == "" || title1 != title2 {
		t.Fatalf("same path should produce same title: %q vs %q", title1, title2)
	}
}

func TestServeHTTP_DifferentPaths(t *testing.T) {
	l := NewLabyrinth()

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/articles/path-alpha/deep", nil)
	l.Serve(w1, r1)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/articles/path-beta/deep", nil)
	l.Serve(w2, r2)

	title1 := extractBetween(w1.Body.String(), "<title>", "</title>")
	title2 := extractBetween(w2.Body.String(), "<title>", "</title>")
	if title1 == title2 {
		t.Fatal("different paths should produce different content")
	}
}

func TestServeHTTP_ContainsLinks(t *testing.T) {
	l := NewLabyrinth()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/docs/api-development/overview", nil)
	l.Serve(w, r)
	body := w.Body.String()
	if !strings.Contains(body, "<a href") {
		t.Fatal("labyrinth page should contain <a href links")
	}
}

func TestSetMaxDepth(t *testing.T) {
	l := NewLabyrinth()
	if l.GetMaxDepth() != 50 {
		t.Fatalf("default maxDepth should be 50, got %d", l.GetMaxDepth())
	}
	l.SetMaxDepth(10)
	if l.GetMaxDepth() != 10 {
		t.Fatalf("expected maxDepth 10, got %d", l.GetMaxDepth())
	}
	l.SetMaxDepth(0)
	if l.GetMaxDepth() != 1 {
		t.Fatalf("maxDepth should clamp to 1, got %d", l.GetMaxDepth())
	}
	l.SetMaxDepth(200)
	if l.GetMaxDepth() != 100 {
		t.Fatalf("maxDepth should clamp to 100, got %d", l.GetMaxDepth())
	}
}

func TestSetLinkDensity(t *testing.T) {
	l := NewLabyrinth()
	if l.GetLinkDensity() != 8 {
		t.Fatalf("default linkDensity should be 8, got %d", l.GetLinkDensity())
	}
	l.SetLinkDensity(3)
	if l.GetLinkDensity() != 3 {
		t.Fatalf("expected linkDensity 3, got %d", l.GetLinkDensity())
	}
	l.SetLinkDensity(0)
	if l.GetLinkDensity() != 1 {
		t.Fatalf("linkDensity should clamp to 1, got %d", l.GetLinkDensity())
	}
	l.SetLinkDensity(50)
	if l.GetLinkDensity() != 20 {
		t.Fatalf("linkDensity should clamp to 20, got %d", l.GetLinkDensity())
	}
}

func TestShouldHandle(t *testing.T) {
	l := NewLabyrinth()

	// Known labyrinth segments
	if !l.IsLabyrinthPath("/articles/something") {
		t.Fatal("path starting with /articles/ should be handled")
	}
	if !l.IsLabyrinthPath("/docs/api") {
		t.Fatal("path starting with /docs/ should be handled")
	}
	// Deep paths (>= 3 slashes)
	if !l.IsLabyrinthPath("/a/b/c") {
		t.Fatal("path with 3+ slashes should be handled")
	}
	// Shallow non-segment path
	if l.IsLabyrinthPath("/favicon.ico") {
		t.Fatal("/favicon.ico should not be handled by labyrinth")
	}
}

func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i == -1 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j == -1 {
		return ""
	}
	return s[i : i+j]
}
