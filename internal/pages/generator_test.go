package pages

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerate_HTML(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	g.Generate(w, r, PageHTML)
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Fatal("HTML page should contain DOCTYPE")
	}
}

func TestGenerate_JSON(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/data", nil)
	g.Generate(w, r, PageJSON)
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected application/json, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "data") {
		t.Fatal("JSON page should contain 'data' key")
	}
}

func TestGenerate_XML(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/xml", nil)
	g.Generate(w, r, PageXML)
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Fatalf("expected application/xml, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "<?xml") {
		t.Fatal("XML page should contain xml declaration")
	}
}

func TestGenerate_CSV(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/export", nil)
	g.Generate(w, r, PageCSV)
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/csv") {
		t.Fatalf("expected text/csv, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "id,name,category") {
		t.Fatal("CSV page should contain header row")
	}
}

func TestGenerate_Returns200(t *testing.T) {
	g := NewGenerator()
	// Test multiple page types all return 200
	types := []PageType{PageHTML, PageJSON, PagePlain, PageXML, PageCSV, PageMarkdown}
	for _, pt := range types {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		g.Generate(w, r, pt)
		if w.Code != 200 {
			t.Fatalf("page type %s returned status %d, expected 200", pt, w.Code)
		}
	}
}
