package search

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ShouldHandle
// ---------------------------------------------------------------------------

func TestShouldHandle_SearchRoot(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/search") {
		t.Error("ShouldHandle should return true for /search")
	}
}

func TestShouldHandle_Advanced(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/search/advanced") {
		t.Error("ShouldHandle should return true for /search/advanced")
	}
}

func TestShouldHandle_Images(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/search/images") {
		t.Error("ShouldHandle should return true for /search/images")
	}
}

func TestShouldHandle_Suggest(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/api/search/suggest") {
		t.Error("ShouldHandle should return true for /api/search/suggest")
	}
}

func TestShouldHandle_NonMatchingPaths(t *testing.T) {
	h := NewHandler()
	cases := []string{
		"/",
		"/about",
		"/search/other",
		"/api/search",
		"/api/search/suggestions",
		"/search/advanced/extra",
		"/searching",
		"/api/search/suggest/extra",
	}
	for _, path := range cases {
		if h.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) should return false", path)
		}
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — unknown path returns 404
// ---------------------------------------------------------------------------

func TestServeHTTP_UnknownPath(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Search home page (no query)
// ---------------------------------------------------------------------------

func TestSearchHome_StatusOK(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestSearchHome_ContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

func TestSearchHome_ContainsTitle(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "<title>GlitchSearch</title>") {
		t.Error("search home page should contain <title>GlitchSearch</title>")
	}
}

func TestSearchHome_ContainsSearchForm(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `action="/search"`) {
		t.Error("search home page should contain a form pointing to /search")
	}
}

func TestSearchHome_ContainsLinks(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "/search/images") {
		t.Error("search home should link to image search")
	}
	if !strings.Contains(body, "/search/advanced") {
		t.Error("search home should link to advanced search")
	}
}

// ---------------------------------------------------------------------------
// Search results (with query)
// ---------------------------------------------------------------------------

func TestSearchResults_StatusOK(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=golang", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestSearchResults_TitleContainsQuery(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=kubernetes+deployment", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "kubernetes deployment - GlitchSearch</title>") {
		t.Error("results page title should contain the query")
	}
}

func TestSearchResults_ContainsResultCount(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=testing", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "results (") {
		t.Error("results page should show result count and time")
	}
}

func TestSearchResults_Contains10Results(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=microservices", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	count := strings.Count(body, `class="result"`)
	if count != 10 {
		t.Errorf("expected 10 results, got %d", count)
	}
}

func TestSearchResults_ContainsResultElements(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=docker", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `class="result-title"`) {
		t.Error("results page should contain result titles")
	}
	if !strings.Contains(body, `class="result-snippet"`) {
		t.Error("results page should contain result snippets")
	}
	if !strings.Contains(body, `class="result-url"`) {
		t.Error("results page should contain result URLs")
	}
}

// ---------------------------------------------------------------------------
// Deterministic results
// ---------------------------------------------------------------------------

func TestSearchResults_Deterministic(t *testing.T) {
	h := NewHandler()
	query := "/search?q=determinism+test"

	req1 := httptest.NewRequest(http.MethodGet, query, nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, query, nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("same query should produce identical results (deterministic)")
	}
}

func TestSearchResults_DifferentQueries_DifferentResults(t *testing.T) {
	h := NewHandler()

	req1 := httptest.NewRequest(http.MethodGet, "/search?q=alpha", nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/search?q=omega", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() == rec2.Body.String() {
		t.Error("different queries should produce different results")
	}
}

func TestSearchResults_DeterministicPerPage(t *testing.T) {
	h := NewHandler()
	query := "/search?q=paging+check&page=3"

	req1 := httptest.NewRequest(http.MethodGet, query, nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, query, nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("same query+page should produce identical results")
	}
}

func TestSearchResults_DifferentPages_DifferentResults(t *testing.T) {
	h := NewHandler()

	req1 := httptest.NewRequest(http.MethodGet, "/search?q=paging&page=1", nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/search?q=paging&page=2", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() == rec2.Body.String() {
		t.Error("different pages should produce different results")
	}
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

func TestSearchResults_Page1_NoPrevious(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=pagination", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "Previous") {
		t.Error("page 1 should not have a Previous link")
	}
	if !strings.Contains(body, "Next") {
		t.Error("page 1 should have a Next link")
	}
}

func TestSearchResults_Page2_HasPrevious(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=pagination&page=2", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Previous") {
		t.Error("page 2 should have a Previous link")
	}
	if !strings.Contains(body, "Next") {
		t.Error("page 2 should have a Next link")
	}
}

func TestSearchResults_InvalidPageFallsBackTo1(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=test&page=abc", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	// With page defaulting to 1, should have no Previous link
	if strings.Contains(body, "Previous") {
		t.Error("invalid page should default to page 1 (no Previous link)")
	}
}

func TestSearchResults_NegativePageFallsBackTo1(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=test&page=-5", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	// page = -5, n > 0 check fails, so defaults to 1
	if strings.Contains(body, "Previous") {
		t.Error("negative page should default to page 1 (no Previous link)")
	}
}

func TestSearchResults_CurrentPageHighlighted(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=highlight&page=3", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<span class="current">3</span>`) {
		t.Error("current page (3) should be highlighted")
	}
}

// ---------------------------------------------------------------------------
// Advanced search page
// ---------------------------------------------------------------------------

func TestAdvanced_StatusOK(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestAdvanced_ContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %q", ct)
	}
}

func TestAdvanced_ContainsTitle(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Advanced Search - GlitchSearch") {
		t.Error("advanced page should contain the correct title")
	}
}

func TestAdvanced_ContainsFormFields(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()

	fields := []string{
		`name="q"`,
		`name="exact"`,
		`name="exclude"`,
		`name="site"`,
		`name="filetype"`,
		`name="date_from"`,
		`name="date_to"`,
	}
	for _, f := range fields {
		if !strings.Contains(body, f) {
			t.Errorf("advanced search should contain form field %q", f)
		}
	}
}

func TestAdvanced_ContainsFileTypeOptions(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()

	fileTypes := []string{"pdf", "doc", "csv", "json", "xml", "yaml", "txt", "html", "md"}
	for _, ft := range fileTypes {
		expected := `value="` + ft + `">`
		if !strings.Contains(body, expected) {
			t.Errorf("advanced search should list file type option %q", ft)
		}
	}
}

func TestAdvanced_FormActionPointsToSearch(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/advanced", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `action="/search"`) {
		t.Error("advanced search form should submit to /search")
	}
}

// ---------------------------------------------------------------------------
// Image search
// ---------------------------------------------------------------------------

func TestImages_StatusOK(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=cats", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestImages_ContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=test", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %q", ct)
	}
}

func TestImages_TitleContainsQuery(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=neural+networks", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "neural networks - GlitchSearch Images") {
		t.Error("image search title should contain query and 'GlitchSearch Images'")
	}
}

func TestImages_DefaultQueryGlitch(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "glitch - GlitchSearch Images") {
		t.Error("image search with no query should default to 'glitch'")
	}
}

func TestImages_Contains20Cards(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=landscapes", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	count := strings.Count(body, `class="img-card"`)
	if count != 20 {
		t.Errorf("expected 20 image cards, got %d", count)
	}
}

func TestImages_ContainsSVGElements(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=diagrams", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "<svg") {
		t.Error("image results should contain SVG elements")
	}
	if !strings.Contains(body, "linearGradient") {
		t.Error("image results should contain gradient SVG fills")
	}
}

func TestImages_Deterministic(t *testing.T) {
	h := NewHandler()
	url := "/search/images?q=consistency"

	req1 := httptest.NewRequest(http.MethodGet, url, nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, url, nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("image search should be deterministic for the same query")
	}
}

func TestImages_HasNavTabs(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search/images?q=test", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `class="active">Images</a>`) {
		t.Error("Images tab should be active on image search page")
	}
}

// ---------------------------------------------------------------------------
// Suggest API
// ---------------------------------------------------------------------------

func TestSuggest_EmptyQuery_EmptyArray(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	body := rec.Body.String()
	if body != "[]" {
		t.Errorf("empty query should return [], got %q", body)
	}
}

func TestSuggest_EmptyQuery_ContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestSuggest_WithQuery_ReturnsJSONArray(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest?q=golang", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}

	var suggestions []string
	err := json.Unmarshal(rec.Body.Bytes(), &suggestions)
	if err != nil {
		t.Fatalf("suggest response should be valid JSON array: %v", err)
	}
}

func TestSuggest_WithQuery_Returns5to10Suggestions(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest?q=python", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	var suggestions []string
	if err := json.Unmarshal(rec.Body.Bytes(), &suggestions); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(suggestions) < 5 || len(suggestions) > 10 {
		t.Errorf("expected 5-10 suggestions, got %d", len(suggestions))
	}
}

func TestSuggest_SuggestionsContainQueryPrefix(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest?q=rust", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	var suggestions []string
	if err := json.Unmarshal(rec.Body.Bytes(), &suggestions); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, s := range suggestions {
		// Each suggestion should contain the query (lowercased) since
		// generateSuggestion always starts with or includes the prefix.
		if !strings.Contains(s, "rust") {
			t.Errorf("suggestion %q should contain the query 'rust'", s)
		}
	}
}

func TestSuggest_Deterministic(t *testing.T) {
	h := NewHandler()
	url := "/api/search/suggest?q=deterministic"

	req1 := httptest.NewRequest(http.MethodGet, url, nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, url, nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("suggest should be deterministic for the same query")
	}
}

func TestSuggest_ContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/search/suggest?q=test", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// Did-you-mean suggestions
// ---------------------------------------------------------------------------

func TestDidYouMean_KnownTypo(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=teh+best+kubernetis+guide", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<div class="did-you-mean">`) {
		t.Error("query with typos should trigger a did-you-mean suggestion")
	}
	if !strings.Contains(body, "the best kubernetes guide") {
		t.Error("did-you-mean should correct 'teh' to 'the' and 'kubernetis' to 'kubernetes'")
	}
}

func TestDidYouMean_NoTypo(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=the+best+kubernetes+guide", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	// The CSS class "did-you-mean" always exists in the stylesheet; check
	// for the actual rendered <div class="did-you-mean"> element instead.
	if strings.Contains(body, `<div class="did-you-mean">`) {
		t.Error("query without typos should not render a did-you-mean div")
	}
}

func TestDidYouMean_MultipleTypos(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=recieve+seperate+parrallel", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "receive separate parallel") {
		t.Error("multiple typos should all be corrected in did-you-mean")
	}
}

// ---------------------------------------------------------------------------
// checkDidYouMean unit test
// ---------------------------------------------------------------------------

func TestCheckDidYouMean_ReturnsEmpty_WhenNoTypos(t *testing.T) {
	h := NewHandler()
	result := h.checkDidYouMean("docker container deploy")
	if result != "" {
		t.Errorf("expected empty string for correct words, got %q", result)
	}
}

func TestCheckDidYouMean_CorrectionIsCaseInsensitive(t *testing.T) {
	h := NewHandler()
	// checkDidYouMean lowercases first, and the typo map has lowercase keys
	result := h.checkDidYouMean("TEH big mistake")
	if result != "the big mistake" {
		t.Errorf("expected 'the big mistake', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func TestFormatNumber_Small(t *testing.T) {
	if formatNumber(42) != "42" {
		t.Errorf("formatNumber(42) = %q, want %q", formatNumber(42), "42")
	}
}

func TestFormatNumber_Thousands(t *testing.T) {
	if formatNumber(1234) != "1,234" {
		t.Errorf("formatNumber(1234) = %q, want %q", formatNumber(1234), "1,234")
	}
}

func TestFormatNumber_Millions(t *testing.T) {
	if formatNumber(1234567) != "1,234,567" {
		t.Errorf("formatNumber(1234567) = %q, want %q", formatNumber(1234567), "1,234,567")
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Hello World":      "hello-world",
		"foo/bar":          "foo-bar",
		"one  two":         "one-two",
		"UPPER":            "upper",
		"a_b":              "a-b",
		"special!chars#$%": "specialchars",
	}
	for input, want := range cases {
		got := slugify(input)
		if got != want {
			t.Errorf("slugify(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAtoi_Valid(t *testing.T) {
	cases := map[string]int{
		"0":    0,
		"1":    1,
		"42":   42,
		"100":  100,
		"-5":   -5,
		"-100": -100,
	}
	for s, want := range cases {
		got := atoi(s)
		if got != want {
			t.Errorf("atoi(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestAtoi_Invalid(t *testing.T) {
	got := atoi("abc")
	if got != 0 {
		t.Errorf("atoi(\"abc\") = %d, want 0", got)
	}
}

func TestAtoi_MixedInput(t *testing.T) {
	// Parses the leading numeric portion
	got := atoi("42abc")
	if got != 42 {
		t.Errorf("atoi(\"42abc\") = %d, want 42", got)
	}
}

func TestQuerySeed_Deterministic(t *testing.T) {
	s1 := querySeed("test query")
	s2 := querySeed("test query")
	if s1 != s2 {
		t.Error("querySeed should return same value for same input")
	}
}

func TestQuerySeed_DifferentInputs(t *testing.T) {
	s1 := querySeed("alpha")
	s2 := querySeed("beta")
	if s1 == s2 {
		t.Error("querySeed should return different values for different inputs")
	}
}

func TestQueryPageSeed_Deterministic(t *testing.T) {
	s1 := queryPageSeed("query", 1)
	s2 := queryPageSeed("query", 1)
	if s1 != s2 {
		t.Error("queryPageSeed should return same value for same input")
	}
}

func TestQueryPageSeed_DifferentPages(t *testing.T) {
	s1 := queryPageSeed("query", 1)
	s2 := queryPageSeed("query", 2)
	if s1 == s2 {
		t.Error("queryPageSeed should return different values for different pages")
	}
}

// ---------------------------------------------------------------------------
// HTML escaping
// ---------------------------------------------------------------------------

func TestSearchResults_HTMLEscapesQuery(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Error("query should be HTML-escaped in the output")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("query should contain escaped HTML entities")
	}
}
