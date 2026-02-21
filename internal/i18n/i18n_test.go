package i18n

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if len(h.languages) != 10 {
		t.Errorf("expected 10 languages, got %d", len(h.languages))
	}
	if len(h.langCodes) != 10 {
		t.Errorf("expected 10 langCodes, got %d", len(h.langCodes))
	}
	if len(h.translations) == 0 {
		t.Error("translations map is empty after init")
	}
}

func TestNewHandlerLanguageCodes(t *testing.T) {
	h := NewHandler()
	expected := []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "ru"}
	for _, code := range expected {
		if !h.langCodes[code] {
			t.Errorf("expected langCodes to contain %q", code)
		}
	}
}

func TestNewHandlerTranslationsForAllLanguages(t *testing.T) {
	h := NewHandler()
	for _, l := range h.languages {
		if _, ok := h.translations[l.Code]; !ok {
			t.Errorf("missing translations for language %q", l.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ShouldHandle
// ---------------------------------------------------------------------------

func TestShouldHandleAPILanguages(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/api/i18n/languages") {
		t.Error("ShouldHandle should return true for /api/i18n/languages")
	}
}

func TestShouldHandleAPITranslate(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/api/i18n/translate") {
		t.Error("ShouldHandle should return true for /api/i18n/translate")
	}
}

func TestShouldHandleLangPathBare(t *testing.T) {
	h := NewHandler()
	codes := []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "ru"}
	for _, code := range codes {
		path := "/" + code
		if !h.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = false, want true", path)
		}
	}
}

func TestShouldHandleLangPathWithSubpath(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/fr/about") {
		t.Error("ShouldHandle(/fr/about) should return true")
	}
	if !h.ShouldHandle("/de/products/category/item") {
		t.Error("ShouldHandle(/de/products/category/item) should return true")
	}
}

func TestShouldHandleLangPathWithTrailingSlash(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/en/") {
		t.Error("ShouldHandle(/en/) should return true")
	}
}

func TestShouldHandleInvalidPaths(t *testing.T) {
	h := NewHandler()
	cases := []string{
		"/",
		"/foo",
		"/abc/def",
		"/api/other",
		"/english",
		"/e",
		"",
		"/xx",
		"/api/i18n",
		"/EN", // uppercase should not match (codes are lowercase)
	}
	for _, path := range cases {
		if h.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = true, want false", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Translate
// ---------------------------------------------------------------------------

func TestTranslateEnglish(t *testing.T) {
	h := NewHandler()
	got := h.Translate("home", "en")
	if got != "Home" {
		t.Errorf("Translate(home, en) = %q, want %q", got, "Home")
	}
}

func TestTranslateSpanish(t *testing.T) {
	h := NewHandler()
	got := h.Translate("home", "es")
	if got != "Inicio" {
		t.Errorf("Translate(home, es) = %q, want %q", got, "Inicio")
	}
}

func TestTranslateFrench(t *testing.T) {
	h := NewHandler()
	got := h.Translate("welcome", "fr")
	if got != "Bienvenue" {
		t.Errorf("Translate(welcome, fr) = %q, want %q", got, "Bienvenue")
	}
}

func TestTranslateGerman(t *testing.T) {
	h := NewHandler()
	got := h.Translate("search", "de")
	if got != "Suchen" {
		t.Errorf("Translate(search, de) = %q, want %q", got, "Suchen")
	}
}

func TestTranslateArabic(t *testing.T) {
	h := NewHandler()
	got := h.Translate("submit", "ar")
	if got == "" || got == "submit" {
		t.Errorf("Translate(submit, ar) should return Arabic translation, got %q", got)
	}
}

func TestTranslateFallbackToEnglish(t *testing.T) {
	h := NewHandler()
	// Use a key that exists in English but might not exist in another language.
	// Actually all languages share the same keys, so test with a bogus language code.
	got := h.Translate("home", "xx")
	if got != "Home" {
		t.Errorf("Translate(home, xx) should fall back to English 'Home', got %q", got)
	}
}

func TestTranslateUnknownKeyReturnsKey(t *testing.T) {
	h := NewHandler()
	got := h.Translate("nonexistent_key_xyz", "en")
	if got != "nonexistent_key_xyz" {
		t.Errorf("Translate with unknown key should return the key, got %q", got)
	}
}

func TestTranslateUnknownKeyUnknownLang(t *testing.T) {
	h := NewHandler()
	got := h.Translate("nonexistent_key_xyz", "xx")
	if got != "nonexistent_key_xyz" {
		t.Errorf("Translate with unknown key and lang should return the key, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// DetectLanguage
// ---------------------------------------------------------------------------

func TestDetectLanguageFromPath(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/fr/about", nil)
	got := h.DetectLanguage(req)
	if got != "fr" {
		t.Errorf("DetectLanguage from path = %q, want %q", got, "fr")
	}
}

func TestDetectLanguageFromCookie(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "de"})
	got := h.DetectLanguage(req)
	if got != "de" {
		t.Errorf("DetectLanguage from cookie = %q, want %q", got, "de")
	}
}

func TestDetectLanguageFromAcceptLanguage(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	req.Header.Set("Accept-Language", "ja;q=0.9, en;q=0.5")
	got := h.DetectLanguage(req)
	if got != "ja" {
		t.Errorf("DetectLanguage from Accept-Language = %q, want %q", got, "ja")
	}
}

func TestDetectLanguageAcceptLanguageWithRegionTag(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/page", nil)
	req.Header.Set("Accept-Language", "pt-BR;q=1.0, en;q=0.5")
	got := h.DetectLanguage(req)
	if got != "pt" {
		t.Errorf("DetectLanguage with region tag = %q, want %q", got, "pt")
	}
}

func TestDetectLanguagePriorityPathOverCookie(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/es/products", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	got := h.DetectLanguage(req)
	if got != "es" {
		t.Errorf("DetectLanguage should prefer path over cookie, got %q", got)
	}
}

func TestDetectLanguagePriorityCookieOverHeader(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "ko"})
	req.Header.Set("Accept-Language", "fr;q=1.0")
	got := h.DetectLanguage(req)
	if got != "ko" {
		t.Errorf("DetectLanguage should prefer cookie over header, got %q", got)
	}
}

func TestDetectLanguageDefaultsToEnglish(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	got := h.DetectLanguage(req)
	if got != "en" {
		t.Errorf("DetectLanguage default = %q, want %q", got, "en")
	}
}

func TestDetectLanguageInvalidCookieFallsThrough(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "xx"})
	req.Header.Set("Accept-Language", "ru;q=0.8")
	got := h.DetectLanguage(req)
	if got != "ru" {
		t.Errorf("DetectLanguage should skip invalid cookie, got %q, want %q", got, "ru")
	}
}

func TestDetectLanguageUnsupportedAcceptLanguageFallsToDefault(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/some-page", nil)
	req.Header.Set("Accept-Language", "sv;q=1.0, fi;q=0.9")
	got := h.DetectLanguage(req)
	if got != "en" {
		t.Errorf("DetectLanguage with unsupported langs = %q, want %q", got, "en")
	}
}

// ---------------------------------------------------------------------------
// parseAcceptLanguage (via DetectLanguage)
// ---------------------------------------------------------------------------

func TestParseAcceptLanguageQualitySorting(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/page", nil)
	req.Header.Set("Accept-Language", "en;q=0.3, fr;q=0.7, de;q=0.9")
	got := h.DetectLanguage(req)
	if got != "de" {
		t.Errorf("highest q should win, got %q, want %q", got, "de")
	}
}

func TestParseAcceptLanguageNoQDefaultsToOne(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/page", nil)
	req.Header.Set("Accept-Language", "zh, en;q=0.5")
	got := h.DetectLanguage(req)
	if got != "zh" {
		t.Errorf("language without q should default to 1.0, got %q, want %q", got, "zh")
	}
}

func TestParseAcceptLanguageEmptyHeader(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/page", nil)
	req.Header.Set("Accept-Language", "")
	got := h.DetectLanguage(req)
	if got != "en" {
		t.Errorf("empty Accept-Language should default to en, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — /api/i18n/languages
// ---------------------------------------------------------------------------

func TestServeLanguagesAPI(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/languages", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var langs []LangInfo
	if err := json.NewDecoder(w.Body).Decode(&langs); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if len(langs) != 10 {
		t.Errorf("expected 10 languages, got %d", len(langs))
	}

	// Verify first language is English
	if langs[0].Code != "en" || langs[0].Name != "English" {
		t.Errorf("first language = %+v, want English", langs[0])
	}

	// Verify Arabic is marked RTL
	for _, l := range langs {
		if l.Code == "ar" && !l.RTL {
			t.Error("Arabic should have RTL=true")
		}
		if l.Code == "en" && l.RTL {
			t.Error("English should have RTL=false")
		}
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — /api/i18n/translate
// ---------------------------------------------------------------------------

func TestServeTranslateAPIValid(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/translate?key=home&lang=es", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["key"] != "home" {
		t.Errorf("response key = %q, want %q", resp["key"], "home")
	}
	if resp["lang"] != "es" {
		t.Errorf("response lang = %q, want %q", resp["lang"], "es")
	}
	if resp["translation"] != "Inicio" {
		t.Errorf("translation = %q, want %q", resp["translation"], "Inicio")
	}
}

func TestServeTranslateAPIMissingKey(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/translate?lang=en", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestServeTranslateAPIMissingLang(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/translate?key=home", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestServeTranslateAPIMissingBothParams(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/translate", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestServeTranslateAPIFallbackToEnglish(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/api/i18n/translate?key=home&lang=xx", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["translation"] != "Home" {
		t.Errorf("translation = %q, want English fallback %q", resp["translation"], "Home")
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — localized pages
// ---------------------------------------------------------------------------

func TestServeLocalizedPageEnglishRoot(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/en/", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, `lang="en"`) {
		t.Error("expected html lang=en attribute")
	}
	if !strings.Contains(body, "GlitchServer") {
		t.Error("expected GlitchServer in page body")
	}
	if !strings.Contains(body, "Home") {
		t.Error("expected 'Home' navigation text for English")
	}

	cl := w.Header().Get("Content-Language")
	if cl != "en" {
		t.Errorf("Content-Language = %q, want %q", cl, "en")
	}
}

func TestServeLocalizedPageSpanish(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/es/", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, `lang="es"`) {
		t.Error("expected html lang=es attribute")
	}
	if !strings.Contains(body, "Inicio") {
		t.Error("expected Spanish 'Inicio' in navigation")
	}
}

func TestServeLocalizedPageArabicRTL(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/ar/", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, `dir="rtl"`) {
		t.Error("expected dir=rtl for Arabic page")
	}
	if !strings.Contains(body, `lang="ar"`) {
		t.Error("expected lang=ar attribute")
	}
}

func TestServeLocalizedPageNonRTLNoDirAttr(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/en/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, `dir="rtl"`) {
		t.Error("English page should not contain dir=rtl")
	}
}

func TestServeLocalizedPageWithSubpath(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/fr/about", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	body := w.Body.String()
	// Page title derived from subpath "about" -> "About" (strings.Title)
	if !strings.Contains(body, "About") {
		t.Error("expected derived page title 'About' in body")
	}
	// Breadcrumbs should contain link to /fr/about
	if !strings.Contains(body, `/fr/about`) {
		t.Error("expected breadcrumb link /fr/about")
	}
}

func TestServeLocalizedPageHreflangTags(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/de/products", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	// Should have hreflang for all 10 languages plus x-default
	for _, code := range []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "ru"} {
		expected := `hreflang="` + code + `"`
		if !strings.Contains(body, expected) {
			t.Errorf("expected hreflang tag for %q", code)
		}
	}
	if !strings.Contains(body, `hreflang="x-default"`) {
		t.Error("expected hreflang x-default tag")
	}
}

func TestServeLocalizedPageLanguageSelector(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/ko/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "<select") {
		t.Error("expected language selector <select> element")
	}
	if !strings.Contains(body, "selected") {
		t.Error("expected a selected option in language selector")
	}
}

func TestServeLocalizedPageDeepSubpath(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/ja/products/category/special-item", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	body := w.Body.String()
	// The last segment "special-item" -> "Special Item" (hyphens replaced, title-cased)
	if !strings.Contains(body, "Special Item") {
		t.Error("expected derived page title 'Special Item' from deep subpath")
	}
}

func TestServeLocalizedPageUnderscoreInSubpath(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/en/my_page", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	// "my_page" -> "my page" -> "My Page"
	if !strings.Contains(body, "My Page") {
		t.Error("expected derived page title 'My Page' from underscore subpath")
	}
}

func TestServeLocalizedPageBareLanguagePath(t *testing.T) {
	h := NewHandler()
	// Path "/en" (no trailing slash) should still work
	req := httptest.NewRequest("GET", "/en", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
}

func TestServeLocalizedPageContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/pt/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestServeLocalizedPageFooterLinks(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest("GET", "/en/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "privacy-policy") {
		t.Error("expected privacy-policy link in footer")
	}
	if !strings.Contains(body, "terms-of-service") {
		t.Error("expected terms-of-service link in footer")
	}
}

func TestServeHTTPInvalidLangPath404(t *testing.T) {
	h := NewHandler()
	// Path that starts like a lang path but has an invalid 2-letter code
	// This goes through ServeHTTP -> parseLangPath which returns empty lang -> 404
	req := httptest.NewRequest("GET", "/xx/page", nil)
	w := httptest.NewRecorder()

	// ShouldHandle returns false for /xx, so this wouldn't normally be routed here,
	// but if called directly, ServeHTTP should handle gracefully.
	status := h.ServeHTTP(w, req)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", status, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// LocalizedSnippet
// ---------------------------------------------------------------------------

func TestLocalizedSnippetEnglish(t *testing.T) {
	h := NewHandler()
	snippet := h.LocalizedSnippet("en")

	if !strings.Contains(snippet, `content="en"`) {
		t.Error("expected Content-Language meta tag with en")
	}
	if !strings.Contains(snippet, `document.documentElement.lang="en"`) {
		t.Error("expected JS lang assignment for en")
	}
	if strings.Contains(snippet, `dir="rtl"`) {
		t.Error("English snippet should not contain RTL directive")
	}
}

func TestLocalizedSnippetArabicRTL(t *testing.T) {
	h := NewHandler()
	snippet := h.LocalizedSnippet("ar")

	if !strings.Contains(snippet, `content="ar"`) {
		t.Error("expected Content-Language meta tag with ar")
	}
	if !strings.Contains(snippet, `dir="rtl"`) {
		t.Error("Arabic snippet should contain RTL directive")
	}
}

func TestLocalizedSnippetHreflangLinks(t *testing.T) {
	h := NewHandler()
	snippet := h.LocalizedSnippet("fr")

	for _, code := range []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "ru"} {
		expected := `hreflang="` + code + `"`
		if !strings.Contains(snippet, expected) {
			t.Errorf("snippet missing hreflang for %q", code)
		}
	}
	if !strings.Contains(snippet, `hreflang="x-default"`) {
		t.Error("snippet missing x-default hreflang")
	}
}

// ---------------------------------------------------------------------------
// parseLangPath edge cases (via ShouldHandle/ServeHTTP)
// ---------------------------------------------------------------------------

func TestParseLangPathShortPath(t *testing.T) {
	h := NewHandler()
	// Paths too short to contain a valid language code
	if h.ShouldHandle("/a") {
		t.Error("single-char path should not match")
	}
	if h.ShouldHandle("/") {
		t.Error("root path should not match")
	}
}

func TestParseLangPathThreeLetterCode(t *testing.T) {
	h := NewHandler()
	// 3-letter code should not match (only 2-letter codes are valid)
	if h.ShouldHandle("/eng/page") {
		t.Error("3-letter code should not match")
	}
}

// ---------------------------------------------------------------------------
// isRTL
// ---------------------------------------------------------------------------

func TestIsRTLArabic(t *testing.T) {
	h := NewHandler()
	if !h.isRTL("ar") {
		t.Error("Arabic should be RTL")
	}
}

func TestIsRTLNonRTLLanguages(t *testing.T) {
	h := NewHandler()
	nonRTL := []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ru"}
	for _, code := range nonRTL {
		if h.isRTL(code) {
			t.Errorf("%q should not be RTL", code)
		}
	}
}

func TestIsRTLUnknownLanguage(t *testing.T) {
	h := NewHandler()
	if h.isRTL("xx") {
		t.Error("unknown language should not be RTL")
	}
}

// ---------------------------------------------------------------------------
// All supported languages serve pages correctly
// ---------------------------------------------------------------------------

func TestAllLanguagesServePages(t *testing.T) {
	h := NewHandler()
	codes := []string{"en", "es", "fr", "de", "pt", "ja", "zh", "ko", "ar", "ru"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+code+"/", nil)
			w := httptest.NewRecorder()

			status := h.ServeHTTP(w, req)

			if status != http.StatusOK {
				t.Errorf("status for /%s/ = %d, want %d", code, status, http.StatusOK)
			}

			body := w.Body.String()
			if !strings.Contains(body, `lang="`+code+`"`) {
				t.Errorf("expected lang=%q attribute in HTML for %s", code, code)
			}

			cl := w.Header().Get("Content-Language")
			if cl != code {
				t.Errorf("Content-Language = %q, want %q", cl, code)
			}

			if !strings.Contains(body, "<!DOCTYPE html>") {
				t.Errorf("expected <!DOCTYPE html> in response for %s", code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Translation coverage — ensure all languages have the same keys as English
// ---------------------------------------------------------------------------

func TestTranslationKeyConsistency(t *testing.T) {
	h := NewHandler()
	enKeys := h.translations["en"]

	for _, l := range h.languages {
		if l.Code == "en" {
			continue
		}
		t.Run(l.Code, func(t *testing.T) {
			langTranslations, ok := h.translations[l.Code]
			if !ok {
				t.Fatalf("no translations for %q", l.Code)
			}
			for key := range enKeys {
				if _, exists := langTranslations[key]; !exists {
					t.Errorf("language %q missing translation for key %q", l.Code, key)
				}
			}
		})
	}
}
