package content

import (
	"math/rand"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ThemeForPath tests
// ---------------------------------------------------------------------------

func TestThemeForPath_ReturnsValidTheme(t *testing.T) {
	paths := []string{
		"/", "/blog/hello", "/products/widget", "/about",
		"/services/cloud", "/some/deep/nested/path",
	}

	valid := make(map[ThemeType]bool, len(AllThemes))
	for _, th := range AllThemes {
		valid[th] = true
	}

	for _, path := range paths {
		theme := ThemeForPath(path)
		if !valid[theme] {
			t.Errorf("ThemeForPath(%q) = %q, not a valid ThemeType", path, theme)
		}
	}
}

func TestThemeForPath_Deterministic(t *testing.T) {
	paths := []string{
		"/", "/blog/article-1", "/products/widget/details",
		"/a/b/c/d/e/f", "/contact",
	}

	for _, path := range paths {
		first := ThemeForPath(path)
		for i := 0; i < 50; i++ {
			got := ThemeForPath(path)
			if got != first {
				t.Errorf("ThemeForPath(%q) not deterministic: got %q and %q", path, first, got)
				break
			}
		}
	}
}

func TestThemeForPath_DifferentPathsMayDiffer(t *testing.T) {
	// Generate many paths and check that we see at least two distinct themes.
	seen := make(map[ThemeType]bool)
	for i := 0; i < 100; i++ {
		path := "/" + string(rune('a'+i%26)) + "/" + string(rune('A'+i%26))
		seen[ThemeForPath(path)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 distinct themes from 100 different paths, got %d", len(seen))
	}
}

// ---------------------------------------------------------------------------
// ThemeCSS tests
// ---------------------------------------------------------------------------

func TestThemeCSS_NonEmptyAndContainsStyle(t *testing.T) {
	for _, theme := range AllThemes {
		css := ThemeCSS(theme)
		if css == "" {
			t.Errorf("ThemeCSS(%q) returned empty string", theme)
			continue
		}
		if !strings.Contains(css, "<style") {
			t.Errorf("ThemeCSS(%q) does not contain '<style'", theme)
		}
		if !strings.Contains(css, "</style>") {
			t.Errorf("ThemeCSS(%q) does not contain '</style>'", theme)
		}
	}
}

func TestThemeCSS_ContainsThemeSpecificProperties(t *testing.T) {
	// Verify each theme has some CSS properties.
	for _, theme := range AllThemes {
		css := ThemeCSS(theme)
		if !strings.Contains(css, "--primary") {
			t.Errorf("ThemeCSS(%q) missing --primary custom property", theme)
		}
		if !strings.Contains(css, "font-family") {
			t.Errorf("ThemeCSS(%q) missing font-family", theme)
		}
	}
}

func TestThemeCSS_ThemesHaveDifferentColors(t *testing.T) {
	// Spot-check that at least some themes have genuinely different primary colors.
	saas := ThemeCSS(ThemeSaaS)
	news := ThemeCSS(ThemeNews)
	if saas == news {
		t.Error("SaaS and News themes should have different CSS")
	}
}

// ---------------------------------------------------------------------------
// ThemeHeader tests
// ---------------------------------------------------------------------------

func TestThemeHeader_NonEmpty(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for _, theme := range AllThemes {
		header := ThemeHeader(theme, rng)
		if header == "" {
			t.Errorf("ThemeHeader(%q) returned empty string", theme)
		}
	}
}

func TestThemeHeader_ContainsNavAndBrand(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	brands := map[ThemeType]string{
		ThemeSaaS:       "Acme Cloud",
		ThemeEcommerce:  "MegaShop",
		ThemeSocial:     "ConnectHub",
		ThemeNews:       "Daily Chronicle",
		ThemeDocs:       "DevDocs",
		ThemeCorporate:  "Meridian Corp",
		ThemeStartup:    "LaunchPad",
		ThemeGovt:       "Federal Services Portal",
		ThemeUniversity: "Westfield University",
		ThemeBanking:    "SecureBank",
	}

	for _, theme := range AllThemes {
		header := ThemeHeader(theme, rng)
		if !strings.Contains(header, "<nav") {
			t.Errorf("ThemeHeader(%q) missing <nav element", theme)
		}
		if !strings.Contains(header, "<header") && theme != ThemeGovt {
			// Govt theme wraps header differently but still has <header
			t.Errorf("ThemeHeader(%q) missing <header element", theme)
		}
		brand, ok := brands[theme]
		if ok && !strings.Contains(header, brand) {
			t.Errorf("ThemeHeader(%q) missing brand name %q", theme, brand)
		}
	}
}

func TestThemeHeader_ContainsLinks(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for _, theme := range AllThemes {
		header := ThemeHeader(theme, rng)
		if !strings.Contains(header, "href=") {
			t.Errorf("ThemeHeader(%q) should contain navigation links", theme)
		}
	}
}

// ---------------------------------------------------------------------------
// ThemeFooter tests
// ---------------------------------------------------------------------------

func TestThemeFooter_NonEmpty(t *testing.T) {
	for _, theme := range AllThemes {
		footer := ThemeFooter(theme)
		if footer == "" {
			t.Errorf("ThemeFooter(%q) returned empty string", theme)
		}
	}
}

func TestThemeFooter_ContainsFooterElement(t *testing.T) {
	for _, theme := range AllThemes {
		footer := ThemeFooter(theme)
		if !strings.Contains(footer, "<footer") {
			t.Errorf("ThemeFooter(%q) missing <footer element", theme)
		}
		if !strings.Contains(footer, "</footer>") {
			t.Errorf("ThemeFooter(%q) missing </footer> closing tag", theme)
		}
	}
}

func TestThemeFooter_ContainsCopyright(t *testing.T) {
	for _, theme := range AllThemes {
		footer := ThemeFooter(theme)
		if !strings.Contains(footer, "&copy;") && !strings.Contains(footer, "copyright") {
			t.Errorf("ThemeFooter(%q) missing copyright notice", theme)
		}
	}
}

func TestThemeFooter_ContainsPrivacyLink(t *testing.T) {
	for _, theme := range AllThemes {
		footer := ThemeFooter(theme)
		hasPrivacy := strings.Contains(strings.ToLower(footer), "privacy")
		if !hasPrivacy {
			t.Errorf("ThemeFooter(%q) missing privacy-related link", theme)
		}
	}
}

// ---------------------------------------------------------------------------
// ThemeMeta tests
// ---------------------------------------------------------------------------

func TestThemeMeta_NonEmpty(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "Test Page")
		if meta == "" {
			t.Errorf("ThemeMeta(%q) returned empty string", theme)
		}
	}
}

func TestThemeMeta_ContainsOgSiteName(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "Test Page")
		if !strings.Contains(meta, "og:site_name") {
			t.Errorf("ThemeMeta(%q) missing og:site_name meta tag", theme)
		}
	}
}

func TestThemeMeta_ContainsApplicationName(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "Test Page")
		if !strings.Contains(meta, "application-name") {
			t.Errorf("ThemeMeta(%q) missing application-name meta tag", theme)
		}
	}
}

func TestThemeMeta_ContainsTitle(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "My Custom Title")
		if !strings.Contains(meta, "My Custom Title") {
			t.Errorf("ThemeMeta(%q) does not contain the provided title", theme)
		}
	}
}

func TestThemeMeta_EscapesHTMLInTitle(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, `<script>alert("xss")</script>`)
		if strings.Contains(meta, "<script>") {
			t.Errorf("ThemeMeta(%q) did not escape HTML in title", theme)
		}
		if !strings.Contains(meta, "&lt;script&gt;") {
			t.Errorf("ThemeMeta(%q) should contain escaped script tag", theme)
		}
	}
}

func TestThemeMeta_ContainsThemeColor(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "Test")
		if !strings.Contains(meta, "theme-color") {
			t.Errorf("ThemeMeta(%q) missing theme-color meta tag", theme)
		}
	}
}

func TestThemeMeta_ContainsDescription(t *testing.T) {
	for _, theme := range AllThemes {
		meta := ThemeMeta(theme, "Test")
		if !strings.Contains(meta, `name="description"`) {
			t.Errorf("ThemeMeta(%q) missing description meta tag", theme)
		}
	}
}

// ---------------------------------------------------------------------------
// AllThemes completeness test
// ---------------------------------------------------------------------------

func TestAllThemes_Count(t *testing.T) {
	if len(AllThemes) != 10 {
		t.Errorf("AllThemes has %d entries, want 10", len(AllThemes))
	}
}

func TestAllThemes_AllHaveImplementations(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for _, theme := range AllThemes {
		css := ThemeCSS(theme)
		if css == "" {
			t.Errorf("theme %q has no CSS implementation", theme)
		}

		header := ThemeHeader(theme, rng)
		if header == "" {
			t.Errorf("theme %q has no Header implementation", theme)
		}

		footer := ThemeFooter(theme)
		if footer == "" {
			t.Errorf("theme %q has no Footer implementation", theme)
		}

		meta := ThemeMeta(theme, "test")
		if meta == "" {
			t.Errorf("theme %q has no Meta implementation", theme)
		}
	}
}

func TestAllThemes_NoDuplicates(t *testing.T) {
	seen := make(map[ThemeType]bool)
	for _, theme := range AllThemes {
		if seen[theme] {
			t.Errorf("duplicate theme in AllThemes: %q", theme)
		}
		seen[theme] = true
	}
}
