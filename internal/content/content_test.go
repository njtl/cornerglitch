package content

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1. Cache tests
// ---------------------------------------------------------------------------

func TestCache_SetAndGet(t *testing.T) {
	c := NewCache(100, time.Hour)
	defer c.Stop()

	entry := &CacheEntry{
		Body:    []byte("hello world"),
		Headers: map[string]string{"Content-Type": "text/html"},
		Status:  200,
	}
	c.Set("/page1", entry)

	got, ok := c.Get("/page1")
	if !ok {
		t.Fatal("expected cache hit for /page1")
	}
	if string(got.Body) != "hello world" {
		t.Errorf("body = %q, want %q", string(got.Body), "hello world")
	}
	if got.Status != 200 {
		t.Errorf("status = %d, want 200", got.Status)
	}
	if got.Headers["Content-Type"] != "text/html" {
		t.Errorf("Content-Type = %q, want %q", got.Headers["Content-Type"], "text/html")
	}
}

func TestCache_GetMiss(t *testing.T) {
	c := NewCache(100, time.Hour)
	defer c.Stop()

	_, ok := c.Get("/nonexistent")
	if ok {
		t.Fatal("expected cache miss for nonexistent key")
	}
}

func TestCache_SetOverwrite(t *testing.T) {
	c := NewCache(100, time.Hour)
	defer c.Stop()

	c.Set("/page1", &CacheEntry{Body: []byte("first"), Status: 200})
	c.Set("/page1", &CacheEntry{Body: []byte("second"), Status: 201})

	got, ok := c.Get("/page1")
	if !ok {
		t.Fatal("expected cache hit after overwrite")
	}
	if string(got.Body) != "second" {
		t.Errorf("body = %q, want %q", string(got.Body), "second")
	}
	if got.Status != 201 {
		t.Errorf("status = %d, want 201", got.Status)
	}
	if c.Len() != 1 {
		t.Errorf("cache length = %d, want 1 after overwrite", c.Len())
	}
}

func TestCache_TTLExpiration(t *testing.T) {
	// Use a very short TTL so the entry expires quickly.
	c := NewCache(100, 50*time.Millisecond)
	defer c.Stop()

	c.Set("/expire-me", &CacheEntry{Body: []byte("temp"), Status: 200})

	// Should be present immediately.
	if _, ok := c.Get("/expire-me"); !ok {
		t.Fatal("expected cache hit before TTL expires")
	}

	// Wait for the TTL to pass.
	time.Sleep(100 * time.Millisecond)

	// Should be gone.
	if _, ok := c.Get("/expire-me"); ok {
		t.Fatal("expected cache miss after TTL expires")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := NewCache(3, time.Hour)
	defer c.Stop()

	c.Set("/a", &CacheEntry{Body: []byte("A"), Status: 200})
	c.Set("/b", &CacheEntry{Body: []byte("B"), Status: 200})
	c.Set("/c", &CacheEntry{Body: []byte("C"), Status: 200})

	// Cache is full. Adding /d should evict /a (least recently used).
	c.Set("/d", &CacheEntry{Body: []byte("D"), Status: 200})

	if _, ok := c.Get("/a"); ok {
		t.Error("expected /a to be evicted")
	}
	if _, ok := c.Get("/b"); !ok {
		t.Error("expected /b to still be present")
	}
	if _, ok := c.Get("/c"); !ok {
		t.Error("expected /c to still be present")
	}
	if _, ok := c.Get("/d"); !ok {
		t.Error("expected /d to still be present")
	}
}

func TestCache_LRUEvictionPromotesOnAccess(t *testing.T) {
	c := NewCache(3, time.Hour)
	defer c.Stop()

	c.Set("/a", &CacheEntry{Body: []byte("A"), Status: 200})
	c.Set("/b", &CacheEntry{Body: []byte("B"), Status: 200})
	c.Set("/c", &CacheEntry{Body: []byte("C"), Status: 200})

	// Access /a to promote it to the front of the LRU list.
	c.Get("/a")

	// Now adding /d should evict /b (the new least recently used).
	c.Set("/d", &CacheEntry{Body: []byte("D"), Status: 200})

	if _, ok := c.Get("/a"); !ok {
		t.Error("expected /a to still be present after promotion")
	}
	if _, ok := c.Get("/b"); ok {
		t.Error("expected /b to be evicted")
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewCache(100, time.Hour)
	defer c.Stop()

	c.Set("/del", &CacheEntry{Body: []byte("delete me"), Status: 200})
	c.Delete("/del")

	if _, ok := c.Get("/del"); ok {
		t.Fatal("expected key to be absent after Delete")
	}
	if c.Len() != 0 {
		t.Errorf("cache length = %d, want 0 after Delete", c.Len())
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewCache(100, time.Hour)
	defer c.Stop()

	c.Set("/x", &CacheEntry{Body: []byte("x"), Status: 200})
	c.Set("/y", &CacheEntry{Body: []byte("y"), Status: 200})
	c.Clear()

	if c.Len() != 0 {
		t.Errorf("cache length = %d, want 0 after Clear", c.Len())
	}
	if _, ok := c.Get("/x"); ok {
		t.Error("expected /x to be absent after Clear")
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewCache(1000, time.Hour)
	defer c.Stop()

	const goroutines = 50
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(id)))
			for i := 0; i < opsPerGoroutine; i++ {
				key := string(rune('a'+rng.Intn(26))) + string(rune('0'+rng.Intn(10)))
				switch rng.Intn(4) {
				case 0:
					c.Set(key, &CacheEntry{
						Body:   []byte(key),
						Status: 200,
					})
				case 1:
					c.Get(key)
				case 2:
					c.Delete(key)
				case 3:
					c.Len()
				}
			}
		}(g)
	}

	wg.Wait()
	// If we get here without a data race or panic, the test passes.
}

func TestCache_StatsTracking(t *testing.T) {
	c := NewCache(3, time.Hour)
	defer c.Stop()

	// Misses
	c.Get("/miss1")
	c.Get("/miss2")

	// Hits
	c.Set("/hit", &CacheEntry{Body: []byte("h"), Status: 200})
	c.Get("/hit")
	c.Get("/hit")

	// Evictions: fill cache, then add one more.
	c.Set("/e1", &CacheEntry{Body: []byte("e1"), Status: 200})
	c.Set("/e2", &CacheEntry{Body: []byte("e2"), Status: 200})
	// Cache is at capacity (3: /hit, /e1, /e2). Adding /e3 evicts the LRU.
	c.Set("/e3", &CacheEntry{Body: []byte("e3"), Status: 200})

	stats := c.Stats()

	if stats.Hits != 2 {
		t.Errorf("hits = %d, want 2", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("misses = %d, want 2", stats.Misses)
	}
	if stats.Evictions < 1 {
		t.Errorf("evictions = %d, want >= 1", stats.Evictions)
	}
	if stats.MaxSize != 3 {
		t.Errorf("maxSize = %d, want 3", stats.MaxSize)
	}
	if stats.Size != 3 {
		t.Errorf("size = %d, want 3", stats.Size)
	}
}

func TestCache_DefaultValues(t *testing.T) {
	// Passing zero values should use defaults.
	c := NewCache(0, 0)
	defer c.Stop()

	stats := c.Stats()
	if stats.MaxSize != 10000 {
		t.Errorf("default maxSize = %d, want 10000", stats.MaxSize)
	}
}

// ---------------------------------------------------------------------------
// 2. WordBank tests
// ---------------------------------------------------------------------------

func TestNewWordBank_NonNil(t *testing.T) {
	wb := NewWordBank()
	if wb == nil {
		t.Fatal("NewWordBank returned nil")
	}
	if wb.topics == nil {
		t.Fatal("topics map is nil")
	}
	if wb.generic == nil {
		t.Fatal("generic vocab is nil")
	}
	if wb.names == nil {
		t.Fatal("names bank is nil")
	}
}

func TestNewWordBank_AllTopicsPresent(t *testing.T) {
	wb := NewWordBank()

	expectedTopics := []string{
		"marketing", "technology", "health", "finance",
		"education", "travel", "food", "sports",
		"fashion", "real-estate", "automotive", "entertainment",
	}

	for _, topic := range expectedTopics {
		if _, ok := wb.topics[topic]; !ok {
			t.Errorf("expected topic %q to be present in WordBank", topic)
		}
	}
}

func TestWordBank_TopicForKnownPaths(t *testing.T) {
	wb := NewWordBank()

	tests := []struct {
		path  string
		topic string
	}{
		{"/marketing/strategy", "marketing"},
		{"/technology/cloud", "technology"},
		{"/health/wellness", "health"},
		{"/finance/investing", "finance"},
		{"/education/courses", "education"},
		{"/travel/destinations", "travel"},
		{"/food/recipes", "food"},
		{"/sports/football", "sports"},
		{"/fashion/trends", "fashion"},
		{"/real-estate/listings", "real-estate"},
		{"/automotive/reviews", "automotive"},
		{"/entertainment/movies", "entertainment"},
	}

	for _, tt := range tests {
		vocab := wb.TopicFor(tt.path)
		expected := wb.topics[tt.topic]
		if vocab != expected {
			t.Errorf("TopicFor(%q) did not return the %s vocab", tt.path, tt.topic)
		}
	}
}

func TestWordBank_TopicForUnknownPath(t *testing.T) {
	wb := NewWordBank()

	vocab := wb.TopicFor("/completely/unknown/path")
	if vocab != wb.generic {
		t.Error("expected generic vocab for unknown path")
	}
}

func TestWordBank_TopicForRootPath(t *testing.T) {
	wb := NewWordBank()

	vocab := wb.TopicFor("/")
	if vocab != wb.generic {
		t.Error("expected generic vocab for root path")
	}
}

func TestWordBank_TopicForSkipsGenericSegments(t *testing.T) {
	wb := NewWordBank()

	// "page" is a generic segment and should be skipped, so "technology" is matched.
	vocab := wb.TopicFor("/page/technology/deep")
	expected := wb.topics["technology"]
	if vocab != expected {
		t.Error("expected TopicFor to skip generic segment 'page' and match 'technology'")
	}

	// Multiple generic segments followed by a known topic.
	vocab = wb.TopicFor("/site/home/marketing")
	// After skipping "site" and "home", "marketing" should match.
	expected = wb.topics["marketing"]
	if vocab != expected {
		t.Error("expected TopicFor to skip 'site' and 'home' and match 'marketing'")
	}

	// All generic segments should fall back to generic vocab.
	vocab = wb.TopicFor("/page/site/home")
	if vocab != wb.generic {
		t.Error("expected generic vocab when all segments are generic")
	}
}

func TestWordBank_RandName(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 20; i++ {
		name := wb.RandName(rng)
		parts := strings.SplitN(name, " ", 2)
		if len(parts) != 2 {
			t.Errorf("RandName() = %q, want 'First Last' format", name)
		}
		if parts[0] == "" || parts[1] == "" {
			t.Errorf("RandName() = %q, has empty first or last name", name)
		}
	}
}

func TestWordBank_RandCompany(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 20; i++ {
		company := wb.RandCompany(rng)
		if company == "" {
			t.Error("RandCompany() returned empty string")
		}
	}
}

func TestWordBank_GenerateSentence(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))
	vocab := wb.topics["technology"]

	sentence := wb.GenerateSentence(rng, vocab)
	if sentence == "" {
		t.Error("GenerateSentence returned empty string")
	}
	// Templates have placeholders like {adj}, {noun}, {verb} - ensure they are filled.
	if strings.Contains(sentence, "{adj}") || strings.Contains(sentence, "{noun}") || strings.Contains(sentence, "{verb}") {
		t.Errorf("GenerateSentence still has unfilled placeholders: %q", sentence)
	}
	if strings.Contains(sentence, "{title}") || strings.Contains(sentence, "{name}") || strings.Contains(sentence, "{company}") {
		t.Errorf("GenerateSentence still has unfilled placeholders: %q", sentence)
	}
}

func TestWordBank_GenerateSentenceEmptyTemplates(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))

	emptyVocab := &TopicVocab{Templates: []string{}}
	sentence := wb.GenerateSentence(rng, emptyVocab)
	if sentence != "" {
		t.Errorf("expected empty string for empty templates, got %q", sentence)
	}
}

func TestWordBank_GenerateParagraph(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))
	vocab := wb.topics["marketing"]

	paragraph := wb.GenerateParagraph(rng, vocab, 5)
	if paragraph == "" {
		t.Error("GenerateParagraph returned empty string")
	}
	// There should be multiple sentences separated by spaces.
	// Each sentence comes from a template, so the paragraph should have substantial content.
	if len(paragraph) < 20 {
		t.Errorf("GenerateParagraph seems too short: %q", paragraph)
	}
}

func TestWordBank_GenerateParagraphDefaultSentences(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))
	vocab := wb.topics["health"]

	// Passing 0 should default to 3 sentences.
	paragraph := wb.GenerateParagraph(rng, vocab, 0)
	if paragraph == "" {
		t.Error("GenerateParagraph with 0 sentences returned empty string")
	}
}

func TestWordBank_Sentence(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))

	sentence := wb.Sentence(rng, 6, 14)
	if sentence == "" {
		t.Error("Sentence returned empty string")
	}
	if !strings.HasSuffix(sentence, ".") {
		t.Errorf("Sentence should end with a period, got %q", sentence)
	}
	// First character should be uppercase.
	if sentence[0] < 'A' || sentence[0] > 'Z' {
		t.Errorf("Sentence should start with uppercase, got %q", sentence)
	}
}

func TestWordBank_Paragraph(t *testing.T) {
	wb := NewWordBank()
	rng := rand.New(rand.NewSource(42))

	paragraph := wb.Paragraph(rng, 4)
	if paragraph == "" {
		t.Error("Paragraph returned empty string")
	}
	// Should contain multiple sentences (at least 4 periods).
	periods := strings.Count(paragraph, ".")
	if periods < 4 {
		t.Errorf("expected at least 4 sentences (periods), got %d", periods)
	}
}

func TestWordBank_ExportedFieldsPopulated(t *testing.T) {
	wb := NewWordBank()

	if len(wb.FirstNames) == 0 {
		t.Error("FirstNames is empty")
	}
	if len(wb.LastNames) == 0 {
		t.Error("LastNames is empty")
	}
	if len(wb.Companies) == 0 {
		t.Error("Companies is empty")
	}
	if len(wb.JobTitles) == 0 {
		t.Error("JobTitles is empty")
	}
	if len(wb.Adjectives) == 0 {
		t.Error("Adjectives is empty")
	}
	if len(wb.Nouns) == 0 {
		t.Error("Nouns is empty")
	}
	if len(wb.Verbs) == 0 {
		t.Error("Verbs is empty")
	}
	if len(wb.Topics) == 0 {
		t.Error("Topics is empty")
	}
	if len(wb.Buzzwords) == 0 {
		t.Error("Buzzwords is empty")
	}
	if len(wb.LoremWords) == 0 {
		t.Error("LoremWords is empty")
	}
}

// ---------------------------------------------------------------------------
// 3. Elements tests
// ---------------------------------------------------------------------------

func newTestElements() *Elements {
	return NewElements(NewWordBank())
}

func TestElements_SearchBar(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.SearchBar(rng)
	if html == "" {
		t.Fatal("SearchBar returned empty string")
	}
	if !strings.Contains(html, `action="/search"`) {
		t.Error("SearchBar should contain form action=\"/search\"")
	}
	if !strings.Contains(html, `method="GET"`) {
		t.Error("SearchBar should contain method=\"GET\"")
	}
	if !strings.Contains(html, `type="search"`) {
		t.Error("SearchBar should contain input type=\"search\"")
	}
}

func TestElements_LoginForm(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.LoginForm(rng)
	if html == "" {
		t.Fatal("LoginForm returned empty string")
	}
	if !strings.Contains(html, `type="hidden" name="_csrf"`) {
		t.Error("LoginForm should contain a CSRF token hidden input")
	}
	if !strings.Contains(html, `action="/api/auth/login"`) {
		t.Error("LoginForm should have action=\"/api/auth/login\"")
	}
	if !strings.Contains(html, `method="POST"`) {
		t.Error("LoginForm should use POST method")
	}
	if !strings.Contains(html, `type="password"`) {
		t.Error("LoginForm should have a password input")
	}
}

func TestElements_RegisterForm(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.RegisterForm(rng)
	if html == "" {
		t.Fatal("RegisterForm returned empty string")
	}
	if !strings.Contains(html, `action="/api/auth/register"`) {
		t.Error("RegisterForm should have action=\"/api/auth/register\"")
	}
	if !strings.Contains(html, `type="hidden" name="_csrf"`) {
		t.Error("RegisterForm should contain a CSRF token")
	}
}

func TestElements_ContactForm(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.ContactForm(rng)
	if html == "" {
		t.Fatal("ContactForm returned empty string")
	}
	if !strings.Contains(html, `method="POST"`) {
		t.Error("ContactForm should use POST method")
	}
	if !strings.Contains(html, `action="/api/contact"`) {
		t.Error("ContactForm should have action=\"/api/contact\"")
	}
	if !strings.Contains(html, "textarea") {
		t.Error("ContactForm should contain a textarea")
	}
}

func TestElements_NewsletterSignup(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.NewsletterSignup(rng)
	if html == "" {
		t.Fatal("NewsletterSignup returned empty string")
	}
	if !strings.Contains(html, `type="email"`) {
		t.Error("NewsletterSignup should have an email input")
	}
}

func TestElements_CookieConsent(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.CookieConsent(rng)
	if html == "" {
		t.Fatal("CookieConsent returned empty string")
	}
	if !strings.Contains(html, "cookie") || !strings.Contains(html, "Accept") {
		t.Error("CookieConsent should mention cookies and have accept button")
	}
}

func TestElements_NavHeader(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	navItems := []NavItem{
		{Label: "Home", Href: "/"},
		{Label: "About", Href: "/about"},
		{Label: "Blog", Href: "/blog"},
	}

	html := e.NavHeader(rng, navItems)
	if html == "" {
		t.Fatal("NavHeader returned empty string")
	}
	if !strings.Contains(html, "<nav") {
		t.Error("NavHeader should contain a <nav element")
	}
	if !strings.Contains(html, "<header") {
		t.Error("NavHeader should contain a <header element")
	}
	if !strings.Contains(html, `href="/about"`) {
		t.Error("NavHeader should contain link to /about")
	}
}

func TestElements_Footer(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.Footer(rng, "TestCorp")
	if html == "" {
		t.Fatal("Footer returned empty string")
	}
	if !strings.Contains(html, "<footer") {
		t.Error("Footer should contain a <footer element")
	}
	if !strings.Contains(html, "&copy;") {
		t.Error("Footer should contain copyright text (&copy;)")
	}
	if !strings.Contains(html, "TestCorp") {
		t.Error("Footer should contain the company name")
	}
	if !strings.Contains(html, "Privacy Policy") {
		t.Error("Footer should contain a Privacy Policy link")
	}
}

func TestElements_CommentSection(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.CommentSection(rng, 3)
	if html == "" {
		t.Fatal("CommentSection returned empty string")
	}
	if !strings.Contains(html, "Comments (3)") {
		t.Error("CommentSection should show the correct comment count")
	}
	if !strings.Contains(html, "comment-") {
		t.Error("CommentSection should contain comment IDs")
	}
}

func TestElements_ProductCard(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.ProductCard(rng)
	if html == "" {
		t.Fatal("ProductCard returned empty string")
	}
	if !strings.Contains(html, "product-card") {
		t.Error("ProductCard should contain product-card class")
	}
	if !strings.Contains(html, "Add to Cart") {
		t.Error("ProductCard should have an Add to Cart button")
	}
}

func TestElements_PricingTable(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.PricingTable(rng)
	if html == "" {
		t.Fatal("PricingTable returned empty string")
	}
	if !strings.Contains(html, "Basic") {
		t.Error("PricingTable should contain 'Basic' tier")
	}
	if !strings.Contains(html, "Pro") {
		t.Error("PricingTable should contain 'Pro' tier")
	}
	if !strings.Contains(html, "Enterprise") {
		t.Error("PricingTable should contain 'Enterprise' tier")
	}
}

func TestElements_Testimonial(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.Testimonial(rng)
	if html == "" {
		t.Fatal("Testimonial returned empty string")
	}
	if !strings.Contains(html, "testimonial") {
		t.Error("Testimonial should contain testimonial class")
	}
}

func TestElements_HeroSection(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.HeroSection(rng, "Test Title", "Test subtitle text")
	if html == "" {
		t.Fatal("HeroSection returned empty string")
	}
	if !strings.Contains(html, "Test Title") {
		t.Error("HeroSection should contain the title")
	}
	if !strings.Contains(html, "Test subtitle text") {
		t.Error("HeroSection should contain the subtitle")
	}
}

func TestElements_DataTable(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.DataTable(rng, 4, 5)
	if html == "" {
		t.Fatal("DataTable returned empty string")
	}
	if !strings.Contains(html, "<table") {
		t.Error("DataTable should contain a <table element")
	}
	if !strings.Contains(html, "<th") {
		t.Error("DataTable should contain <th elements")
	}
}

func TestElements_Breadcrumbs(t *testing.T) {
	e := newTestElements()

	html := e.Breadcrumbs("/blog/my-first-post")
	if html == "" {
		t.Fatal("Breadcrumbs returned empty string")
	}
	if !strings.Contains(html, `href="/"`) {
		t.Error("Breadcrumbs should contain a Home link")
	}
	if !strings.Contains(html, `href="/blog"`) {
		t.Error("Breadcrumbs should contain a link to /blog")
	}
	if !strings.Contains(html, "My First Post") {
		t.Error("Breadcrumbs should contain title-cased last segment")
	}
	// Last segment should not be a link.
	if strings.Contains(html, `href="/blog/my-first-post"`) {
		t.Error("Breadcrumbs last segment should not be a link")
	}
}

func TestElements_BreadcrumbsDeepPath(t *testing.T) {
	e := newTestElements()

	html := e.Breadcrumbs("/services/cloud/enterprise-plan")
	if !strings.Contains(html, `href="/services"`) {
		t.Error("Breadcrumbs should contain link to /services")
	}
	if !strings.Contains(html, `href="/services/cloud"`) {
		t.Error("Breadcrumbs should contain link to /services/cloud")
	}
	if !strings.Contains(html, "Enterprise Plan") {
		t.Error("Breadcrumbs should contain title-cased last segment")
	}
}

func TestElements_ImagePlaceholder(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	svg := e.ImagePlaceholder(rng, 800, 600)
	if svg == "" {
		t.Fatal("ImagePlaceholder returned empty string")
	}
	if !strings.Contains(svg, "<svg") {
		t.Error("ImagePlaceholder should return valid SVG")
	}
	if !strings.Contains(svg, "800") {
		t.Error("ImagePlaceholder SVG should contain the width")
	}
	if !strings.Contains(svg, "600") {
		t.Error("ImagePlaceholder SVG should contain the height")
	}
	if !strings.Contains(svg, "800 x 600") {
		t.Error("ImagePlaceholder should show dimensions text")
	}
	if !strings.Contains(svg, "linearGradient") {
		t.Error("ImagePlaceholder should contain a linearGradient")
	}
}

func TestElements_SocialShareButtons(t *testing.T) {
	e := newTestElements()

	html := e.SocialShareButtons()
	if html == "" {
		t.Fatal("SocialShareButtons returned empty string")
	}
	if !strings.Contains(html, "twitter") {
		t.Error("SocialShareButtons should contain Twitter link")
	}
	if !strings.Contains(html, "Share") {
		t.Error("SocialShareButtons should contain Share label")
	}
}

func TestElements_NotificationBanner(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.NotificationBanner(rng)
	if html == "" {
		t.Fatal("NotificationBanner returned empty string")
	}
}

func TestElements_Sidebar(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	links := []NavItem{
		{Label: "Related 1", Href: "/related/1"},
		{Label: "Related 2", Href: "/related/2"},
	}

	html := e.Sidebar(rng, links)
	if html == "" {
		t.Fatal("Sidebar returned empty string")
	}
	if !strings.Contains(html, "Related 1") {
		t.Error("Sidebar should contain the provided link labels")
	}
}

func TestElements_ArticleMetadata(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(42))

	html := e.ArticleMetadata(rng)
	if html == "" {
		t.Fatal("ArticleMetadata returned empty string")
	}
}

// Test that all element methods return non-empty HTML.
func TestElements_AllReturnNonEmpty(t *testing.T) {
	e := newTestElements()
	rng := rand.New(rand.NewSource(99))

	tests := []struct {
		name string
		fn   func() string
	}{
		{"SearchBar", func() string { return e.SearchBar(rng) }},
		{"LoginForm", func() string { return e.LoginForm(rng) }},
		{"RegisterForm", func() string { return e.RegisterForm(rng) }},
		{"ContactForm", func() string { return e.ContactForm(rng) }},
		{"NewsletterSignup", func() string { return e.NewsletterSignup(rng) }},
		{"CookieConsent", func() string { return e.CookieConsent(rng) }},
		{"NavHeader", func() string { return e.NavHeader(rng, []NavItem{{Label: "X", Href: "/x"}}) }},
		{"Footer", func() string { return e.Footer(rng, "TestCo") }},
		{"CommentSection", func() string { return e.CommentSection(rng, 2) }},
		{"ProductCard", func() string { return e.ProductCard(rng) }},
		{"PricingTable", func() string { return e.PricingTable(rng) }},
		{"Testimonial", func() string { return e.Testimonial(rng) }},
		{"HeroSection", func() string { return e.HeroSection(rng, "Title", "Sub") }},
		{"DataTable", func() string { return e.DataTable(rng, 3, 3) }},
		{"NotificationBanner", func() string { return e.NotificationBanner(rng) }},
		{"Breadcrumbs", func() string { return e.Breadcrumbs("/a/b/c") }},
		{"ImagePlaceholder", func() string { return e.ImagePlaceholder(rng, 100, 100) }},
		{"SocialShareButtons", func() string { return e.SocialShareButtons() }},
		{"Sidebar", func() string { return e.Sidebar(rng, []NavItem{{Label: "L", Href: "/l"}}) }},
		{"ArticleMetadata", func() string { return e.ArticleMetadata(rng) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result == "" {
				t.Errorf("%s returned empty string", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Engine tests
// ---------------------------------------------------------------------------

func TestEngine_ShouldHandleRegularPaths(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	regularPaths := []string{
		"/",
		"/blog/hello-world",
		"/products/widget",
		"/about/team",
		"/services/consulting",
		"/help/faq",
		"/some/random/path",
	}

	for _, path := range regularPaths {
		if !eng.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = false, want true", path)
		}
	}
}

func TestEngine_ShouldHandleReservedPaths(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	reservedPaths := []string{
		"/api/v1/users",
		"/v1/resources",
		"/v2/data",
		"/v3/endpoint",
		"/graphql",
		"/ws/events",
		"/oauth/authorize",
		"/saml/login",
		"/.well-known/openid-configuration",
		"/.env",
		"/.git/config",
		"/health",
		"/healthz",
		"/ready",
		"/live",
		"/metrics",
		"/debug/pprof",
		"/actuator/health",
		"/favicon.ico",
		"/robots.txt",
		"/sitemap.xml",
	}

	for _, path := range reservedPaths {
		if eng.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = true, want false", path)
		}
	}
}

func TestEngine_DetectPageStyle(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	tests := []struct {
		path  string
		style PageStyle
	}{
		{"/blog/my-post", StyleArticle},
		{"/news/today", StyleArticle},
		{"/articles/latest", StyleArticle},
		{"/posts/first", StyleArticle},
		{"/stories/featured", StyleArticle},
		{"/products/widget", StyleProduct},
		{"/shop/items", StyleProduct},
		{"/store/deals", StyleProduct},
		{"/catalog/list", StyleProduct},
		{"/marketplace/apps", StyleProduct},
		{"/about/us", StyleCorporate},
		{"/team/engineering", StyleCorporate},
		{"/careers/open", StyleCorporate},
		{"/company/overview", StyleCorporate},
		{"/investors/relations", StyleCorporate},
		{"/services/consulting", StyleService},
		{"/solutions/enterprise", StyleService},
		{"/features/overview", StyleService},
		{"/platform/api", StyleService},
		{"/help/getting-started", StyleHelp},
		{"/support/tickets", StyleHelp},
		{"/faq/billing", StyleHelp},
		{"/docs/api", StyleHelp},
		{"/knowledge-base/articles", StyleHelp},
		{"/dashboard/overview", StyleDashboard},
		{"/account/settings", StyleDashboard},
		{"/settings/profile", StyleDashboard},
		{"/profile/edit", StyleDashboard},
		{"/admin/users", StyleDashboard},
		{"/", StyleGeneric},
		{"/random-page", StyleGeneric},
		{"/xyz/abc/def", StyleGeneric},
	}

	for _, tt := range tests {
		got := eng.detectPageStyle(tt.path)
		if got != tt.style {
			t.Errorf("detectPageStyle(%q) = %q, want %q", tt.path, got, tt.style)
		}
	}
}

func TestEngine_Serve_Returns200(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	req := httptest.NewRequest(http.MethodGet, "/blog/test-article", nil)
	w := httptest.NewRecorder()

	status := eng.Serve(w, req)
	if status != http.StatusOK {
		t.Errorf("Serve status = %d, want %d", status, http.StatusOK)
	}
	if w.Code != http.StatusOK {
		t.Errorf("response code = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestEngine_Serve_ReturnsHTML(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	req := httptest.NewRequest(http.MethodGet, "/products/test-product", nil)
	w := httptest.NewRecorder()

	eng.Serve(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("response should contain <!DOCTYPE html>")
	}
	if !strings.Contains(body, "<html") {
		t.Error("response should contain <html element")
	}
	if !strings.Contains(body, "<head") {
		t.Error("response should contain <head element")
	}
	if !strings.Contains(body, "<body") {
		t.Error("response should contain <body element")
	}
	if !strings.Contains(body, "<nav") {
		t.Error("response should contain <nav element")
	}
	if !strings.Contains(body, "<footer") {
		t.Error("response should contain <footer element")
	}
	if !strings.Contains(body, "<main") {
		t.Error("response should contain <main element")
	}

	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestEngine_Serve_Deterministic(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	path := "/blog/determinism-test-1234"

	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	w1 := httptest.NewRecorder()
	eng.Serve(w1, req1)
	body1 := w1.Body.String()

	// Clear cache to force re-generation.
	eng.cache.Clear()

	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	w2 := httptest.NewRecorder()
	eng.Serve(w2, req2)
	body2 := w2.Body.String()

	if body1 != body2 {
		t.Error("same path should produce identical content (deterministic); bodies differ")
	}
}

func TestEngine_Serve_DifferentPathsDifferentContent(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	req1 := httptest.NewRequest(http.MethodGet, "/blog/alpha-content", nil)
	w1 := httptest.NewRecorder()
	eng.Serve(w1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/products/beta-gadget", nil)
	w2 := httptest.NewRecorder()
	eng.Serve(w2, req2)

	if w1.Body.String() == w2.Body.String() {
		t.Error("different paths should produce different content")
	}
}

func TestEngine_Serve_ContentIsCached(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	path := "/blog/cache-test-page"

	// First request: uncached, generates content.
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	w1 := httptest.NewRecorder()
	start1 := time.Now()
	eng.Serve(w1, req1)
	duration1 := time.Since(start1)

	// Second request: should be served from cache.
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	w2 := httptest.NewRecorder()
	start2 := time.Now()
	eng.Serve(w2, req2)
	duration2 := time.Since(start2)

	// Verify the content is the same.
	if w1.Body.String() != w2.Body.String() {
		t.Error("cached response body should match original")
	}

	// Verify cache was used (second request should be significantly faster).
	// We give generous slack since test environments can be slow.
	if duration1 > 0 && duration2 > duration1*10 {
		t.Errorf("cached request took %v, uncached took %v; cache does not seem effective", duration2, duration1)
	}

	// Verify cache stats show a hit.
	stats := eng.CacheStats()
	if stats.Hits < 1 {
		t.Errorf("expected at least 1 cache hit, got %d", stats.Hits)
	}
}

func TestEngine_Serve_Headers(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	req := httptest.NewRequest(http.MethodGet, "/about/us", nil)
	w := httptest.NewRecorder()
	eng.Serve(w, req)

	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "public, max-age=86400" {
		t.Errorf("Cache-Control = %q, want %q", cacheControl, "public, max-age=86400")
	}

	contentID := w.Header().Get("X-Content-Id")
	if contentID == "" {
		t.Error("X-Content-Id header should be present")
	}
	if !strings.HasPrefix(contentID, "cid-") {
		t.Errorf("X-Content-Id = %q, should start with 'cid-'", contentID)
	}
}

func TestEngine_PathSeedDeterministic(t *testing.T) {
	// Same path should always produce the same seed.
	seed1 := pathSeed("/test/path")
	seed2 := pathSeed("/test/path")
	if seed1 != seed2 {
		t.Errorf("pathSeed is not deterministic: %d != %d", seed1, seed2)
	}

	// Different paths should (almost certainly) produce different seeds.
	seed3 := pathSeed("/different/path")
	if seed1 == seed3 {
		t.Errorf("pathSeed returned same value for different paths: %d", seed1)
	}
}

func TestEngine_Slugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hello World", "hello-world"},
		{"Under_Score", "under-score"},
		{"Special!@#Chars", "specialchars"},
		{"already-slug", "already-slug"},
		{"UPPER CASE", "upper-case"},
		{"123-numbers", "123-numbers"},
		{"mixed CASE_with-stuff!", "mixed-case-with-stuff"},
		{"", ""},
	}

	for _, tt := range tests {
		got := slugify(tt.input)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEngine_EscHTML(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert('xss')&lt;/script&gt;"},
		{`a"b`, "a&quot;b"},
		{"a&b", "a&amp;b"},
		{"<>&\"", "&lt;&gt;&amp;&quot;"},
	}

	for _, tt := range tests {
		got := escHTML(tt.input)
		if got != tt.want {
			t.Errorf("escHTML(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEngine_PathSegments(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"/", nil},
		{"", nil},
		{"/blog/post", []string{"blog", "post"}},
		{"/a/page/b", []string{"a", "b"}}, // "page" is filtered
		{"/blog/", []string{"blog"}},
		{"/a/b/c", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		got := pathSegments(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("pathSegments(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("pathSegments(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestEngine_Serve_AllPageStyles(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	paths := []struct {
		path  string
		style string
	}{
		{"/blog/test-article", "article"},
		{"/products/test-product", "product"},
		{"/about/company", "corporate"},
		{"/services/consulting", "service"},
		{"/help/getting-started", "help"},
		{"/dashboard/overview", "dashboard"},
		{"/random/generic-page", "generic"},
	}

	for _, tt := range paths {
		t.Run(tt.style, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			status := eng.Serve(w, req)
			if status != http.StatusOK {
				t.Errorf("Serve(%s) status = %d, want 200", tt.path, status)
			}
			body := w.Body.String()
			if !strings.Contains(body, "<html") {
				t.Errorf("Serve(%s) response missing <html", tt.path)
			}
			if len(body) < 1000 {
				t.Errorf("Serve(%s) response seems too short: %d bytes", tt.path, len(body))
			}
		})
	}
}

func TestEngine_Serve_RootPath(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	status := eng.Serve(w, req)

	if status != http.StatusOK {
		t.Errorf("Serve(/) status = %d, want 200", status)
	}
	if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Error("root path should return full HTML page")
	}
}

func TestEngine_CacheStats(t *testing.T) {
	eng := NewEngine()
	defer eng.Stop()

	stats := eng.CacheStats()
	if stats.MaxSize != 10000 {
		t.Errorf("engine cache maxSize = %d, want 10000", stats.MaxSize)
	}
	if stats.Size != 0 {
		t.Errorf("engine cache initial size = %d, want 0", stats.Size)
	}
}
