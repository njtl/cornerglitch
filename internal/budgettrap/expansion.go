package budgettrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ServeExpandedContent generates an HTML page with an exponentially growing number
// of links as path depth increases. Designed to drain crawler budgets by creating
// an ever-expanding tree of realistic-looking pages.
func ServeExpandedContent(w http.ResponseWriter, r *http.Request) (int, string) {
	path := r.URL.Path
	rng := rand.New(rand.NewSource(pathSeed(path)))

	// Calculate depth from path segments
	segments := strings.Split(strings.Trim(path, "/"), "/")
	depth := len(segments)

	// N = min(5 * depth^1.3, 50), minimum 5
	n := int(math.Min(5.0*math.Pow(float64(depth), 1.3), 50))
	if n < 5 {
		n = 5
	}

	// Generate links
	links := generateExpansionLinks(path, rng, n)

	// Build page title from path
	title := generateExpansionTitle(rng, segments)

	// Build breadcrumbs
	breadcrumbs := buildBreadcrumbs(segments)

	// Generate sections of realistic content
	numSections := rng.Intn(4) + 2
	var sections strings.Builder
	for i := 0; i < numSections; i++ {
		sectionTitle := expansionTitle(rng)
		sections.WriteString(fmt.Sprintf(`<section class="content-section"><h2>%s</h2>`, sectionTitle))
		numParagraphs := rng.Intn(3) + 2
		for j := 0; j < numParagraphs; j++ {
			sections.WriteString(fmt.Sprintf(`<p>%s</p>`, expansionParagraph(rng)))
		}
		sections.WriteString(`</section>`)
	}

	// Build link listing
	var linkNav strings.Builder
	linkNav.WriteString(`<nav class="resource-links"><h2>Related Resources</h2><ul>`)
	for _, link := range links {
		linkNav.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a> — %s</li>`, link.href, link.text, link.desc))
	}
	linkNav.WriteString(`</ul></nav>`)

	// Sidebar with additional links
	var sidebar strings.Builder
	sidebar.WriteString(`<aside class="sidebar"><h3>Popular Topics</h3><ul>`)
	sidebarN := rng.Intn(8) + 5
	sidebarLinks := generateExpansionLinks(path+"/sidebar", rng, sidebarN)
	for _, link := range sidebarLinks {
		sidebar.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, link.href, link.text))
	}
	sidebar.WriteString(`</ul></aside>`)

	// Prefetch hints and fetch() calls for API discovery
	var prefetch strings.Builder
	apiPaths := []string{
		"/api/v1/users/me", "/api/v1/notifications", "/api/auth/status",
		"/api/csrf-token", "/api/v1/content/related", "/api/search/suggest",
	}
	picked := rng.Intn(3) + 3
	for i := 0; i < picked && i < len(apiPaths); i++ {
		prefetch.WriteString(fmt.Sprintf(`  <link rel="prefetch" href="%s">`+"\n", apiPaths[rng.Intn(len(apiPaths))]))
	}

	publishDate := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -rng.Intn(365))

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s - Acme Corp Portal</title>
  <meta name="description" content="%s">
  <link rel="canonical" href="http://%s%s">
%s  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
    a { color: #2563eb; text-decoration: none; } a:hover { text-decoration: underline; }
    .topnav { background: #1e293b; color: white; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; }
    .topnav a { color: #94a3b8; margin-left: 20px; } .topnav a:hover { color: white; }
    .topnav .brand { font-weight: 700; font-size: 1.2em; color: white; }
    .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    .layout { display: grid; grid-template-columns: 1fr 300px; gap: 30px; margin-top: 20px; }
    .breadcrumbs { padding: 15px 0; font-size: 0.85em; color: #64748b; }
    .breadcrumbs a { color: #64748b; } .breadcrumbs a:hover { color: #2563eb; }
    main h1 { font-size: 2em; margin-bottom: 0.5em; }
    .meta { color: #64748b; font-size: 0.9em; margin-bottom: 20px; }
    .content-section { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .content-section h2 { margin-bottom: 12px; }
    .content-section p { margin-bottom: 10px; }
    .resource-links { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .resource-links ul { list-style: none; } .resource-links li { padding: 8px 0; border-bottom: 1px solid #e2e8f0; }
    .sidebar { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .sidebar h3 { margin-bottom: 12px; } .sidebar ul { list-style: none; } .sidebar li { padding: 6px 0; border-bottom: 1px solid #f1f5f9; }
    footer { background: #1e293b; color: #94a3b8; padding: 30px 20px; margin-top: 40px; text-align: center; font-size: 0.85em; }
    footer a { color: #60a5fa; }
  </style>
</head>
<body>
  <nav class="topnav">
    <span class="brand">Acme Corp Portal</span>
    <div>
      <a href="/">Home</a>
      <a href="/products">Products</a>
      <a href="/services">Services</a>
      <a href="/docs">Documentation</a>
      <a href="/support">Support</a>
      <a href="/blog">Blog</a>
    </div>
  </nav>
  <div class="container">
    <div class="breadcrumbs">%s</div>
    <div class="layout">
      <main>
        <h1>%s</h1>
        <p class="meta">Published %s | Category: %s | Depth: %d</p>
        %s
        %s
      </main>
      %s
    </div>
  </div>
  <footer>
    <p>&copy; 2025 Acme Corporation. All rights reserved.</p>
    <p><a href="/privacy">Privacy Policy</a> | <a href="/terms">Terms of Service</a> | <a href="/sitemap.xml">Sitemap</a></p>
  </footer>
  <script>
  document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/v1/users/me', {headers:{'Authorization':'Bearer ' + (document.cookie.match(/token=([^;]+)/)||[])[1]}})
      .then(r => r.json()).catch(() => {});
    fetch('/api/v1/content/related?path=' + encodeURIComponent(location.pathname))
      .then(r => r.json()).then(d => { /* populate sidebar */ });
    fetch('/api/auth/status', {credentials:'include'})
      .then(r => r.json()).then(d => { /* update UI */ });
  });
  </script>
</body>
</html>`,
		title,
		expansionTitle(rng),
		r.Host, path,
		prefetch.String(),
		breadcrumbs,
		title,
		publishDate.Format("January 2, 2006"),
		expansionTopics[rng.Intn(len(expansionTopics))],
		depth,
		sections.String(),
		linkNav.String(),
		sidebar.String(),
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK, "expansion"
}

type expansionLink struct {
	href string
	text string
	desc string
}

func generateExpansionLinks(basePath string, rng *rand.Rand, n int) []expansionLink {
	links := make([]expansionLink, n)
	for i := range links {
		adj := expansionAdjectives[rng.Intn(len(expansionAdjectives))]
		noun := expansionNouns[rng.Intn(len(expansionNouns))]

		// Generate deterministic sub-path hash
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s-%s-%d", basePath, adj, noun, i)))
		seg := hex.EncodeToString(h[:6])

		links[i] = expansionLink{
			href: fmt.Sprintf("%s/%s", strings.TrimRight(basePath, "/"), seg),
			text: fmt.Sprintf("%s %s", capitalize(adj), capitalize(noun)),
			desc: expansionDesc(rng),
		}
	}
	return links
}

func generateExpansionTitle(rng *rand.Rand, segments []string) string {
	if len(segments) > 0 {
		last := segments[len(segments)-1]
		// If it looks like a hash, use generated title
		if len(last) == 12 {
			return expansionTitle(rng)
		}
		words := strings.Split(last, "-")
		for i, w := range words {
			words[i] = capitalize(w)
		}
		return strings.Join(words, " ")
	}
	return expansionTitle(rng)
}

func expansionTitle(rng *rand.Rand) string {
	patterns := []string{
		fmt.Sprintf("The %s Guide to %s", expansionAdjectives[rng.Intn(len(expansionAdjectives))], expansionNouns[rng.Intn(len(expansionNouns))]),
		fmt.Sprintf("%s %s: A %s Overview", capitalize(expansionAdjectives[rng.Intn(len(expansionAdjectives))]), capitalize(expansionNouns[rng.Intn(len(expansionNouns))]), expansionAdjectives[rng.Intn(len(expansionAdjectives))]),
		fmt.Sprintf("Understanding %s in %s", expansionNouns[rng.Intn(len(expansionNouns))], expansionTopics[rng.Intn(len(expansionTopics))]),
		fmt.Sprintf("How to Build %s %s", expansionAdjectives[rng.Intn(len(expansionAdjectives))], expansionNouns[rng.Intn(len(expansionNouns))]),
		fmt.Sprintf("%s vs %s: Complete Comparison", capitalize(expansionNouns[rng.Intn(len(expansionNouns))]), capitalize(expansionNouns[rng.Intn(len(expansionNouns))])),
	}
	return patterns[rng.Intn(len(patterns))]
}

func expansionDesc(rng *rand.Rand) string {
	descs := []string{
		fmt.Sprintf("A %s guide covering %s %s", expansionAdjectives[rng.Intn(len(expansionAdjectives))], expansionAdjectives[rng.Intn(len(expansionAdjectives))], expansionNouns[rng.Intn(len(expansionNouns))]),
		fmt.Sprintf("Learn about %s and %s in %s", expansionNouns[rng.Intn(len(expansionNouns))], expansionNouns[rng.Intn(len(expansionNouns))], expansionTopics[rng.Intn(len(expansionTopics))]),
		fmt.Sprintf("Essential reading for %s %s", expansionAdjectives[rng.Intn(len(expansionAdjectives))], expansionNouns[rng.Intn(len(expansionNouns))]),
	}
	return descs[rng.Intn(len(descs))]
}

func expansionParagraph(rng *rand.Rand) string {
	templates := []string{
		"When building %s %s, it is essential to understand the %s nature of %s. Organizations that invest in %s %s report significant improvement in overall performance.",
		"The evolution of %s has transformed how we approach %s. Modern %s %s leverage %s techniques to achieve %s reliability across distributed systems.",
		"Consider the trade-offs between %s and %s when designing %s. A %s approach to %s can reduce complexity while maintaining %s quality.",
		"Industry leaders in %s consistently recommend %s %s for mission-critical %s. This %s methodology delivers %s outcomes across all operational contexts.",
		"Recent benchmarks show that %s %s outperform traditional %s in throughput. This %s breakthrough in %s is reshaping %s across all sectors.",
	}
	t := templates[rng.Intn(len(templates))]
	result := t
	for strings.Contains(result, "%s") {
		choices := []string{
			expansionAdjectives[rng.Intn(len(expansionAdjectives))],
			expansionNouns[rng.Intn(len(expansionNouns))],
			expansionTopics[rng.Intn(len(expansionTopics))],
		}
		result = strings.Replace(result, "%s", choices[rng.Intn(len(choices))], 1)
	}
	return result
}

func buildBreadcrumbs(segments []string) string {
	var sb strings.Builder
	sb.WriteString(`<a href="/">Home</a>`)
	accumulated := ""
	for _, part := range segments {
		if part == "" {
			continue
		}
		accumulated += "/" + part
		display := strings.ReplaceAll(part, "-", " ")
		if len(display) > 30 {
			display = display[:27] + "..."
		}
		sb.WriteString(fmt.Sprintf(` &raquo; <a href="%s">%s</a>`, accumulated, display))
	}
	return sb.String()
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var expansionAdjectives = []string{
	"advanced", "comprehensive", "essential", "practical", "complete",
	"definitive", "illustrated", "ultimate", "beginner", "expert",
	"modern", "classic", "interactive", "automated", "dynamic",
	"certified", "professional", "enterprise", "scalable", "premium",
}

var expansionNouns = []string{
	"systems", "networks", "protocols", "algorithms", "frameworks",
	"architectures", "databases", "interfaces", "pipelines", "deployments",
	"clusters", "containers", "services", "endpoints", "modules",
	"components", "patterns", "strategies", "workflows", "integrations",
}

var expansionTopics = []string{
	"machine learning", "distributed computing", "cloud infrastructure",
	"data engineering", "security operations", "DevOps practices",
	"microservices design", "API development", "performance tuning",
	"observability", "incident response", "capacity planning",
}
