package pages

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// PageType defines the category of page content to generate.
type PageType string

const (
	PageHTML       PageType = "html"
	PageJSON       PageType = "json"
	PagePlain      PageType = "plain"
	PageXML        PageType = "xml"
	PageCSV        PageType = "csv"
	PageMarkdown   PageType = "markdown"
	PageSSE        PageType = "sse"           // server-sent events stream
	PageChunked    PageType = "chunked"       // chunked transfer
	PageWebSocket  PageType = "websocket_ish" // not real WS, but mimics upgrade
)

var allPageTypes = []PageType{
	PageHTML, PageJSON, PagePlain, PageXML, PageCSV, PageMarkdown, PageSSE, PageChunked,
}

// Generator produces dynamic page content on the fly.
type Generator struct {
	titles    []string
	words     []string
	companies []string
	paths     []string
}

func NewGenerator() *Generator {
	return &Generator{
		titles: []string{
			"Welcome", "About Us", "Products", "Services", "Contact",
			"Blog", "News", "FAQ", "Pricing", "Documentation",
			"Terms of Service", "Privacy Policy", "Careers", "Team",
			"Case Studies", "Resources", "Support", "Status", "API",
			"Dashboard", "Settings", "Profile", "Analytics", "Reports",
		},
		words: []string{
			"innovative", "scalable", "enterprise", "cloud-native", "real-time",
			"distributed", "resilient", "microservice", "serverless", "containerized",
			"high-availability", "fault-tolerant", "event-driven", "data-driven",
			"AI-powered", "blockchain", "quantum-ready", "next-generation",
			"mission-critical", "best-in-class", "paradigm-shifting", "synergistic",
			"robust", "agile", "seamless", "cutting-edge", "disruptive",
		},
		companies: []string{
			"Acme Corp", "Globex", "Initech", "Umbrella Inc", "Cyberdyne",
			"Soylent Corp", "Weyland-Yutani", "Tyrell Corp", "Stark Industries",
		},
		paths: []string{
			"/products", "/about", "/contact", "/blog", "/api/v1/data",
			"/services", "/pricing", "/docs", "/faq", "/news",
			"/team", "/careers", "/support", "/status", "/dashboard",
		},
	}
}

// PickType selects a random page type.
func (g *Generator) PickType() PageType {
	return allPageTypes[rand.Intn(len(allPageTypes))]
}

// Generate writes a full page response of the given type.
func (g *Generator) Generate(w http.ResponseWriter, r *http.Request, pt PageType) {
	switch pt {
	case PageHTML:
		g.generateHTML(w, r)
	case PageJSON:
		g.generateJSON(w, r)
	case PagePlain:
		g.generatePlain(w)
	case PageXML:
		g.generateXML(w)
	case PageCSV:
		g.generateCSV(w)
	case PageMarkdown:
		g.generateMarkdown(w)
	case PageSSE:
		g.generateSSE(w)
	case PageChunked:
		g.generateChunked(w)
	default:
		g.generateHTML(w, r)
	}
}

func (g *Generator) randWords(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = g.words[rand.Intn(len(g.words))]
	}
	return strings.Join(parts, " ")
}

func (g *Generator) randTitle() string {
	return g.titles[rand.Intn(len(g.titles))]
}

func (g *Generator) generateHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title := g.randTitle()
	company := g.companies[rand.Intn(len(g.companies))]

	// Generate internal links for crawlers to follow
	numLinks := rand.Intn(10) + 5
	var links strings.Builder
	for i := 0; i < numLinks; i++ {
		path := g.paths[rand.Intn(len(g.paths))]
		linkTitle := g.randTitle()
		links.WriteString(fmt.Sprintf(`    <li><a href="%s">%s</a></li>`+"\n", path, linkTitle))
	}

	numParagraphs := rand.Intn(5) + 2
	var paragraphs strings.Builder
	for i := 0; i < numParagraphs; i++ {
		paragraphs.WriteString(fmt.Sprintf("  <p>Our %s solution provides %s capabilities for %s organizations. "+
			"Built with %s architecture, it delivers %s performance at scale.</p>\n",
			g.randWords(1), g.randWords(2), g.randWords(1), g.randWords(1), g.randWords(1)))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s - %s</title>
  <meta name="description" content="%s">
  <meta name="generator" content="GlitchServer/2.0">
  <link rel="canonical" href="http://%s%s">
</head>
<body>
  <header>
    <h1>%s</h1>
    <nav>
      <ul>
%s      </ul>
    </nav>
  </header>
  <main>
%s
    <section>
      <h2>%s</h2>
      <p>Generated at %s. Request #%d.</p>
      <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Uptime</td><td>%d%%</td></tr>
        <tr><td>Latency</td><td>%dms</td></tr>
        <tr><td>Throughput</td><td>%d req/s</td></tr>
      </table>
    </section>
  </main>
  <footer>
    <p>&copy; %d %s. All rights reserved.</p>
  </footer>
</body>
</html>`,
		title, company, g.randWords(5),
		r.Host, r.URL.Path,
		title,
		links.String(),
		paragraphs.String(),
		g.randTitle(),
		time.Now().Format(time.RFC3339), rand.Intn(100000),
		90+rand.Intn(10), rand.Intn(200)+5, rand.Intn(10000)+100,
		time.Now().Year(), company)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (g *Generator) generateJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	numItems := rand.Intn(20) + 1
	items := make([]map[string]interface{}, numItems)
	for i := range items {
		items[i] = map[string]interface{}{
			"id":          rand.Intn(100000),
			"name":        g.randTitle(),
			"description": g.randWords(5),
			"status":      []string{"active", "pending", "inactive", "archived"}[rand.Intn(4)],
			"created_at":  time.Now().Add(-time.Duration(rand.Intn(365*24)) * time.Hour).Format(time.RFC3339),
			"metrics": map[string]interface{}{
				"views":       rand.Intn(10000),
				"conversions": rand.Intn(500),
				"score":       rand.Float64() * 100,
			},
			"tags": []string{g.randWords(1), g.randWords(1)},
		}
	}

	resp := map[string]interface{}{
		"data": items,
		"meta": map[string]interface{}{
			"total":     numItems + rand.Intn(100),
			"page":      1,
			"per_page":  numItems,
			"timestamp": time.Now().Unix(),
			"request":   r.URL.Path,
		},
		"links": map[string]string{
			"self":  r.URL.Path,
			"next":  r.URL.Path + "?page=2",
			"prev":  "",
			"first": r.URL.Path + "?page=1",
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (g *Generator) generatePlain(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	var sb strings.Builder
	sb.WriteString("=== System Report ===\n\n")
	for i := 0; i < rand.Intn(20)+5; i++ {
		sb.WriteString(fmt.Sprintf("[%s] %s: %s — value=%d status=%s\n",
			time.Now().Add(-time.Duration(i)*time.Minute).Format("15:04:05"),
			g.randTitle(), g.randWords(3),
			rand.Intn(1000),
			[]string{"OK", "WARN", "ERR", "CRIT"}[rand.Intn(4)]))
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
}

func (g *Generator) generateXML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString("<response>\n")
	sb.WriteString(fmt.Sprintf("  <timestamp>%s</timestamp>\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("  <items>\n")
	for i := 0; i < rand.Intn(10)+3; i++ {
		sb.WriteString(fmt.Sprintf("    <item id=\"%d\">\n", rand.Intn(10000)))
		sb.WriteString(fmt.Sprintf("      <name>%s</name>\n", g.randTitle()))
		sb.WriteString(fmt.Sprintf("      <value>%d</value>\n", rand.Intn(1000)))
		sb.WriteString(fmt.Sprintf("      <status>%s</status>\n",
			[]string{"active", "inactive", "pending"}[rand.Intn(3)]))
		sb.WriteString("    </item>\n")
	}
	sb.WriteString("  </items>\n")
	sb.WriteString("</response>")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
}

func (g *Generator) generateCSV(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=export.csv")
	var sb strings.Builder
	sb.WriteString("id,name,category,value,timestamp,status\n")
	for i := 0; i < rand.Intn(50)+10; i++ {
		sb.WriteString(fmt.Sprintf("%d,%s,%s,%d,%s,%s\n",
			i+1, g.randTitle(), g.randWords(1),
			rand.Intn(10000),
			time.Now().Add(-time.Duration(rand.Intn(24*30))*time.Hour).Format(time.RFC3339),
			[]string{"active", "closed", "pending"}[rand.Intn(3)]))
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
}

func (g *Generator) generateMarkdown(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/markdown")
	var sb strings.Builder
	title := g.randTitle()
	sb.WriteString(fmt.Sprintf("# %s\n\n", title))
	sb.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("## Overview\n\n%s.\n\n", g.randWords(12)))
	sb.WriteString("## Key Metrics\n\n")
	sb.WriteString("| Metric | Value | Status |\n|--------|-------|--------|\n")
	for i := 0; i < rand.Intn(8)+3; i++ {
		sb.WriteString(fmt.Sprintf("| %s | %d | %s |\n",
			g.randTitle(), rand.Intn(1000),
			[]string{"OK", "Warning", "Critical"}[rand.Intn(3)]))
	}
	sb.WriteString(fmt.Sprintf("\n## Details\n\n%s.\n", g.randWords(20)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
}

func (g *Generator) generateSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)

	numEvents := rand.Intn(10) + 3
	for i := 0; i < numEvents; i++ {
		eventType := []string{"update", "metric", "alert", "heartbeat"}[rand.Intn(4)]
		data := fmt.Sprintf(`{"type":"%s","value":%d,"ts":%d}`, eventType, rand.Intn(1000), time.Now().UnixMilli())
		fmt.Fprintf(w, "event: %s\ndata: %s\nid: %d\n\n", eventType, data, i)
		if ok {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rand.Intn(500)+100) * time.Millisecond)
	}
}

func (g *Generator) generateChunked(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, ok := w.(http.Flusher)

	chunks := rand.Intn(8) + 3
	for i := 0; i < chunks; i++ {
		w.Write([]byte(fmt.Sprintf("Chunk %d/%d: %s\n", i+1, chunks, g.randWords(5))))
		if ok {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rand.Intn(300)+50) * time.Millisecond)
	}
}
