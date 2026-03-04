package budgettrap

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ServeStreamingBait serves a slow-drip HTML page that sends content in chunks
// over several minutes, keeping scanner connections occupied and draining budgets.
// The response has no Content-Length, forcing clients to wait for the stream to end.
func ServeStreamingBait(w http.ResponseWriter, r *http.Request) (int, string) {
	rng := rand.New(rand.NewSource(pathSeed(r.URL.Path)))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	if !canFlush {
		// Fallback: write entire page at once
		w.Write([]byte(generateFullPage(rng)))
		return http.StatusOK, "streaming_bait"
	}

	// First chunk: HTML head + opening body (immediate)
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Loading...</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #1e293b; line-height: 1.6; }
    h1 { color: #0f172a; margin-bottom: 20px; }
    .content p { margin-bottom: 16px; }
    .loading { color: #64748b; font-style: italic; }
    footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 0.85em; }
  </style>
</head>
<body>
<h1>` + streamingTitle(rng) + `</h1>
<div class="content">
`))
	flusher.Flush()

	// Drip content chunks
	maxChunks := 50
	deadline := time.After(10 * time.Minute)

	for i := 0; i < maxChunks; i++ {
		// Wait 3-10 seconds between chunks
		delay := time.Duration(3+rng.Intn(8)) * time.Second
		select {
		case <-deadline:
			goto finish
		case <-r.Context().Done():
			return http.StatusOK, "streaming_bait"
		case <-time.After(delay):
		}

		chunk := streamingChunk(rng, i+1)
		_, err := w.Write([]byte(chunk))
		if err != nil {
			return http.StatusOK, "streaming_bait"
		}
		flusher.Flush()
	}

finish:
	// Closing tags
	w.Write([]byte(`</div>
<footer>
  <p>&copy; 2025 Acme Corporation. Content generated dynamically.</p>
  <p><a href="/sitemap.xml">Sitemap</a> | <a href="/privacy">Privacy</a> | <a href="/terms">Terms</a></p>
</footer>
<script>
  fetch('/api/v1/users/me').then(r => r.json()).catch(() => {});
  fetch('/api/v1/content/related?path=' + encodeURIComponent(location.pathname)).then(r => r.json()).catch(() => {});
</script>
</body>
</html>`))
	flusher.Flush()

	return http.StatusOK, "streaming_bait"
}

func streamingTitle(rng *rand.Rand) string {
	titles := []string{
		"Comprehensive Analysis Report",
		"System Architecture Overview",
		"Performance Benchmark Results",
		"Infrastructure Audit Summary",
		"Security Assessment Findings",
		"Data Migration Status Report",
		"Compliance Verification Results",
		"Capacity Planning Analysis",
	}
	return titles[rng.Intn(len(titles))]
}

func streamingChunk(rng *rand.Rand, section int) string {
	templates := []string{
		"Our analysis of %s across %s environments reveals that %s approaches consistently outperform traditional %s methods. The %s framework demonstrates a clear advantage when deployed alongside %s infrastructure, particularly in scenarios involving %s workloads.",
		"Section %d examines the relationship between %s and %s in production environments. Key findings indicate that %s configurations paired with %s monitoring achieve superior %s metrics compared to baseline deployments.",
		"The %s evaluation methodology was applied to %s systems operating under %s conditions. Results confirm that %s optimization techniques, when combined with %s strategies, yield measurable improvements in %s throughput and %s latency.",
		"Cross-referencing %s data with %s benchmarks from the previous quarter shows a trend toward %s architectures. Teams adopting %s practices report fewer %s incidents and improved %s satisfaction scores.",
		"Investigation into %s failure modes during the %s stress test revealed that %s resilience depends heavily on %s configuration. The %s mitigation strategy reduced %s events by a significant margin while maintaining %s compliance.",
	}

	t := templates[rng.Intn(len(templates))]
	result := t
	for strings.Contains(result, "%s") {
		choices := []string{
			streamingNouns[rng.Intn(len(streamingNouns))],
			streamingAdjectives[rng.Intn(len(streamingAdjectives))],
		}
		result = strings.Replace(result, "%s", choices[rng.Intn(len(choices))], 1)
	}
	for strings.Contains(result, "%d") {
		result = strings.Replace(result, "%d", fmt.Sprintf("%d", section), 1)
	}

	return fmt.Sprintf(`<p>Section %d: %s</p>`+"\n", section, result)
}

// generateFullPage builds the entire streaming page at once (fallback for no Flusher).
func generateFullPage(rng *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>%s</title>
  <style>body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }</style>
</head>
<body>
<h1>%s</h1>
<div class="content">
`, streamingTitle(rng), streamingTitle(rng)))

	numChunks := 30 + rng.Intn(21)
	for i := 1; i <= numChunks; i++ {
		sb.WriteString(streamingChunk(rng, i))
	}

	sb.WriteString(`</div>
<footer><p>&copy; 2025 Acme Corporation.</p></footer>
</body>
</html>`)
	return sb.String()
}

var streamingNouns = []string{
	"infrastructure", "deployment", "orchestration", "monitoring", "provisioning",
	"authentication", "authorization", "encryption", "caching", "replication",
	"clustering", "sharding", "load balancing", "failover", "throughput",
	"latency", "availability", "durability", "consistency", "partition tolerance",
}

var streamingAdjectives = []string{
	"distributed", "containerized", "automated", "resilient", "scalable",
	"cloud-native", "event-driven", "microservice-based", "serverless", "hybrid",
	"multi-region", "fault-tolerant", "high-availability", "zero-downtime", "observability-first",
}
