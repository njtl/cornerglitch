package budgettrap

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// InjectBreadcrumbHeaders adds fake debug/server headers that make the response
// look like a misconfigured production server, enticing scanners to dig deeper.
func InjectBreadcrumbHeaders(w http.ResponseWriter, rng *rand.Rand) {
	// X-Powered-By: random PHP/ASP version
	poweredBy := []string{
		"PHP/5.4.0", "PHP/7.2.1", "PHP/7.4.3", "PHP/8.0.0",
		"ASP.NET/4.0", "ASP.NET/4.5",
	}
	w.Header().Set("X-Powered-By", poweredBy[rng.Intn(len(poweredBy))])

	// Server: random web server
	servers := []string{
		"Apache/2.2.14 (Ubuntu)", "Apache/2.4.41 (Ubuntu)",
		"nginx/1.14.0", "nginx/1.18.0",
		"Microsoft-IIS/8.5", "Microsoft-IIS/10.0",
	}
	w.Header().Set("Server", servers[rng.Intn(len(servers))])

	// X-Debug-Trace: fake trace ID
	w.Header().Set("X-Debug-Trace", fmt.Sprintf("trace-%08x-%04x-%04x",
		rng.Uint32(), rng.Intn(0xFFFF), rng.Intn(0xFFFF)))

	// X-Request-ID: fake UUID
	w.Header().Set("X-Request-ID", fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		rng.Uint32(), rng.Intn(0xFFFF), rng.Intn(0xFFFF),
		rng.Intn(0xFFFF), rng.Int63n(0xFFFFFFFFFFFF)))

	// Sometimes add ASP.NET version header
	if rng.Float64() < 0.4 {
		w.Header().Set("X-AspNet-Version", "4.0.30319")
	}

	// Sometimes add a backend routing header
	if rng.Float64() < 0.3 {
		backends := []string{"web-01", "web-02", "app-server-3", "backend-prod-1"}
		w.Header().Set("X-Backend-Server", backends[rng.Intn(len(backends))])
	}
}

// GenerateBreadcrumbHTML returns an HTML snippet containing fake debug information
// that scanners will find enticing: error comments, hidden forms, meta tags.
func GenerateBreadcrumbHTML(rng *rand.Rand) string {
	var sb strings.Builder

	// PHP-style error comment
	files := []string{
		"/var/www/app/models/User.php",
		"/var/www/app/controllers/AuthController.php",
		"/var/www/html/includes/db.php",
		"/opt/app/lib/session_handler.rb",
		"/srv/www/api/middleware/auth.py",
	}
	lines := []int{42, 87, 142, 203, 315, 419, 567}
	sb.WriteString(fmt.Sprintf("<!-- Error in %s line %d -->",
		files[rng.Intn(len(files))], lines[rng.Intn(len(lines))]))

	// Hidden form with fake CSRF token
	sb.WriteString(fmt.Sprintf(`<form style="display:none" action="/api/internal/update" method="POST"><input type="hidden" name="_csrf" value="%08x%08x%08x%08x"/></form>`,
		rng.Uint32(), rng.Uint32(), rng.Uint32(), rng.Uint32()))

	// Meta tag with fake git commit hash
	sb.WriteString(fmt.Sprintf(`<meta name="version" content="build-%08x"/>`, rng.Uint32()))

	// Commented-out SQL debug query
	tables := []string{"users", "sessions", "accounts", "api_keys", "permissions"}
	columns := []string{"role='admin'", "active=1", "level>5", "type='superuser'"}
	sb.WriteString(fmt.Sprintf("<!-- DEBUG: SELECT * FROM %s WHERE %s -->",
		tables[rng.Intn(len(tables))], columns[rng.Intn(len(columns))]))

	// Fake stack trace comment (sometimes)
	if rng.Float64() < 0.5 {
		sb.WriteString(fmt.Sprintf("<!-- Stack: %s:%d -> %s:%d -->",
			files[rng.Intn(len(files))], rng.Intn(500)+1,
			files[rng.Intn(len(files))], rng.Intn(500)+1))
	}

	// Hidden link to fake internal endpoint (sometimes)
	if rng.Float64() < 0.4 {
		endpoints := []string{
			"/api/internal/debug", "/admin/phpinfo", "/.env.backup",
			"/api/v1/users?admin=true", "/config/database.yml",
		}
		sb.WriteString(fmt.Sprintf(`<a href="%s" style="display:none">internal</a>`,
			endpoints[rng.Intn(len(endpoints))]))
	}

	return sb.String()
}
