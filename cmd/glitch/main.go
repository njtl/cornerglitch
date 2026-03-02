package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/analytics"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/apichaos"
	"github.com/glitchWebServer/internal/audit"
	"github.com/glitchWebServer/internal/botdetect"
	"github.com/glitchWebServer/internal/captcha"
	"github.com/glitchWebServer/internal/cdn"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/cookies"
	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/email"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/framework"
	"github.com/glitchWebServer/internal/headers"
	"github.com/glitchWebServer/internal/health"
	"github.com/glitchWebServer/internal/honeypot"
	"github.com/glitchWebServer/internal/i18n"
	"github.com/glitchWebServer/internal/jstrap"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/media"
	"github.com/glitchWebServer/internal/mediachaos"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/oauth"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/privacy"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/search"
	"github.com/glitchWebServer/internal/selftest"
	"github.com/glitchWebServer/internal/spider"
	"github.com/glitchWebServer/internal/server"
	"github.com/glitchWebServer/internal/vuln"
	"github.com/glitchWebServer/internal/websocket"
)

// loadEnvFile reads a .env file and sets environment variables that are not
// already set in the environment. This ensures explicit env vars and CLI flags
// always take precedence over .env file values.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // .env is optional
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// Remove surrounding quotes if present.
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		// Don't override existing environment variables.
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}

func main() {
	// Auto-load .env file (won't override existing env vars).
	loadEnvFile(".env")

	// Check for subcommands before flag parsing.
	if len(os.Args) > 1 && os.Args[1] == "selftest" {
		if err := selftest.RunCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	port := flag.Int("port", 8765, "Server port")
	dashPort := flag.Int("dash-port", 8766, "Dashboard/metrics port")
	configFile := flag.String("config", "", "Path to config JSON file to import on startup")
	adminPass := flag.String("admin-password", "", "Admin panel password (env: GLITCH_ADMIN_PASSWORD)")
	dbURL := flag.String("db-url", "", "PostgreSQL connection URL (env: GLITCH_DB_URL)")
	flag.Parse()

	// Configure admin password.
	pw := *adminPass
	if pw == "" {
		pw = os.Getenv("GLITCH_ADMIN_PASSWORD")
	}
	if pw != "" {
		dashboard.SetAdminPassword(pw)
	}

	// Initialize PostgreSQL storage (optional — graceful degradation).
	dbConn := *dbURL
	if dbConn == "" {
		dbConn = os.Getenv("GLITCH_DB_URL")
	}
	if dbConn != "" {
		if err := dashboard.InitStorage(dbConn); err != nil {
			log.Printf("\033[33m[glitch]\033[0m Storage init warning: %v", err)
		} else {
			log.Printf("\033[36m[glitch]\033[0m PostgreSQL connected")
		}
	} else {
		log.Printf("\033[33m[glitch]\033[0m No GLITCH_DB_URL set — running without database persistence")
	}

	// Initialize audit logger (after storage, before config load).
	var auditStore audit.AuditStore
	if store := dashboard.GetStore(); store != nil {
		auditStore = store
	}
	audit.Init(auditStore)

	// Set up auto-save state file.
	dashboard.SetStateFile(".glitch-state.json")

	// Import config: explicit file takes priority, otherwise auto-load state.
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read config file %s: %v", *configFile, err)
		}
		var export dashboard.ConfigExport
		if err := json.Unmarshal(data, &export); err != nil {
			log.Fatalf("Failed to parse config file %s: %v", *configFile, err)
		}
		dashboard.ImportConfig(&export)
		log.Printf("\033[36m[glitch]\033[0m Imported config from %s (version: %s)", *configFile, export.Version)
	} else {
		dashboard.LoadStateFile()
	}

	// Restore scan history from DB if available.
	dashboard.LoadBuiltinScanHistory()

	collector := metrics.NewCollector()
	dashboard.RestoreMetrics(collector)
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	errGen := errors.NewGenerator()
	pageGen := pages.NewGenerator()
	lab := labyrinth.NewLabyrinth()
	contentEng := content.NewEngine()
	apiRouter := api.NewRouter()
	honey := honeypot.NewHoneypot()
	fw := framework.NewEmulator()
	captchaEng := captcha.NewEngine()
	vulnH := vuln.NewHandler()
	analytix := analytics.NewEngine()
	cdnEng := cdn.NewEngine()
	oauthH := oauth.NewHandler()
	privacyH := privacy.NewHandler()
	wsH := websocket.NewHandler()
	rec := recorder.NewRecorder("captures")
	searchH := search.NewHandler()
	emailH := email.NewHandler()
	healthH := health.NewHandler(time.Now())
	i18nH := i18n.NewHandler()
	headerEng := headers.NewEngine()
	cookieT := cookies.NewTracker()
	jsEng := jstrap.NewEngine()
	botDet := botdetect.NewDetector()
	spiderCfg := spider.NewConfig()
	dashboard.SetSpiderConfig(spiderCfg)
	dashboard.SetRecorder(rec)
	dashboard.InitScanRunner(*port, *dashPort)
	dashboard.LoadExternalScanHistory()
	spiderH := spider.NewHandler(spiderCfg)
	apiChaosEng := apichaos.New()
	mediaGen := media.New()
	mediaChaosEng := mediachaos.New()

	handler := server.NewHandler(collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter, honey, fw, captchaEng, vulnH, analytix, cdnEng, oauthH, privacyH, wsH, rec, searchH, emailH, healthH, i18nH, headerEng, cookieT, jsEng, botDet, spiderH, apiChaosEng, mediaGen, mediaChaosEng)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler.ServeHTTP)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	dashSrv := dashboard.NewServer(collector, fp, adapt, *dashPort)
	stopSnapshotter := dashboard.StartMetricsSnapshotter(collector)

	go func() {
		log.Printf("\033[36m[glitch]\033[0m Dashboard listening on :%d", *dashPort)
		if err := dashSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Dashboard server error: %v", err)
		}
	}()

	go func() {
		log.Printf("\033[36m[glitch]\033[0m Server listening on :%d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	audit.LogSystem("system.start", "system.lifecycle", map[string]interface{}{"port": *port, "dash_port": *dashPort})

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("\033[33m[glitch]\033[0m Shutting down...")
	audit.LogSystem("system.stop", "system.lifecycle", nil)
	stopSnapshotter()
	// Final metrics save before shutdown.
	dashboard.SaveMetricsNow(collector)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	dashSrv.Shutdown(ctx)
	botDet.Stop()
	contentEng.Stop()
	if l := audit.GetLogger(); l != nil {
		l.Close()
	}
	if store := dashboard.GetStore(); store != nil {
		store.Close()
	}
	log.Println("\033[32m[glitch]\033[0m Stopped.")
}
