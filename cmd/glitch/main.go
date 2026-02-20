package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/server"
)

func main() {
	port := flag.Int("port", 8765, "Server port")
	dashPort := flag.Int("dash-port", 8766, "Dashboard/metrics port")
	flag.Parse()

	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	errGen := errors.NewGenerator()
	pageGen := pages.NewGenerator()
	lab := labyrinth.NewLabyrinth()
	contentEng := content.NewEngine()
	apiRouter := api.NewRouter()

	handler := server.NewHandler(collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter)

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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("\033[33m[glitch]\033[0m Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	dashSrv.Shutdown(ctx)
	log.Println("\033[32m[glitch]\033[0m Stopped.")
}
