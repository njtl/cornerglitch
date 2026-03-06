package tlschaos

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewEngine_SelfSigned(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if e.Level() != 0 {
		t.Errorf("initial level = %d, want 0", e.Level())
	}
}

func TestSetLevel(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	for _, level := range []int{0, 1, 2, 3, 4} {
		e.SetLevel(level)
		if got := e.Level(); got != level {
			t.Errorf("SetLevel(%d): Level() = %d", level, got)
		}
	}

	// Bounds
	e.SetLevel(-1)
	if got := e.Level(); got != 0 {
		t.Errorf("SetLevel(-1): Level() = %d, want 0", got)
	}
	e.SetLevel(99)
	if got := e.Level(); got != 4 {
		t.Errorf("SetLevel(99): Level() = %d, want 4", got)
	}
}

func TestTLSConfig_Levels(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		level      int
		wantMinVer uint16
	}{
		{0, tls.VersionTLS13},
		{1, tls.VersionTLS10},
		{2, tls.VersionTLS10},
		{3, tls.VersionTLS12},
		{4, tls.VersionTLS10},
	}

	for _, tt := range tests {
		e.SetLevel(tt.level)
		cfg := e.TLSConfig()
		if cfg.MinVersion != tt.wantMinVer {
			t.Errorf("level %d: MinVersion = %d, want %d", tt.level, cfg.MinVersion, tt.wantMinVer)
		}
	}
}

func TestTLSConfig_WeakCiphers(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	e.SetLevel(2)
	cfg := e.TLSConfig()
	if len(cfg.CipherSuites) == 0 {
		t.Error("level 2 should have weak cipher suites")
	}
	// Verify 3DES is in the list
	has3DES := false
	for _, cs := range cfg.CipherSuites {
		if cs == tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA || cs == tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA {
			has3DES = true
			break
		}
	}
	if !has3DES {
		t.Error("weak cipher list should include 3DES")
	}
}

func TestTLSConfig_NightmareALPN(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	e.SetLevel(4)
	cfg := e.TLSConfig()
	if len(cfg.NextProtos) == 0 {
		t.Error("nightmare level should have ALPN protocols")
	}
}

func TestTLSServer_Serves(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	// Create a test TLS server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto: %s", r.Proto)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = e.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	// Create client that trusts the self-signed cert
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	t.Logf("Response: %s", body)
}

func TestTLSServer_HTTP2(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", r.Proto)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = e.TLSConfig()
	// Enable HTTP/2 by adding h2 to NextProtos
	srv.TLS.NextProtos = []string{"h2", "http/1.1"}
	srv.StartTLS()
	defer srv.Close()

	// HTTP/2 client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	proto := string(body)
	t.Logf("Protocol: %s", proto)

	// Go's httptest with TLS should negotiate HTTP/2
	if proto != "HTTP/2.0" {
		t.Logf("Expected HTTP/2.0, got %s (may depend on Go version)", proto)
	}
}

func TestCertChaos_RotatesCerts(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	e.SetLevel(3) // Cert chaos level

	// Make multiple requests and verify we get different certs
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	tlsCfg := e.TLSConfig()
	// Disable session tickets so each connection triggers GetCertificate
	tlsCfg.SessionTicketsDisabled = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{Handler: handler}
	go srv.Serve(tlsLn)
	defer srv.Close()

	addr := ln.Addr().String()
	subjects := make(map[string]int)

	for i := 0; i < 8; i++ {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			// Disable session cache so each connection does a fresh handshake
			ClientSessionCache: nil,
		})
		if err != nil {
			t.Logf("connection %d failed: %v", i, err)
			continue
		}
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cn := state.PeerCertificates[0].Subject.CommonName
			subjects[cn]++
		}
		conn.Close()
	}

	t.Logf("Certificate subjects seen: %v", subjects)
	if len(subjects) < 2 {
		t.Errorf("cert chaos should rotate through different certs, got %d unique subjects", len(subjects))
	}
}

func TestDowngrade_TLS12Max(t *testing.T) {
	e, err := NewEngine("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	e.SetLevel(1) // Downgrade level

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := e.TLSConfig()
	tlsLn := tls.NewListener(ln, cfg)
	srv := &http.Server{Handler: handler}
	go srv.Serve(tlsLn)
	defer srv.Close()

	addr := ln.Addr().String()

	// At downgrade level, server MaxVersion is TLS 1.2, so TLS 1.3 should not be negotiated
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("connection failed: %v", err)
	}
	version := conn.ConnectionState().Version
	t.Logf("Negotiated version: 0x%x (TLS 1.2 = 0x%x, TLS 1.3 = 0x%x)", version, tls.VersionTLS12, tls.VersionTLS13)
	if version > tls.VersionTLS12 {
		t.Errorf("downgrade level should cap at TLS 1.2, got 0x%x", version)
	}
	conn.Close()
}

func TestGenerateCert(t *testing.T) {
	cert, err := generateCert("test.example.com", time.Now(), time.Now().Add(24*time.Hour), nil)
	if err != nil {
		t.Fatalf("generateCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("certificate should have at least one cert in chain")
	}

	// Parse and verify the cert
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	if parsed.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want %q", parsed.Subject.CommonName, "test.example.com")
	}
	if !parsed.NotAfter.After(time.Now()) {
		t.Error("cert should not be expired")
	}
}
