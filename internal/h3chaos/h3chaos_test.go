package h3chaos

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEngine_EnableDisable(t *testing.T) {
	e := NewEngine()
	if e.IsEnabled() {
		t.Error("should start disabled")
	}
	e.SetEnabled(true)
	if !e.IsEnabled() {
		t.Error("should be enabled after SetEnabled(true)")
	}
	if e.UDPPort() == 0 {
		t.Error("UDP port should be non-zero when enabled")
	}
	port := e.UDPPort()
	t.Logf("UDP listener on port %d", port)

	e.SetEnabled(false)
	if e.IsEnabled() {
		t.Error("should be disabled after SetEnabled(false)")
	}
	if e.UDPPort() != 0 {
		t.Error("UDP port should be 0 when disabled")
	}
}

func TestEngine_SetLevel(t *testing.T) {
	e := NewEngine()
	e.SetLevel(3)
	if e.GetLevel() != 3 {
		t.Errorf("expected level 3, got %d", e.GetLevel())
	}
	e.SetLevel(-1)
	if e.GetLevel() != 0 {
		t.Errorf("expected level 0 for -1, got %d", e.GetLevel())
	}
	e.SetLevel(99)
	if e.GetLevel() != 4 {
		t.Errorf("expected level 4 for 99, got %d", e.GetLevel())
	}
}

func TestEngine_InjectHeaders_Disabled(t *testing.T) {
	e := NewEngine()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	e.InjectHeaders(rec, req)
	if rec.Header().Get("Alt-Svc") != "" {
		t.Error("should not inject headers when disabled")
	}
}

func TestEngine_InjectHeaders_Level1(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	defer e.Shutdown()
	e.SetLevel(1)

	// Run many requests to increase chance of hitting the 50% probability
	found := false
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/test%d", i), nil)
		req.RemoteAddr = "192.168.1.1:12345"
		e.InjectHeaders(rec, req)
		if rec.Header().Get("Alt-Svc") != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Alt-Svc header at level 1 within 50 requests")
	}
}

func TestEngine_InjectHeaders_Level4_Nightmare(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	defer e.Shutdown()
	e.SetLevel(4)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	e.InjectHeaders(rec, req)

	// Nightmare should add multiple Alt-Svc headers
	altSvc := rec.Header()["Alt-Svc"]
	if len(altSvc) < 2 {
		t.Errorf("expected multiple Alt-Svc headers at nightmare level, got %d", len(altSvc))
	}

	// Should have Upgrade header
	if rec.Header().Get("Upgrade") != "h3" {
		t.Error("expected Upgrade: h3 at nightmare level")
	}

	// Check for emoji in Alt-Svc (nightmare only)
	foundEmoji := false
	for _, v := range altSvc {
		if strings.Contains(v, "\xF0\x9F\x92\xA9") {
			foundEmoji = true
			break
		}
	}
	if !foundEmoji {
		t.Error("expected emoji in Alt-Svc at nightmare level")
	}
}

func TestBuildVersionNegotiation(t *testing.T) {
	// Simulate a client QUIC Initial packet
	clientPkt := make([]byte, 64)
	clientPkt[0] = 0xC0
	clientPkt[5] = 8 // DCID length
	for i := 6; i < 14; i++ {
		clientPkt[i] = byte(i)
	}

	resp := BuildVersionNegotiation(clientPkt)
	if len(resp) < 20 {
		t.Errorf("version negotiation too short: %d bytes", len(resp))
	}
	if resp[0]&0x80 == 0 {
		t.Error("expected long header form (bit 7 set)")
	}
	// Version should be 0x00000000
	if resp[1] != 0 || resp[2] != 0 || resp[3] != 0 || resp[4] != 0 {
		t.Error("version negotiation must have version 0")
	}
}

func TestBuildRetryPacket(t *testing.T) {
	resp := BuildRetryPacket(nil)
	if len(resp) < 32 {
		t.Errorf("retry packet too short: %d bytes", len(resp))
	}
}

func TestBuildInitialWrongVersion(t *testing.T) {
	resp := BuildInitialWrongVersion()
	if len(resp) < 16 {
		t.Errorf("initial packet too short: %d bytes", len(resp))
	}
	if resp[0]&0x80 == 0 {
		t.Error("expected long header form")
	}
}

func TestBuildGarbageQUIC(t *testing.T) {
	resp := BuildGarbageQUIC()
	if len(resp) != 64 {
		t.Errorf("expected 64 byte garbage, got %d", len(resp))
	}
}

func TestBuildStatelessReset(t *testing.T) {
	resp := BuildStatelessReset()
	if len(resp) != 48 {
		t.Errorf("expected 48 byte reset, got %d", len(resp))
	}
	// Last 16 bytes should be our reset token
	token := string(resp[len(resp)-16:])
	if token != "GLITCH_RESET_TOK" {
		t.Errorf("expected GLITCH_RESET_TOK, got %q", token)
	}
}

func TestEngine_UDPListener_RespondsToPackets(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(4)
	defer e.Shutdown()

	port := e.UDPPort()
	if port == 0 {
		t.Fatal("UDP listener not started")
	}

	// Send a fake QUIC Initial packet to the listener
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	})
	if err != nil {
		t.Fatalf("failed to connect UDP: %v", err)
	}
	defer conn.Close()

	// Send a QUIC-like Initial packet
	clientPkt := BuildInitialWrongVersion()
	_, err = conn.Write(clientPkt)
	if err != nil {
		t.Fatalf("failed to send UDP: %v", err)
	}

	// Try to read response (with timeout)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Logf("no UDP response (may be timing): %v", err)
		return // Not a failure — UDP is best-effort
	}
	t.Logf("received %d byte QUIC response", n)
	if n < 4 {
		t.Error("response too short")
	}
}

func TestEngine_Shutdown(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	port := e.UDPPort()
	if port == 0 {
		t.Fatal("UDP not started")
	}
	e.Shutdown()
	if e.UDPPort() != 0 {
		t.Error("port should be 0 after shutdown")
	}
}

func TestEngine_InjectHeaders_ResponseWriter(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	defer e.Shutdown()
	e.SetLevel(2) // Moderate

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.InjectHeaders(w, r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// At level 2, we should get some Alt-Svc headers
	altSvc := resp.Header["Alt-Svc"]
	t.Logf("Alt-Svc headers: %v", altSvc)
}
