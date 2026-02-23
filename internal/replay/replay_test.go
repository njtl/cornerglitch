package replay

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// writePCAPFile creates a minimal valid pcap file with HTTP request packets.
func writePCAPFile(t *testing.T, path string, requests []struct{ method, urlPath string }) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Global header (24 bytes).
	ghdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(ghdr[0:4], 0xa1b2c3d4)  // magic
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)            // version major
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)            // version minor
	binary.LittleEndian.PutUint32(ghdr[8:12], 0)           // thiszone
	binary.LittleEndian.PutUint32(ghdr[12:16], 0)          // sigfigs
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)      // snaplen
	binary.LittleEndian.PutUint32(ghdr[20:24], 1)          // network (Ethernet)
	f.Write(ghdr)

	now := time.Now()
	for i, req := range requests {
		httpPayload := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\n", req.method, req.urlPath))

		// Fake headers: 14 (eth) + 20 (ip) + 20 (tcp) = 54 bytes
		fakeHeaders := make([]byte, 54)
		// Set EtherType to IPv4.
		binary.BigEndian.PutUint16(fakeHeaders[12:14], 0x0800)
		// IPv4: version=4, IHL=5.
		fakeHeaders[14] = 0x45
		// Protocol: TCP.
		fakeHeaders[14+9] = 6
		// TCP data offset: 5 (20 bytes).
		fakeHeaders[34+12] = 0x50

		totalLen := len(fakeHeaders) + len(httpPayload)

		// Record header (16 bytes).
		ts := now.Add(time.Duration(i) * 100 * time.Millisecond)
		recHdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(recHdr[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(recHdr[4:8], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(recHdr[8:12], uint32(totalLen))
		binary.LittleEndian.PutUint32(recHdr[12:16], uint32(totalLen))

		f.Write(recHdr)
		f.Write(fakeHeaders)
		f.Write(httpPayload)
	}
}

func TestLoadPCAP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	reqs := []struct{ method, urlPath string }{
		{"GET", "/"},
		{"GET", "/api/users"},
		{"POST", "/api/login"},
	}
	writePCAPFile(t, path, reqs)

	packets, err := LoadPCAP(path)
	if err != nil {
		t.Fatalf("LoadPCAP: %v", err)
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	if packets[0].Method != "GET" || packets[0].Path != "/" {
		t.Errorf("packet 0: got %s %s, want GET /", packets[0].Method, packets[0].Path)
	}
	if packets[1].Method != "GET" || packets[1].Path != "/api/users" {
		t.Errorf("packet 1: got %s %s, want GET /api/users", packets[1].Method, packets[1].Path)
	}
	if packets[2].Method != "POST" || packets[2].Path != "/api/login" {
		t.Errorf("packet 2: got %s %s, want POST /api/login", packets[2].Method, packets[2].Path)
	}

	for i, pkt := range packets {
		if !pkt.IsRequest {
			t.Errorf("packet %d: expected IsRequest=true", i)
		}
		if pkt.Host != "localhost" {
			t.Errorf("packet %d: host=%q, want 'localhost'", i, pkt.Host)
		}
	}
}

func TestLoadPCAP_InvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pcap")
	os.WriteFile(path, []byte("not a pcap file here"), 0o644)

	_, err := LoadPCAP(path)
	if err == nil {
		t.Fatal("expected error for invalid pcap magic")
	}
}

func TestLoadJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	lines := `{"type":"request","method":"GET","path":"/","host":"localhost","timestamp":"2026-02-23T12:00:00Z"}
{"type":"request","method":"POST","path":"/api/data","host":"localhost","timestamp":"2026-02-23T12:00:01Z","body":"hello"}
{"type":"response","status_code":200,"timestamp":"2026-02-23T12:00:01Z"}
`
	os.WriteFile(path, []byte(lines), 0o644)

	packets, err := LoadJSONL(path)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	if packets[0].Method != "GET" || packets[0].Path != "/" {
		t.Errorf("packet 0: %s %s", packets[0].Method, packets[0].Path)
	}
	if packets[1].Method != "POST" || string(packets[1].Body) != "hello" {
		t.Errorf("packet 1: %s body=%q", packets[1].Method, packets[1].Body)
	}
	if packets[2].IsRequest {
		t.Error("packet 2 should be a response")
	}
	if packets[2].StatusCode != 200 {
		t.Errorf("packet 2 status: %d", packets[2].StatusCode)
	}
}

func TestLoadFile_AutoDetect(t *testing.T) {
	dir := t.TempDir()

	// Test pcap auto-detect.
	pcapPath := filepath.Join(dir, "test.pcap")
	writePCAPFile(t, pcapPath, []struct{ method, urlPath string }{{"GET", "/test"}})

	packets, err := LoadFile(pcapPath)
	if err != nil {
		t.Fatalf("LoadFile pcap: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	// Test unsupported format.
	_, err = LoadFile(filepath.Join(dir, "test.txt"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestPlayerBurst(t *testing.T) {
	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()
	packets := []*Packet{
		{Timestamp: now, Method: "GET", Path: "/a", IsRequest: true, Headers: map[string]string{}},
		{Timestamp: now.Add(time.Second), Method: "GET", Path: "/b", IsRequest: true, Headers: map[string]string{}},
		{Timestamp: now.Add(2 * time.Second), Method: "POST", Path: "/c", IsRequest: true, Headers: map[string]string{}},
		{Timestamp: now.Add(3 * time.Second), Method: "GET", Path: "/d", IsRequest: false, StatusCode: 200}, // response, should be skipped
	}

	player := NewPlayer(packets, Config{TimingMode: "burst"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := player.Play(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Play: %v", err)
	}

	if got := requestCount.Load(); got != 3 {
		t.Errorf("expected 3 requests, got %d", got)
	}

	stats := player.GetStats()
	if stats.PacketsPlayed != 3 {
		t.Errorf("stats.PacketsPlayed=%d, want 3", stats.PacketsPlayed)
	}
	if stats.PacketsLoaded != 4 {
		t.Errorf("stats.PacketsLoaded=%d, want 4", stats.PacketsLoaded)
	}
}

func TestPlayerFilterPath(t *testing.T) {
	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()
	packets := []*Packet{
		{Timestamp: now, Method: "GET", Path: "/api/users", IsRequest: true, Headers: map[string]string{}},
		{Timestamp: now, Method: "GET", Path: "/static/style.css", IsRequest: true, Headers: map[string]string{}},
		{Timestamp: now, Method: "GET", Path: "/api/products", IsRequest: true, Headers: map[string]string{}},
	}

	player := NewPlayer(packets, Config{TimingMode: "burst", FilterPath: "/api/"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := player.Play(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Play: %v", err)
	}

	if got := requestCount.Load(); got != 2 {
		t.Errorf("expected 2 filtered requests, got %d", got)
	}
}

func TestPlayerStop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()
	var packets []*Packet
	for i := 0; i < 100; i++ {
		packets = append(packets, &Packet{
			Timestamp: now.Add(time.Duration(i) * 100 * time.Millisecond),
			Method:    "GET",
			Path:      fmt.Sprintf("/page/%d", i),
			IsRequest: true,
			Headers:   map[string]string{},
		})
	}

	player := NewPlayer(packets, Config{TimingMode: "exact", Speed: 1.0})

	go func() {
		time.Sleep(300 * time.Millisecond)
		player.Stop()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	player.Play(ctx, ts.URL)

	stats := player.GetStats()
	// Should have been stopped before playing all 100 packets.
	if stats.PacketsPlayed >= 100 {
		t.Errorf("expected fewer than 100 packets played after stop, got %d", stats.PacketsPlayed)
	}
}
