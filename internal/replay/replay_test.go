package replay

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// ---------------------------------------------------------------------------
// ParseMetadata tests
// ---------------------------------------------------------------------------

func TestParseMetadata_Empty(t *testing.T) {
	meta := ParseMetadata(nil)
	if meta["total_packets"].(int) != 0 {
		t.Errorf("total_packets should be 0 for nil input, got %v", meta["total_packets"])
	}
	if meta["total_requests"].(int) != 0 {
		t.Errorf("total_requests should be 0, got %v", meta["total_requests"])
	}
}

func TestParseMetadata_Mixed(t *testing.T) {
	now := time.Date(2026, 2, 23, 12, 0, 0, 0, time.UTC)
	packets := []*Packet{
		{Timestamp: now, Method: "GET", Path: "/", Host: "example.com", IsRequest: true,
			Headers: map[string]string{"User-Agent": "test"}},
		{Timestamp: now.Add(100 * time.Millisecond), Method: "GET", Path: "/api/users", Host: "example.com", IsRequest: true,
			Headers: map[string]string{}},
		{Timestamp: now.Add(200 * time.Millisecond), Method: "POST", Path: "/api/login", Host: "api.example.com", IsRequest: true,
			Headers: map[string]string{}, Body: []byte(`{"user":"test"}`)},
		{Timestamp: now.Add(300 * time.Millisecond), Method: "GET", Path: "/", Host: "example.com", IsRequest: true,
			Headers: map[string]string{}},
		{Timestamp: now.Add(150 * time.Millisecond), IsRequest: false, StatusCode: 200,
			Headers: map[string]string{}},
		{Timestamp: now.Add(250 * time.Millisecond), IsRequest: false, StatusCode: 404,
			Headers: map[string]string{}},
	}

	meta := ParseMetadata(packets)

	if meta["total_packets"].(int) != 6 {
		t.Errorf("total_packets: got %v, want 6", meta["total_packets"])
	}
	if meta["total_requests"].(int) != 4 {
		t.Errorf("total_requests: got %v, want 4", meta["total_requests"])
	}
	if meta["total_responses"].(int) != 2 {
		t.Errorf("total_responses: got %v, want 2", meta["total_responses"])
	}

	methods := meta["methods"].(map[string]int)
	if methods["GET"] != 3 {
		t.Errorf("methods[GET]: got %d, want 3", methods["GET"])
	}
	if methods["POST"] != 1 {
		t.Errorf("methods[POST]: got %d, want 1", methods["POST"])
	}

	statusCodes := meta["status_codes"].(map[int]int)
	if statusCodes[200] != 1 {
		t.Errorf("status_codes[200]: got %d, want 1", statusCodes[200])
	}
	if statusCodes[404] != 1 {
		t.Errorf("status_codes[404]: got %d, want 1", statusCodes[404])
	}

	hosts := meta["unique_hosts"].([]string)
	if len(hosts) != 2 {
		t.Errorf("unique_hosts count: got %d, want 2", len(hosts))
	}

	uniquePaths := meta["unique_paths"].(int)
	if uniquePaths != 3 {
		t.Errorf("unique_paths: got %d, want 3", uniquePaths)
	}

	topPaths := meta["top_paths"].([]map[string]interface{})
	if len(topPaths) != 3 {
		t.Errorf("top_paths count: got %d, want 3", len(topPaths))
	}
	// "/" should be first (count=2)
	if topPaths[0]["path"].(string) != "/" || topPaths[0]["count"].(int) != 2 {
		t.Errorf("top_paths[0]: got %v, want / with count 2", topPaths[0])
	}

	timeSpanMs := meta["time_span_ms"].(int64)
	if timeSpanMs != 300 {
		t.Errorf("time_span_ms: got %d, want 300", timeSpanMs)
	}

	if meta["time_start"].(string) == "" {
		t.Error("time_start should not be empty")
	}
	if meta["time_end"].(string) == "" {
		t.Error("time_end should not be empty")
	}

	protocols := meta["protocols"].([]string)
	if len(protocols) != 1 || protocols[0] != "HTTP/1.1" {
		t.Errorf("protocols: got %v, want [HTTP/1.1]", protocols)
	}
}

func TestParseMetadata_AvgRequestSize(t *testing.T) {
	now := time.Now()
	packets := []*Packet{
		{Timestamp: now, Method: "POST", Path: "/a", IsRequest: true,
			Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte("1234567890")},
		{Timestamp: now, Method: "POST", Path: "/b", IsRequest: true,
			Headers: map[string]string{"Content-Type": "text/plain"}, Body: []byte("12345678901234567890")},
	}

	meta := ParseMetadata(packets)
	avgSize := meta["avg_request_size"].(int)
	// Each request: body size + header key+value sizes
	// Req1: 10 (body) + 12+16=28 (header) = 38
	// Req2: 20 (body) + 12+10=22 (header) = 42
	// avg = (38+42)/2 = 40
	if avgSize != 40 {
		t.Errorf("avg_request_size: got %d, want 40", avgSize)
	}
}

// ---------------------------------------------------------------------------
// LoadFromReader tests
// ---------------------------------------------------------------------------

func TestLoadFromReader_PCAP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	reqs := []struct{ method, urlPath string }{
		{"GET", "/reader-test"},
		{"POST", "/data"},
	}
	writePCAPFile(t, path, reqs)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	packets, err := LoadFromReader(bytes.NewReader(data), "test.pcap")
	if err != nil {
		t.Fatalf("LoadFromReader pcap: %v", err)
	}

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	if packets[0].Method != "GET" || packets[0].Path != "/reader-test" {
		t.Errorf("packet 0: got %s %s, want GET /reader-test", packets[0].Method, packets[0].Path)
	}
	if packets[1].Method != "POST" || packets[1].Path != "/data" {
		t.Errorf("packet 1: got %s %s, want POST /data", packets[1].Method, packets[1].Path)
	}
}

func TestLoadFromReader_JSONL(t *testing.T) {
	jsonlData := `{"type":"request","method":"GET","path":"/from-reader","host":"localhost","timestamp":"2026-02-23T12:00:00Z"}
{"type":"response","status_code":200,"timestamp":"2026-02-23T12:00:01Z"}
`
	packets, err := LoadFromReader(strings.NewReader(jsonlData), "data.jsonl")
	if err != nil {
		t.Fatalf("LoadFromReader jsonl: %v", err)
	}

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	if packets[0].Method != "GET" || packets[0].Path != "/from-reader" {
		t.Errorf("packet 0: got %s %s, want GET /from-reader", packets[0].Method, packets[0].Path)
	}
	if packets[1].StatusCode != 200 {
		t.Errorf("packet 1 status: got %d, want 200", packets[1].StatusCode)
	}
}

func TestLoadFromReader_UnsupportedFormat(t *testing.T) {
	_, err := LoadFromReader(strings.NewReader("data"), "file.txt")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention unsupported, got: %v", err)
	}
}

func TestLoadFromReader_InvalidPCAP(t *testing.T) {
	_, err := LoadFromReader(strings.NewReader("not pcap data"), "bad.pcap")
	if err == nil {
		t.Fatal("expected error for invalid pcap data")
	}
}

func TestParseMetadata_TopPathsLimit(t *testing.T) {
	// Create 15 unique paths, verify only top 10 are returned.
	now := time.Now()
	var packets []*Packet
	for i := 0; i < 15; i++ {
		path := fmt.Sprintf("/path/%d", i)
		// Give each path a different count: path/0 has 15 hits, path/14 has 1 hit.
		for j := 0; j < 15-i; j++ {
			packets = append(packets, &Packet{
				Timestamp: now,
				Method:    "GET",
				Path:      path,
				IsRequest: true,
				Headers:   map[string]string{},
			})
		}
	}

	meta := ParseMetadata(packets)
	topPaths := meta["top_paths"].([]map[string]interface{})
	if len(topPaths) != 10 {
		t.Errorf("top_paths count: got %d, want 10", len(topPaths))
	}
	// First should be /path/0 with count 15.
	if topPaths[0]["path"].(string) != "/path/0" || topPaths[0]["count"].(int) != 15 {
		t.Errorf("top_paths[0]: got %v, want /path/0 with count 15", topPaths[0])
	}
}
