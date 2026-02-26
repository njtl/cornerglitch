package recorder

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// helper: create a Recorder with a temp directory that is cleaned up after the test.
func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	dir := t.TempDir()
	return NewRecorder(dir)
}

// --- NewRecorder ---

func TestNewRecorder_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "captures")
	rec := NewRecorder(dir)
	if rec == nil {
		t.Fatal("NewRecorder returned nil")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected directory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory, got a file")
	}
}

func TestNewRecorder_ExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	rec := NewRecorder(dir)
	if rec == nil {
		t.Fatal("NewRecorder returned nil")
	}
}

// --- IsRecording / Start / Stop ---

func TestIsRecording_InitiallyFalse(t *testing.T) {
	rec := newTestRecorder(t)
	if rec.IsRecording() {
		t.Error("expected IsRecording to be false initially")
	}
}

func TestStart_SetsRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	if !rec.IsRecording() {
		t.Error("expected IsRecording to be true after Start")
	}
}

func TestStop_ClearsRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	rec.Stop()
	if rec.IsRecording() {
		t.Error("expected IsRecording to be false after Stop")
	}
}

func TestStart_IdempotentWhenAlreadyRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	// Grab the filename from the first start
	rec.mu.Lock()
	firstFile := rec.fileName
	rec.mu.Unlock()

	// Calling Start again should be a no-op
	rec.Start()

	rec.mu.Lock()
	secondFile := rec.fileName
	rec.mu.Unlock()

	if firstFile != secondFile {
		t.Errorf("expected same file after double Start, got %q and %q", firstFile, secondFile)
	}
}

func TestStop_IdempotentWhenNotRecording(t *testing.T) {
	rec := newTestRecorder(t)
	// Should not panic
	rec.Stop()
	rec.Stop()
	if rec.IsRecording() {
		t.Error("expected IsRecording to still be false")
	}
}

func TestStart_CreatesFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	defer rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture file, got %d", len(captures))
	}
	if !captures[0].IsActive {
		t.Error("expected the capture file to be marked active")
	}
}

// --- RecordFull ---

func TestRecordFull_WritesWhenRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	respHeaders := http.Header{"Content-Type": []string{"text/html"}}
	rec.RecordFull("GET", "/test", "client1",
		map[string]string{"User-Agent": "test-agent"}, []byte("request body"),
		200, respHeaders, 42, 1.5)

	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture file, got %d", len(captures))
	}
	if captures[0].Records != 1 {
		t.Errorf("expected 1 record, got %d", captures[0].Records)
	}
	if captures[0].SizeBytes == 0 {
		t.Error("expected non-zero file size")
	}

	// Read and verify the JSONL content
	data, err := os.ReadFile(filepath.Join(rec.capturesDir, captures[0].Filename))
	if err != nil {
		t.Fatalf("failed to read capture file: %v", err)
	}

	var record captureRecord
	if err := json.Unmarshal(data[:len(data)-1], &record); err != nil { // strip trailing newline
		t.Fatalf("failed to parse record: %v", err)
	}

	if record.Method != "GET" {
		t.Errorf("expected method GET, got %q", record.Method)
	}
	if record.Path != "/test" {
		t.Errorf("expected path /test, got %q", record.Path)
	}
	if record.ClientID != "client1" {
		t.Errorf("expected clientID client1, got %q", record.ClientID)
	}
	if record.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", record.StatusCode)
	}
	if record.ResponseBodySz != 42 {
		t.Errorf("expected response body size 42, got %d", record.ResponseBodySz)
	}
	if record.LatencyMs != 1.5 {
		t.Errorf("expected latency 1.5, got %f", record.LatencyMs)
	}
	if record.RequestBody != "request body" {
		t.Errorf("expected request body 'request body', got %q", record.RequestBody)
	}
	if record.RequestHeaders["User-Agent"] != "test-agent" {
		t.Errorf("expected User-Agent header 'test-agent', got %q", record.RequestHeaders["User-Agent"])
	}
	if record.ResponseHeaders["Content-Type"] != "text/html" {
		t.Errorf("expected Content-Type response header 'text/html', got %q", record.ResponseHeaders["Content-Type"])
	}
}

func TestRecordFull_NoOpWhenNotRecording(t *testing.T) {
	rec := newTestRecorder(t)
	// Not started
	rec.RecordFull("GET", "/test", "c1", nil, nil, 200, nil, 0, 0)
	captures := rec.GetCaptures()
	if len(captures) != 0 {
		t.Errorf("expected 0 captures, got %d", len(captures))
	}
}

func TestRecordFull_MultipleRecords(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	for i := 0; i < 5; i++ {
		rec.RecordFull("GET", "/page", "c1", nil, nil, 200, http.Header{}, 10, 0.5)
	}

	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 5 {
		t.Errorf("expected 5 records, got %d", captures[0].Records)
	}
}

func TestRecordFull_EmptyRequestBody(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	rec.RecordFull("GET", "/test", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()

	captures := rec.GetCaptures()
	data, _ := os.ReadFile(filepath.Join(rec.capturesDir, captures[0].Filename))
	var record captureRecord
	json.Unmarshal(data[:len(data)-1], &record)

	if record.RequestBody != "" {
		t.Errorf("expected empty request body, got %q", record.RequestBody)
	}
}

// --- RecordResponse ---

func TestRecordResponse_WritesWhenRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	respHeaders := http.Header{"X-Custom": []string{"value"}}
	rec.RecordResponse(404, respHeaders, []byte("not found"), "client2", "/missing")

	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 1 {
		t.Errorf("expected 1 record, got %d", captures[0].Records)
	}

	data, _ := os.ReadFile(filepath.Join(rec.capturesDir, captures[0].Filename))
	var record captureRecord
	json.Unmarshal(data[:len(data)-1], &record)

	if record.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", record.StatusCode)
	}
	if record.Path != "/missing" {
		t.Errorf("expected path /missing, got %q", record.Path)
	}
	if record.ResponseBodySz != int64(len("not found")) {
		t.Errorf("expected response body size %d, got %d", len("not found"), record.ResponseBodySz)
	}
}

func TestRecordResponse_NoOpWhenNotRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.RecordResponse(200, http.Header{}, []byte("data"), "c1", "/path")
	captures := rec.GetCaptures()
	if len(captures) != 0 {
		t.Errorf("expected no captures, got %d", len(captures))
	}
}

// --- RecordRequest ---

func TestRecordRequest_NoOpForFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec.RecordRequest(req, []byte("body"))

	// RecordRequest alone does not write to file
	rec.mu.Lock()
	size := rec.fileSize
	rec.mu.Unlock()

	if size != 0 {
		t.Errorf("expected zero file size after RecordRequest, got %d", size)
	}

	rec.Stop()
}

// --- ShouldHandle ---

func TestShouldHandle_MatchingPaths(t *testing.T) {
	rec := newTestRecorder(t)

	tests := []struct {
		path   string
		expect bool
	}{
		{"/captures/", true},
		{"/captures", true},
		{"/captures/start", true},
		{"/captures/stop", true},
		{"/captures/somefile.jsonl", true},
		{"/captures/subdir/file", true},
		{"/", false},
		{"/api/metrics", false},
		{"/capture", false},
		{"/capturesextra", false},
	}

	for _, tc := range tests {
		got := rec.ShouldHandle(tc.path)
		if got != tc.expect {
			t.Errorf("ShouldHandle(%q) = %v, want %v", tc.path, got, tc.expect)
		}
	}
}

// --- ServeHTTP: POST /captures/start ---

func TestServeHTTP_Start(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodPost, "/captures/start", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if !rec.IsRecording() {
		t.Error("expected recording to be true after /captures/start")
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "recording" {
		t.Errorf("expected status=recording, got %q", resp["status"])
	}
	if resp["file"] == "" {
		t.Error("expected file name in response")
	}
}

func TestServeHTTP_StartIdempotent(t *testing.T) {
	rec := newTestRecorder(t)

	// First start
	req1 := httptest.NewRequest(http.MethodPost, "/captures/start", nil)
	w1 := httptest.NewRecorder()
	rec.ServeHTTP(w1, req1)

	var resp1 map[string]string
	json.Unmarshal(w1.Body.Bytes(), &resp1)

	// Second start
	req2 := httptest.NewRequest(http.MethodPost, "/captures/start", nil)
	w2 := httptest.NewRecorder()
	rec.ServeHTTP(w2, req2)

	var resp2 map[string]string
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp1["file"] != resp2["file"] {
		t.Errorf("expected same file on double start, got %q and %q", resp1["file"], resp2["file"])
	}
}

// --- ServeHTTP: POST /captures/stop ---

func TestServeHTTP_Stop(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	// Record something so records > 0
	rec.RecordFull("GET", "/x", "c", nil, nil, 200, http.Header{}, 0, 0)

	req := httptest.NewRequest(http.MethodPost, "/captures/stop", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if rec.IsRecording() {
		t.Error("expected recording to be false after /captures/stop")
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "stopped" {
		t.Errorf("expected status=stopped, got %v", resp["status"])
	}
	if resp["records"].(float64) != 1 {
		t.Errorf("expected records=1, got %v", resp["records"])
	}
}

func TestServeHTTP_StopWhenNotRecording(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodPost, "/captures/stop", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "not_recording" {
		t.Errorf("expected status=not_recording, got %v", resp["status"])
	}
}

// --- ServeHTTP: GET /captures/ (list) ---

func TestServeHTTP_ListEmpty(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodGet, "/captures/", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}

	var captures []CaptureInfo
	json.Unmarshal(w.Body.Bytes(), &captures)
	if len(captures) != 0 {
		t.Errorf("expected 0 captures, got %d", len(captures))
	}
}

func TestServeHTTP_ListWithCaptures(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	rec.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()

	req := httptest.NewRequest(http.MethodGet, "/captures/", nil)
	w := httptest.NewRecorder()
	rec.ServeHTTP(w, req)

	var captures []CaptureInfo
	json.Unmarshal(w.Body.Bytes(), &captures)
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 1 {
		t.Errorf("expected 1 record, got %d", captures[0].Records)
	}
	if !strings.HasPrefix(captures[0].Filename, "capture_") {
		t.Errorf("unexpected filename: %q", captures[0].Filename)
	}
}

func TestServeHTTP_ListWithoutTrailingSlash(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodGet, "/captures", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
}

// --- ServeHTTP: GET /captures/{file} (download) ---

func TestServeHTTP_DownloadFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	rec.RecordFull("GET", "/page", "c1", nil, nil, 200, http.Header{}, 10, 1.0)
	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) == 0 {
		t.Fatal("no captures available")
	}
	filename := captures[0].Filename

	req := httptest.NewRequest(http.MethodGet, "/captures/"+filename, nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Errorf("expected Content-Type application/x-ndjson, got %q", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Error("expected Content-Disposition header")
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty body")
	}
}

func TestServeHTTP_DownloadNonexistentFile(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodGet, "/captures/capture_20250101_000000.jsonl", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("expected 404, got %d", status)
	}
}

// --- ServeHTTP: DELETE /captures/{file} ---

func TestServeHTTP_DeleteFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	rec.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()

	captures := rec.GetCaptures()
	filename := captures[0].Filename

	req := httptest.NewRequest(http.MethodDelete, "/captures/"+filename, nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["deleted"] != true {
		t.Errorf("expected deleted=true, got %v", resp["deleted"])
	}

	// Verify file is gone
	remaining := rec.GetCaptures()
	if len(remaining) != 0 {
		t.Errorf("expected 0 captures after delete, got %d", len(remaining))
	}
}

func TestServeHTTP_DeleteActiveFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	rec.mu.Lock()
	activeFile := rec.fileName
	rec.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/captures/"+activeFile, nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusConflict {
		t.Errorf("expected 409 Conflict, got %d", status)
	}

	// File should still exist
	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Errorf("expected 1 capture (active), got %d", len(captures))
	}

	rec.Stop()
}

func TestServeHTTP_DeleteNonexistentFile(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodDelete, "/captures/capture_20250101_000000.jsonl", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("expected 404, got %d", status)
	}
}

// --- Path traversal protection ---

func TestServeHTTP_PathTraversal(t *testing.T) {
	rec := newTestRecorder(t)

	malicious := []string{
		"/captures/../../../etc/passwd",
		"/captures/..%2f..%2fetc/passwd",
		"/captures/capture_../../evil.jsonl",
		"/captures/subdir/capture_foo.jsonl",
	}

	for _, p := range malicious {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		status := rec.ServeHTTP(w, req)

		if status == http.StatusOK {
			t.Errorf("expected non-200 status for path traversal attempt %q, got %d", p, status)
		}
	}
}

func TestIsValidCaptureFilename(t *testing.T) {
	tests := []struct {
		name   string
		valid  bool
	}{
		{"capture_20250101_120000.jsonl", true},
		{"capture_20250612_235959.jsonl", true},
		{"../capture_20250101_120000.jsonl", false},
		{"capture_20250101_120000.jsonl/../../etc/passwd", false},
		{"capture_evil\\path.jsonl", false},
		{"notcapture_20250101_120000.jsonl", false},
		{"capture_20250101_120000.txt", false},
		{"capture_20250101_120000.jsonl.bak", false},
		{"", false},
	}

	for _, tc := range tests {
		got := isValidCaptureFilename(tc.name)
		if got != tc.valid {
			t.Errorf("isValidCaptureFilename(%q) = %v, want %v", tc.name, got, tc.valid)
		}
	}
}

// --- Method not allowed ---

func TestServeHTTP_MethodNotAllowed(t *testing.T) {
	rec := newTestRecorder(t)

	// Create a capture file so the filename is valid
	rec.Start()
	rec.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()

	captures := rec.GetCaptures()
	filename := captures[0].Filename

	// PUT is not supported on capture files
	req := httptest.NewRequest(http.MethodPut, "/captures/"+filename, nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", status)
	}
}

// --- GetCaptures ---

func TestGetCaptures_IgnoresNonCaptureFiles(t *testing.T) {
	rec := newTestRecorder(t)

	// Create some non-capture files in the directory
	os.WriteFile(filepath.Join(rec.capturesDir, "readme.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(rec.capturesDir, "data.jsonl"), []byte("data"), 0o644)

	captures := rec.GetCaptures()
	if len(captures) != 0 {
		t.Errorf("expected 0 captures (non-capture files should be ignored), got %d", len(captures))
	}
}

func TestGetCaptures_IgnoresDirectories(t *testing.T) {
	rec := newTestRecorder(t)

	// Create a directory that looks like a capture file
	os.MkdirAll(filepath.Join(rec.capturesDir, "capture_20250101_120000.jsonl"), 0o755)

	captures := rec.GetCaptures()
	if len(captures) != 0 {
		t.Errorf("expected 0 captures (directories should be ignored), got %d", len(captures))
	}
}

func TestGetCaptures_MarksActiveFile(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if !captures[0].IsActive {
		t.Error("expected the active file to be marked as active")
	}

	rec.Stop()

	captures = rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].IsActive {
		t.Error("expected no active file after stop")
	}
}

func TestGetCaptures_MultipleFiles(t *testing.T) {
	rec := newTestRecorder(t)

	// Create multiple capture files manually
	for i := 0; i < 3; i++ {
		name := "capture_20250101_12000" + string(rune('0'+i)) + ".jsonl"
		os.WriteFile(filepath.Join(rec.capturesDir, name), []byte("{}\n"), 0o644)
	}

	captures := rec.GetCaptures()
	if len(captures) != 3 {
		t.Errorf("expected 3 captures, got %d", len(captures))
	}
}

// --- parseFilenameTime ---

func TestParseFilenameTime_Valid(t *testing.T) {
	ts := parseFilenameTime("capture_20250612_143059.jsonl")
	if ts.IsZero() {
		t.Fatal("expected non-zero time")
	}
	if ts.Year() != 2025 || ts.Month() != 6 || ts.Day() != 12 {
		t.Errorf("unexpected date: %v", ts)
	}
	if ts.Hour() != 14 || ts.Minute() != 30 || ts.Second() != 59 {
		t.Errorf("unexpected time: %v", ts)
	}
}

func TestParseFilenameTime_Invalid(t *testing.T) {
	ts := parseFilenameTime("not_a_capture_file.txt")
	if !ts.IsZero() {
		t.Errorf("expected zero time for invalid filename, got %v", ts)
	}
}

// --- countLines ---

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	// Write 5 lines
	content := "{}\n{}\n{}\n{}\n{}\n"
	os.WriteFile(path, []byte(content), 0o644)

	count := countLines(path)
	if count != 5 {
		t.Errorf("expected 5 lines, got %d", count)
	}
}

func TestCountLines_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(path, []byte(""), 0o644)

	count := countLines(path)
	if count != 0 {
		t.Errorf("expected 0 lines, got %d", count)
	}
}

func TestCountLines_NonexistentFile(t *testing.T) {
	count := countLines("/nonexistent/path/file.jsonl")
	if count != 0 {
		t.Errorf("expected 0 for nonexistent file, got %d", count)
	}
}

// --- File rotation ---

func TestFileRotation_BySize(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	rec.mu.Lock()
	firstFile := rec.fileName
	// Simulate a large file by setting fileSize just below the threshold
	rec.fileSize = maxFileSize
	rec.mu.Unlock()

	// Next record should trigger rotation (async — writer processes it)
	rec.RecordFull("GET", "/large", "c1", nil, nil, 200, http.Header{}, 0, 0)

	// Wait for the async writer to process the message and rotate.
	for i := 0; i < 100; i++ {
		rec.mu.Lock()
		sz := rec.fileSize
		rec.mu.Unlock()
		if sz < maxFileSize {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	rec.mu.Lock()
	secondFile := rec.fileName
	rec.mu.Unlock()

	// The files might have the same name if they rotate within the same second,
	// but the rotation should have happened (closeFile + openNewFile).
	// We check that rotation was triggered by verifying the file size was reset.
	rec.mu.Lock()
	currentSize := rec.fileSize
	rec.mu.Unlock()

	// After rotation, current file should contain only the new record, so it should be
	// much smaller than maxFileSize.
	if currentSize >= maxFileSize {
		t.Errorf("expected file size to be reset after rotation, got %d", currentSize)
	}

	rec.Stop()

	// If rotation created a new file with a different name, we should have 2 files
	if firstFile != secondFile {
		captures := rec.GetCaptures()
		if len(captures) < 2 {
			t.Errorf("expected at least 2 capture files after size rotation, got %d", len(captures))
		}
	}
}

func TestFileRotation_ByDuration(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	rec.mu.Lock()
	// Simulate that the file has been open for more than maxFileDuration
	rec.fileStart = time.Now().Add(-maxFileDuration - time.Minute)
	firstFile := rec.fileName
	rec.mu.Unlock()

	// Next record should trigger rotation (async — writer processes it)
	rec.RecordFull("GET", "/old", "c1", nil, nil, 200, http.Header{}, 0, 0)

	// Wait for the async writer to process the message and rotate.
	for i := 0; i < 100; i++ {
		rec.mu.Lock()
		fs := rec.fileStart
		rec.mu.Unlock()
		if time.Since(fs) < time.Minute {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	rec.mu.Lock()
	secondFile := rec.fileName
	fileStart := rec.fileStart
	rec.mu.Unlock()

	// The fileStart should have been reset to a recent time
	if time.Since(fileStart) > time.Minute {
		t.Error("expected fileStart to be reset after duration rotation")
	}

	rec.Stop()

	if firstFile != secondFile {
		captures := rec.GetCaptures()
		if len(captures) < 2 {
			t.Errorf("expected at least 2 capture files after duration rotation, got %d", len(captures))
		}
	}
}

// --- Concurrent access ---

func TestConcurrentRecording(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec.RecordFull("GET", "/concurrent", "c1",
				nil, nil, 200, http.Header{}, int64(i), 0.1)
		}(i)
	}
	wg.Wait()
	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 50 {
		t.Errorf("expected 50 records, got %d", captures[0].Records)
	}
}

func TestConcurrentStartStop(t *testing.T) {
	rec := newTestRecorder(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.Start()
			rec.RecordFull("GET", "/", "c", nil, nil, 200, http.Header{}, 0, 0)
			rec.Stop()
		}()
	}
	wg.Wait()

	// Should not panic or deadlock; final state should be not recording
	if rec.IsRecording() {
		t.Error("expected not recording after all goroutines finish")
	}
}

// --- ServeHTTP: edge cases ---

func TestServeHTTP_NotFound(t *testing.T) {
	rec := newTestRecorder(t)

	// A path that doesn't match any known route but still handled by ShouldHandle logic
	// Actually, let's test a truly unknown path — the catch-all at the end of ServeHTTP
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("expected 404, got %d", status)
	}
}

func TestServeHTTP_InvalidFilenameInPath(t *testing.T) {
	rec := newTestRecorder(t)

	req := httptest.NewRequest(http.MethodGet, "/captures/not_a_capture.txt", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid filename") {
		t.Errorf("expected 'invalid filename' in body, got %q", body)
	}
}

func TestServeHTTP_ListViaTrailingSlashFilename(t *testing.T) {
	// GET /captures/something/ where "something" trims to empty should list
	rec := newTestRecorder(t)

	// /captures/ with trailing slash after trimming the prefix gives ""
	req := httptest.NewRequest(http.MethodGet, "/captures/", nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}

	// Should return JSON array
	var captures []CaptureInfo
	err := json.Unmarshal(w.Body.Bytes(), &captures)
	if err != nil {
		t.Errorf("expected valid JSON array, got error: %v", err)
	}
}

// --- Full workflow: start -> record -> stop -> list -> download -> delete ---

func TestFullWorkflow(t *testing.T) {
	rec := newTestRecorder(t)

	// 1. Start recording
	req := httptest.NewRequest(http.MethodPost, "/captures/start", nil)
	w := httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start: expected 200, got %d", w.Code)
	}

	// 2. Record some traffic
	for i := 0; i < 3; i++ {
		rec.RecordFull("GET", "/page", "client1",
			map[string]string{"Accept": "text/html"}, nil,
			200, http.Header{"Content-Type": []string{"text/html"}}, 1024, 5.0)
	}

	// 3. Stop recording
	req = httptest.NewRequest(http.MethodPost, "/captures/stop", nil)
	w = httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stop: expected 200, got %d", w.Code)
	}
	var stopResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &stopResp)
	if stopResp["records"].(float64) != 3 {
		t.Errorf("stop: expected 3 records, got %v", stopResp["records"])
	}

	// 4. List captures
	req = httptest.NewRequest(http.MethodGet, "/captures/", nil)
	w = httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	var captures []CaptureInfo
	json.Unmarshal(w.Body.Bytes(), &captures)
	if len(captures) != 1 {
		t.Fatalf("list: expected 1 capture, got %d", len(captures))
	}
	filename := captures[0].Filename

	// 5. Download the file
	req = httptest.NewRequest(http.MethodGet, "/captures/"+filename, nil)
	w = httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("download: expected 200, got %d", w.Code)
	}

	// Verify the downloaded content has 3 JSONL lines
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("download: expected 3 lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var record captureRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Errorf("download: line %d is not valid JSON: %v", i, err)
		}
	}

	// 6. Delete the file
	req = httptest.NewRequest(http.MethodDelete, "/captures/"+filename, nil)
	w = httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", w.Code)
	}

	// 7. Verify it's gone
	req = httptest.NewRequest(http.MethodGet, "/captures/", nil)
	w = httptest.NewRecorder()
	rec.ServeHTTP(w, req)
	json.Unmarshal(w.Body.Bytes(), &captures)
	if len(captures) != 0 {
		t.Errorf("list after delete: expected 0 captures, got %d", len(captures))
	}
}

// --- Content-Type headers in API responses ---

func TestServeHTTP_ContentTypeJSON(t *testing.T) {
	rec := newTestRecorder(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/captures/start"},
		{http.MethodPost, "/captures/stop"},
		{http.MethodGet, "/captures/"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		rec.ServeHTTP(w, req)

		ct := w.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("%s %s: expected Content-Type application/json, got %q", ep.method, ep.path, ct)
		}
	}
}

// --- RecordResponse with nil headers ---

func TestRecordResponse_NilHeaders(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	// Should not panic with nil headers
	rec.RecordResponse(200, nil, []byte("data"), "c1", "/path")
	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 1 {
		t.Errorf("expected 1 record, got %d", captures[0].Records)
	}
}

// --- RecordFull with nil response headers ---

func TestRecordFull_NilResponseHeaders(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	// Should not panic with nil response headers
	rec.RecordFull("POST", "/api", "c1", map[string]string{"X": "Y"}, []byte("body"), 201, nil, 4, 2.0)
	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if captures[0].Records != 1 {
		t.Errorf("expected 1 record, got %d", captures[0].Records)
	}
}

// --- Download sets correct response headers ---

func TestServeHTTP_DownloadHeaders(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()
	rec.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()

	captures := rec.GetCaptures()
	filename := captures[0].Filename

	req := httptest.NewRequest(http.MethodGet, "/captures/"+filename, nil)
	w := httptest.NewRecorder()
	rec.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Errorf("expected Content-Type application/x-ndjson, got %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), filename) {
		t.Errorf("expected Content-Disposition to contain filename, got %q", resp.Header.Get("Content-Disposition"))
	}
	if resp.Header.Get("Content-Length") == "" {
		t.Error("expected Content-Length header")
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
}

// --- maybeRotate with nil file ---

func TestMaybeRotate_NilFileOpensNew(t *testing.T) {
	rec := newTestRecorder(t)
	rec.Start()

	// Force file to nil to simulate edge case
	rec.mu.Lock()
	rec.file.Close()
	rec.file = nil
	rec.mu.Unlock()

	// Recording should still work because maybeRotate opens a new file
	rec.RecordFull("GET", "/recover", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec.Stop()
}

// =============================================================================
// PCAP format tests
// =============================================================================

func TestPCAPWriter_CreatesValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	// Write a simple packet
	err = pw.WritePacket("10.0.0.1", "10.0.0.2", 12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("failed to write packet: %v", err)
	}

	err = pw.Close()
	if err != nil {
		t.Fatalf("failed to close PCAPWriter: %v", err)
	}

	// Read the file and verify magic bytes
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read pcap file: %v", err)
	}

	if len(data) < 24 {
		t.Fatalf("pcap file too small: %d bytes", len(data))
	}

	// Verify magic number (little-endian 0xa1b2c3d4)
	magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if magic != 0xa1b2c3d4 {
		t.Errorf("expected magic 0xa1b2c3d4, got 0x%08x", magic)
	}

	// Verify version major = 2
	versionMaj := uint16(data[4]) | uint16(data[5])<<8
	if versionMaj != 2 {
		t.Errorf("expected version major 2, got %d", versionMaj)
	}

	// Verify version minor = 4
	versionMin := uint16(data[6]) | uint16(data[7])<<8
	if versionMin != 4 {
		t.Errorf("expected version minor 4, got %d", versionMin)
	}

	// Verify snaplen = 65535
	snaplen := uint32(data[16]) | uint32(data[17])<<8 | uint32(data[18])<<16 | uint32(data[19])<<24
	if snaplen != 65535 {
		t.Errorf("expected snaplen 65535, got %d", snaplen)
	}

	// Verify network = 1 (LINKTYPE_ETHERNET)
	network := uint32(data[20]) | uint32(data[21])<<8 | uint32(data[22])<<16 | uint32(data[23])<<24
	if network != 1 {
		t.Errorf("expected network 1, got %d", network)
	}

	// File should be larger than just the global header (24 bytes)
	if len(data) <= 24 {
		t.Errorf("expected file to contain packet data beyond global header, got %d bytes", len(data))
	}
}

func TestPCAPWriter_WriteHTTPRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_req.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	sizeBefore := pw.Size()

	err = pw.WriteHTTPRequest("GET", "/api/data", "example.com",
		map[string]string{"Accept": "application/json"}, "")
	if err != nil {
		t.Fatalf("failed to write HTTP request: %v", err)
	}

	sizeAfter := pw.Size()
	if sizeAfter <= sizeBefore {
		t.Errorf("expected file to grow after WriteHTTPRequest, before=%d after=%d", sizeBefore, sizeAfter)
	}

	pw.Close()
}

func TestPCAPWriter_WriteHTTPResponse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_resp.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	sizeBefore := pw.Size()

	err = pw.WriteHTTPResponse(200, map[string]string{"Content-Type": "text/html"}, 1024)
	if err != nil {
		t.Fatalf("failed to write HTTP response: %v", err)
	}

	sizeAfter := pw.Size()
	if sizeAfter <= sizeBefore {
		t.Errorf("expected file to grow after WriteHTTPResponse, before=%d after=%d", sizeBefore, sizeAfter)
	}

	pw.Close()
}

func TestRecorder_PCAPFormat_StartStop(t *testing.T) {
	rec := newTestRecorder(t)
	rec.SetFormat("pcap")

	rec.Start()
	if !rec.IsRecording() {
		t.Fatal("expected recording to be true after Start")
	}

	rec.Stop()
	if rec.IsRecording() {
		t.Fatal("expected recording to be false after Stop")
	}

	// Verify a .pcap file was created
	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture file, got %d", len(captures))
	}
	if !strings.HasSuffix(captures[0].Filename, ".pcap") {
		t.Errorf("expected .pcap extension, got %q", captures[0].Filename)
	}
	if captures[0].SizeBytes < 24 {
		t.Errorf("expected pcap file to be at least 24 bytes (global header), got %d", captures[0].SizeBytes)
	}
}

func TestRecorder_PCAPFormat_RecordFull(t *testing.T) {
	rec := newTestRecorder(t)
	rec.SetFormat("pcap")
	rec.Start()

	respHeaders := http.Header{"Content-Type": []string{"text/html"}}
	rec.RecordFull("GET", "/test", "client1",
		map[string]string{"User-Agent": "test-agent", "Host": "example.com"},
		[]byte("request body"),
		200, respHeaders, 42, 1.5)

	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture file, got %d", len(captures))
	}

	// The file should have content beyond the 24-byte global header
	if captures[0].SizeBytes <= 24 {
		t.Errorf("expected pcap file to have packet data, got %d bytes", captures[0].SizeBytes)
	}

	// Verify the file has valid pcap magic bytes
	data, err := os.ReadFile(filepath.Join(rec.capturesDir, captures[0].Filename))
	if err != nil {
		t.Fatalf("failed to read capture file: %v", err)
	}
	magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if magic != 0xa1b2c3d4 {
		t.Errorf("expected magic 0xa1b2c3d4, got 0x%08x", magic)
	}
}

func TestRecorder_FormatSelection(t *testing.T) {
	// Test JSONL format creates .jsonl
	rec1 := newTestRecorder(t)
	rec1.SetFormat("jsonl")
	rec1.Start()
	rec1.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec1.Stop()

	captures1 := rec1.GetCaptures()
	if len(captures1) != 1 {
		t.Fatalf("jsonl: expected 1 capture, got %d", len(captures1))
	}
	if !strings.HasSuffix(captures1[0].Filename, ".jsonl") {
		t.Errorf("jsonl: expected .jsonl extension, got %q", captures1[0].Filename)
	}

	// Test PCAP format creates .pcap
	rec2 := newTestRecorder(t)
	rec2.SetFormat("pcap")
	rec2.Start()
	rec2.RecordFull("GET", "/", "c1", nil, nil, 200, http.Header{}, 0, 0)
	rec2.Stop()

	captures2 := rec2.GetCaptures()
	if len(captures2) != 1 {
		t.Fatalf("pcap: expected 1 capture, got %d", len(captures2))
	}
	if !strings.HasSuffix(captures2[0].Filename, ".pcap") {
		t.Errorf("pcap: expected .pcap extension, got %q", captures2[0].Filename)
	}
}

func TestRecorder_PCAPDownload_ContentType(t *testing.T) {
	rec := newTestRecorder(t)
	rec.SetFormat("pcap")
	rec.Start()
	rec.RecordFull("GET", "/page", "c1", nil, nil, 200, http.Header{}, 10, 1.0)
	rec.Stop()

	captures := rec.GetCaptures()
	if len(captures) == 0 {
		t.Fatal("no captures available")
	}
	filename := captures[0].Filename

	req := httptest.NewRequest(http.MethodGet, "/captures/"+filename, nil)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	expectedCT := "application/vnd.tcpdump.pcap"
	if w.Header().Get("Content-Type") != expectedCT {
		t.Errorf("expected Content-Type %q, got %q", expectedCT, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Error("expected Content-Disposition header")
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty body")
	}
}

func TestRecorder_PCAPFormat_HandleStartWithFormat(t *testing.T) {
	rec := newTestRecorder(t)

	// Start recording via HTTP API with format=pcap
	body := strings.NewReader(`{"format":"pcap"}`)
	req := httptest.NewRequest(http.MethodPost, "/captures/start", body)
	w := httptest.NewRecorder()
	status := rec.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if !rec.IsRecording() {
		t.Error("expected recording to be true after /captures/start")
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["format"] != "pcap" {
		t.Errorf("expected format=pcap in response, got %q", resp["format"])
	}
	if !strings.HasSuffix(resp["file"], ".pcap") {
		t.Errorf("expected .pcap filename, got %q", resp["file"])
	}

	// Stop and verify file exists
	rec.Stop()
	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(captures))
	}
	if !strings.HasSuffix(captures[0].Filename, ".pcap") {
		t.Errorf("expected .pcap file, got %q", captures[0].Filename)
	}
}

func TestRecorder_PCAPFormat_ValidCaptureFilename(t *testing.T) {
	// .pcap files should be valid capture filenames
	tests := []struct {
		name  string
		valid bool
	}{
		{"capture_20250101_120000.pcap", true},
		{"capture_20250612_235959.pcap", true},
		{"capture_20250101_120000.jsonl", true},
		{"capture_20250101_120000.txt", false},
		{"notcapture_20250101_120000.pcap", false},
		{"../capture_20250101_120000.pcap", false},
	}

	for _, tc := range tests {
		got := isValidCaptureFilename(tc.name)
		if got != tc.valid {
			t.Errorf("isValidCaptureFilename(%q) = %v, want %v", tc.name, got, tc.valid)
		}
	}
}

func TestRecorder_PCAPFormat_ParseFilenameTime(t *testing.T) {
	// .pcap extension should be handled by parseFilenameTime
	ts := parseFilenameTime("capture_20250612_143059.pcap")
	if ts.IsZero() {
		t.Fatal("expected non-zero time for .pcap filename")
	}
	if ts.Year() != 2025 || ts.Month() != 6 || ts.Day() != 12 {
		t.Errorf("unexpected date: %v", ts)
	}
	if ts.Hour() != 14 || ts.Minute() != 30 || ts.Second() != 59 {
		t.Errorf("unexpected time: %v", ts)
	}
}

func TestRecorder_PCAPFormat_GetFormat(t *testing.T) {
	rec := newTestRecorder(t)

	// Default format should be jsonl
	if rec.GetFormat() != "jsonl" {
		t.Errorf("expected default format jsonl, got %q", rec.GetFormat())
	}

	rec.SetFormat("pcap")
	if rec.GetFormat() != "pcap" {
		t.Errorf("expected format pcap, got %q", rec.GetFormat())
	}

	rec.SetFormat("jsonl")
	if rec.GetFormat() != "jsonl" {
		t.Errorf("expected format jsonl, got %q", rec.GetFormat())
	}

	// Invalid format should be ignored
	rec.SetFormat("xml")
	if rec.GetFormat() != "jsonl" {
		t.Errorf("expected format to remain jsonl after invalid set, got %q", rec.GetFormat())
	}
}

func TestPCAPWriter_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	// Close twice should not panic
	pw.Close()
	err = pw.Close()
	if err != nil {
		t.Errorf("second Close should return nil, got %v", err)
	}
}

func TestPCAPWriter_SizeAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	pw.Close()

	// Size after close should return 0
	if pw.Size() != 0 {
		t.Errorf("expected Size() == 0 after close, got %d", pw.Size())
	}
}

func TestPCAPWriter_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("failed to create PCAPWriter: %v", err)
	}

	pw.Close()

	// Write after close should return error
	err = pw.WritePacket("10.0.0.1", "10.0.0.2", 12345, 80, []byte("data"))
	if err == nil {
		t.Error("expected error when writing to closed PCAPWriter")
	}
}

// =============================================================================
// StartWithLimits and GetStatus tests
// =============================================================================

func TestRecorder_StartWithLimits_MaxRequests(t *testing.T) {
	rec := newTestRecorder(t)

	// Start with a max of 5 requests
	rec.StartWithLimits(0, 5)
	if !rec.IsRecording() {
		t.Fatal("expected recording to be true after StartWithLimits")
	}

	// Record 10 requests; the recorder should auto-stop after 5
	for i := 0; i < 10; i++ {
		rec.RecordFull("GET", "/page", "c1", nil, nil, 200, http.Header{}, 0, 0.1)
	}

	// Stop is async — wait for it to complete.
	for i := 0; i < 100; i++ {
		if !rec.IsRecording() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rec.IsRecording() {
		t.Error("expected recording to auto-stop after reaching maxRequests")
	}

	// Verify exactly 5 records were written
	captures := rec.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("expected 1 capture file, got %d", len(captures))
	}
	if captures[0].Records != 5 {
		t.Errorf("expected 5 records, got %d", captures[0].Records)
	}
}

func TestRecorder_StartWithLimits_MaxDuration(t *testing.T) {
	rec := newTestRecorder(t)

	// Start with a max duration of 1 second
	rec.StartWithLimits(1, 0)
	if !rec.IsRecording() {
		t.Fatal("expected recording to be true after StartWithLimits")
	}

	// Wait 2 seconds for the timer to fire
	time.Sleep(2 * time.Second)

	if rec.IsRecording() {
		t.Error("expected recording to auto-stop after maxDuration elapsed")
	}
}

func TestRecorder_GetStatus_Recording(t *testing.T) {
	rec := newTestRecorder(t)

	rec.SetFormat("jsonl")
	rec.StartWithLimits(60, 1000)

	// Record a few entries
	for i := 0; i < 3; i++ {
		rec.RecordFull("GET", "/test", "c1", nil, nil, 200, http.Header{}, 10, 0.5)
	}

	// Wait for async writer to flush records to disk.
	for i := 0; i < 100; i++ {
		if s := rec.GetStatus(); s.SizeBytes > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	status := rec.GetStatus()

	if !status.Recording {
		t.Error("expected Recording to be true")
	}
	if status.Format != "jsonl" {
		t.Errorf("expected format jsonl, got %q", status.Format)
	}
	if status.FileName == "" {
		t.Error("expected non-empty FileName")
	}
	if status.Records != 3 {
		t.Errorf("expected 3 records, got %d", status.Records)
	}
	if status.SizeBytes == 0 {
		t.Error("expected non-zero SizeBytes")
	}
	if status.ElapsedSec <= 0 {
		t.Errorf("expected positive ElapsedSec, got %f", status.ElapsedSec)
	}
	if status.MaxDuration != 60 {
		t.Errorf("expected MaxDuration 60, got %d", status.MaxDuration)
	}
	if status.MaxRequests != 1000 {
		t.Errorf("expected MaxRequests 1000, got %d", status.MaxRequests)
	}

	rec.Stop()
}

func TestRecorder_GetStatus_NotRecording(t *testing.T) {
	rec := newTestRecorder(t)

	status := rec.GetStatus()

	if status.Recording {
		t.Error("expected Recording to be false")
	}
	if status.Format != "jsonl" {
		t.Errorf("expected default format jsonl, got %q", status.Format)
	}
	if status.FileName != "" {
		t.Errorf("expected empty FileName, got %q", status.FileName)
	}
	if status.Records != 0 {
		t.Errorf("expected 0 records, got %d", status.Records)
	}
	if status.SizeBytes != 0 {
		t.Errorf("expected 0 SizeBytes, got %d", status.SizeBytes)
	}
	if status.ElapsedSec != 0 {
		t.Errorf("expected 0 ElapsedSec, got %f", status.ElapsedSec)
	}
	if status.MaxDuration != 0 {
		t.Errorf("expected 0 MaxDuration, got %d", status.MaxDuration)
	}
	if status.MaxRequests != 0 {
		t.Errorf("expected 0 MaxRequests, got %d", status.MaxRequests)
	}
}
