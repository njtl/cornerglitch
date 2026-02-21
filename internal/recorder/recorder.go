package recorder

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxFileSize is the maximum capture file size before rotation (50MB).
const maxFileSize = 50 * 1024 * 1024

// maxFileDuration is the maximum duration for a single capture file before rotation (1 hour).
const maxFileDuration = time.Hour

// CaptureInfo describes a single capture file on disk.
type CaptureInfo struct {
	Filename  string    `json:"filename"`
	StartTime time.Time `json:"start_time"`
	Records   int64     `json:"records"`
	SizeBytes int64     `json:"size_bytes"`
	IsActive  bool      `json:"is_active"`
}

// captureRecord is a single JSON-lines entry written to a capture file.
type captureRecord struct {
	Timestamp       string            `json:"timestamp"`
	ClientID        string            `json:"client_id"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	StatusCode      int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBodySz  int64             `json:"response_body_size"`
	LatencyMs       float64           `json:"latency_ms"`
}

// Recorder handles HTTP traffic capture to JSONL files.
type Recorder struct {
	capturesDir string

	mu          sync.Mutex
	recording   bool
	file        *os.File
	fileName    string
	fileStart   time.Time
	fileSize    int64
	recordCount atomic.Int64
}

// NewRecorder creates a new Recorder that stores captures in capturesDir.
// The directory is created if it does not exist.
func NewRecorder(capturesDir string) *Recorder {
	_ = os.MkdirAll(capturesDir, 0o755)
	return &Recorder{
		capturesDir: capturesDir,
	}
}

// IsRecording returns whether the recorder is currently capturing traffic.
func (rec *Recorder) IsRecording() bool {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.recording
}

// Start begins a new capture session. If already recording, this is a no-op.
func (rec *Recorder) Start() {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.recording {
		return
	}
	rec.openNewFile()
	rec.recording = true
}

// Stop ends the current capture session. If not recording, this is a no-op.
func (rec *Recorder) Stop() {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.recording {
		return
	}
	rec.closeFile()
	rec.recording = false
}

// RecordRequest captures an incoming HTTP request. It is safe for concurrent use.
func (rec *Recorder) RecordRequest(r *http.Request, body []byte) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.recording {
		return
	}
	// We store the request details but write a combined record in RecordResponse.
	// RecordRequest is provided so callers can capture request bodies early,
	// but the actual file write happens in RecordResponse where we have the
	// full round-trip data. This method is intentionally a no-op for the file;
	// callers should hold onto the body bytes and pass them to RecordResponse
	// via the request context or a side channel.
}

// RecordResponse captures a response and writes a combined request+response record.
// The caller should pass the original request's method, path, headers, and body.
func (rec *Recorder) RecordResponse(statusCode int, headers http.Header, body []byte, clientID string, path string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.recording {
		return
	}

	rec.maybeRotate()

	if rec.file == nil {
		return
	}

	respHeaders := make(map[string]string, len(headers))
	for k := range headers {
		respHeaders[k] = headers.Get(k)
	}

	entry := captureRecord{
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		ClientID:        clientID,
		Method:          "", // filled in by caller if needed; path is authoritative
		Path:            path,
		RequestHeaders:  nil,
		RequestBody:     "",
		StatusCode:      statusCode,
		ResponseHeaders: respHeaders,
		ResponseBodySz:  int64(len(body)),
		LatencyMs:       0,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	n, err := rec.file.Write(data)
	if err != nil {
		return
	}
	rec.fileSize += int64(n)
	rec.recordCount.Add(1)
}

// RecordFull writes a complete request+response record with all fields populated.
// This is the preferred recording method when the caller has full round-trip data.
func (rec *Recorder) RecordFull(method, path, clientID string, reqHeaders map[string]string, reqBody []byte,
	statusCode int, respHeaders http.Header, respBodySize int64, latencyMs float64) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.recording {
		return
	}

	rec.maybeRotate()

	if rec.file == nil {
		return
	}

	rh := make(map[string]string, len(respHeaders))
	for k := range respHeaders {
		rh[k] = respHeaders.Get(k)
	}

	var bodyStr string
	if len(reqBody) > 0 {
		bodyStr = string(reqBody)
	}

	entry := captureRecord{
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		ClientID:        clientID,
		Method:          method,
		Path:            path,
		RequestHeaders:  reqHeaders,
		RequestBody:     bodyStr,
		StatusCode:      statusCode,
		ResponseHeaders: rh,
		ResponseBodySz:  respBodySize,
		LatencyMs:       latencyMs,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	n, err := rec.file.Write(data)
	if err != nil {
		return
	}
	rec.fileSize += int64(n)
	rec.recordCount.Add(1)
}

// ShouldHandle returns true if the request path is a captures management endpoint.
func (rec *Recorder) ShouldHandle(path string) bool {
	return path == "/captures/" || path == "/captures" ||
		strings.HasPrefix(path, "/captures/")
}

// ServeHTTP handles capture management API requests and returns the HTTP status code.
func (rec *Recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	// POST /captures/start
	if path == "/captures/start" && r.Method == http.MethodPost {
		return rec.handleStart(w)
	}

	// POST /captures/stop
	if path == "/captures/stop" && r.Method == http.MethodPost {
		return rec.handleStop(w)
	}

	// GET /captures/ or /captures — list captures
	if (path == "/captures/" || path == "/captures") && r.Method == http.MethodGet {
		return rec.handleList(w)
	}

	// GET /captures/{filename} — download a capture file
	// DELETE /captures/{filename} — delete a capture file
	if strings.HasPrefix(path, "/captures/") {
		filename := strings.TrimPrefix(path, "/captures/")
		filename = strings.TrimSuffix(filename, "/")
		if filename == "" {
			return rec.handleList(w)
		}

		// Sanitize: only allow filenames that look like capture files
		if !isValidCaptureFilename(filename) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid filename"}`))
			return http.StatusBadRequest
		}

		switch r.Method {
		case http.MethodGet:
			return rec.handleDownload(w, filename)
		case http.MethodDelete:
			return rec.handleDelete(w, filename)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return http.StatusMethodNotAllowed
		}
	}

	w.WriteHeader(http.StatusNotFound)
	return http.StatusNotFound
}

// GetCaptures returns information about all capture files on disk.
func (rec *Recorder) GetCaptures() []CaptureInfo {
	rec.mu.Lock()
	activeFile := rec.fileName
	rec.mu.Unlock()

	entries, err := os.ReadDir(rec.capturesDir)
	if err != nil {
		return nil
	}

	var captures []CaptureInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "capture_") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		startTime := parseFilenameTime(name)
		records := countLines(filepath.Join(rec.capturesDir, name))

		captures = append(captures, CaptureInfo{
			Filename:  name,
			StartTime: startTime,
			Records:   records,
			SizeBytes: info.Size(),
			IsActive:  name == activeFile,
		})
	}

	return captures
}

// --- internal methods ---

// openNewFile creates a new capture JSONL file. Must be called with mu held.
func (rec *Recorder) openNewFile() {
	now := time.Now()
	name := fmt.Sprintf("capture_%s.jsonl", now.Format("20060102_150405"))
	path := filepath.Join(rec.capturesDir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}

	rec.file = f
	rec.fileName = name
	rec.fileStart = now
	rec.fileSize = 0
	rec.recordCount.Store(0)
}

// closeFile closes the current capture file. Must be called with mu held.
func (rec *Recorder) closeFile() {
	if rec.file != nil {
		_ = rec.file.Close()
		rec.file = nil
		rec.fileName = ""
	}
}

// maybeRotate checks size and duration limits and rotates the file if needed.
// Must be called with mu held.
func (rec *Recorder) maybeRotate() {
	if rec.file == nil {
		rec.openNewFile()
		return
	}

	needRotate := rec.fileSize >= maxFileSize || time.Since(rec.fileStart) >= maxFileDuration
	if needRotate {
		rec.closeFile()
		rec.openNewFile()
	}
}

// handleStart begins recording and returns the response.
func (rec *Recorder) handleStart(w http.ResponseWriter) int {
	rec.mu.Lock()
	alreadyRecording := rec.recording
	if !alreadyRecording {
		rec.openNewFile()
		rec.recording = true
	}
	filename := rec.fileName
	rec.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"status": "recording",
		"file":   filename,
	}
	data, _ := json.Marshal(resp)
	_, _ = w.Write(data)
	return http.StatusOK
}

// handleStop stops recording and returns the response.
func (rec *Recorder) handleStop(w http.ResponseWriter) int {
	rec.mu.Lock()
	wasRecording := rec.recording
	records := rec.recordCount.Load()
	if wasRecording {
		rec.closeFile()
		rec.recording = false
	}
	rec.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]interface{}{
		"status":  "stopped",
		"records": records,
	}
	if !wasRecording {
		resp["status"] = "not_recording"
	}
	data, _ := json.Marshal(resp)
	_, _ = w.Write(data)
	return http.StatusOK
}

// handleList returns a JSON array of all capture files.
func (rec *Recorder) handleList(w http.ResponseWriter) int {
	captures := rec.GetCaptures()
	if captures == nil {
		captures = []CaptureInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	data, _ := json.Marshal(captures)
	_, _ = w.Write(data)
	return http.StatusOK
}

// handleDownload serves a capture file for download.
func (rec *Recorder) handleDownload(w http.ResponseWriter, filename string) int {
	path := filepath.Join(rec.capturesDir, filename)

	info, err := os.Stat(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"file not found"}`))
		return http.StatusNotFound
	}

	f, err := os.Open(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"cannot open file"}`))
		return http.StatusInternalServerError
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.WriteHeader(http.StatusOK)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}

	return http.StatusOK
}

// handleDelete removes a capture file from disk.
func (rec *Recorder) handleDelete(w http.ResponseWriter, filename string) int {
	// Don't allow deleting the active file
	rec.mu.Lock()
	activeFile := rec.fileName
	rec.mu.Unlock()

	if filename == activeFile {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"cannot delete active capture file"}`))
		return http.StatusConflict
	}

	path := filepath.Join(rec.capturesDir, filename)
	err := os.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"file not found"}`))
			return http.StatusNotFound
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"delete failed"}`))
		return http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"deleted":true}`))
	return http.StatusOK
}

// --- helpers ---

// isValidCaptureFilename checks that a filename looks like a capture file
// and does not contain path traversal characters.
func isValidCaptureFilename(name string) bool {
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return false
	}
	return strings.HasPrefix(name, "capture_") && strings.HasSuffix(name, ".jsonl")
}

// parseFilenameTime extracts the timestamp from a capture filename.
func parseFilenameTime(name string) time.Time {
	// capture_20060102_150405.jsonl
	name = strings.TrimPrefix(name, "capture_")
	name = strings.TrimSuffix(name, ".jsonl")
	t, err := time.Parse("20060102_150405", name)
	if err != nil {
		return time.Time{}
	}
	return t
}

// countLines counts the number of lines (records) in a file.
func countLines(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	var count int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				count++
			}
		}
		if readErr != nil {
			break
		}
	}
	return count
}
