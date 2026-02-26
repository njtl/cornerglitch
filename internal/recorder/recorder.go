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

// writeMsg carries pre-marshaled data to the background writer goroutine.
type writeMsg struct {
	data []byte   // marshaled JSON + newline (for JSONL)
	pcap *pcapMsg // for PCAP format
}

// pcapMsg carries PCAP write parameters to the background writer.
type pcapMsg struct {
	hasRequest  bool
	method      string
	path        string
	host        string
	reqHeaders  map[string]string
	reqBody     string
	statusCode  int
	respHeaders map[string]string
	respBodySz  int64
}

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

// RecorderStatus describes the current state of the recorder.
type RecorderStatus struct {
	Recording   bool    `json:"recording"`
	Format      string  `json:"format"`
	FileName    string  `json:"file_name"`
	Records     int64   `json:"records"`
	SizeBytes   int64   `json:"size_bytes"`
	ElapsedSec  float64 `json:"elapsed_sec"`
	MaxDuration int     `json:"max_duration_sec"`
	MaxRequests int64   `json:"max_requests"`
}

// Recorder handles HTTP traffic capture to JSONL or PCAP files.
type Recorder struct {
	capturesDir string

	mu          sync.Mutex
	recording   bool
	format      string // "jsonl" (default) or "pcap"
	file        *os.File
	pcapWriter  *PCAPWriter
	fileName    string
	fileStart   time.Time
	fileSize    int64
	recordCount atomic.Int64

	// Async writer
	writeCh    chan writeMsg
	writerDone chan struct{} // closed when writer goroutine exits

	// Recording limits
	maxDuration time.Duration // 0 = unlimited
	maxRequests int64         // 0 = unlimited
	stopTimer   *time.Timer
	startedAt   time.Time

	// Cache for closed-file record counts (filename -> count).
	// Closed capture files are immutable so counts never change.
	recordCountCache sync.Map

	// Cached result of GetCaptures() to avoid repeated ReadDir + Stat on every
	// dashboard refresh. Invalidated after capturesCacheTTL or when recording
	// state changes.
	capturesCache    []CaptureInfo
	capturesCacheAt  time.Time
}

// NewRecorder creates a new Recorder that stores captures in capturesDir.
// The directory is created if it does not exist.
func NewRecorder(capturesDir string) *Recorder {
	_ = os.MkdirAll(capturesDir, 0o755)
	return &Recorder{
		capturesDir: capturesDir,
		format:      "jsonl",
	}
}

// SetFormat sets the capture format ("jsonl" or "pcap"). Must not be called
// while recording is active — the format takes effect on the next Start.
func (rec *Recorder) SetFormat(format string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if format == "pcap" || format == "jsonl" {
		rec.format = format
	}
}

// GetFormat returns the current capture format.
func (rec *Recorder) GetFormat() string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.format
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
	rec.startLocked()
}

// startLocked sets up a new capture session. Must be called with mu held.
func (rec *Recorder) startLocked() {
	rec.openNewFile()
	rec.recording = true
	rec.startedAt = time.Now()
	rec.capturesCache = nil // invalidate
	rec.writeCh = make(chan writeMsg, 8192)
	rec.writerDone = make(chan struct{})
	go rec.writerLoop(rec.writeCh, rec.writerDone)
}

// Stop ends the current capture session. If not recording, this is a no-op.
// It signals the background writer to drain pending writes, waits for it to
// finish, then closes the capture file.
func (rec *Recorder) Stop() {
	rec.mu.Lock()
	if !rec.recording {
		rec.mu.Unlock()
		return
	}
	rec.recording = false
	if rec.stopTimer != nil {
		rec.stopTimer.Stop()
		rec.stopTimer = nil
	}
	rec.maxDuration = 0
	rec.maxRequests = 0
	ch := rec.writeCh
	done := rec.writerDone
	rec.writeCh = nil
	rec.writerDone = nil
	rec.capturesCache = nil // invalidate
	rec.mu.Unlock()

	// Close the channel so the writer drains and exits.
	if ch != nil {
		close(ch)
	}
	if done != nil {
		<-done
	}

	// Now safe to close the file — writer is done.
	rec.mu.Lock()
	rec.closeFile()
	rec.mu.Unlock()
}

// StartWithLimits begins a new capture session with optional limits.
// maxDurationSec <= 0 means no duration limit; maxRequests <= 0 means no request limit.
// If already recording, this is a no-op.
func (rec *Recorder) StartWithLimits(maxDurationSec int, maxRequests int64) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.recording {
		return
	}

	if maxDurationSec > 0 {
		rec.maxDuration = time.Duration(maxDurationSec) * time.Second
	} else {
		rec.maxDuration = 0
	}
	if maxRequests > 0 {
		rec.maxRequests = maxRequests
	} else {
		rec.maxRequests = 0
	}

	rec.startLocked()

	if rec.maxDuration > 0 {
		rec.stopTimer = time.AfterFunc(rec.maxDuration, func() {
			rec.Stop()
		})
	}
}

// GetStatus returns the current status of the recorder.
func (rec *Recorder) GetStatus() RecorderStatus {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	status := RecorderStatus{
		Recording: rec.recording,
		Format:    rec.format,
		FileName:  rec.fileName,
		Records:   rec.recordCount.Load(),
		SizeBytes: rec.fileSize,
	}

	if rec.recording && !rec.startedAt.IsZero() {
		status.ElapsedSec = time.Since(rec.startedAt).Seconds()
	}

	if rec.maxDuration > 0 {
		status.MaxDuration = int(rec.maxDuration.Seconds())
	}
	status.MaxRequests = rec.maxRequests

	return status
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
// Data is marshaled outside the mutex and sent to a buffered channel for async disk I/O.
func (rec *Recorder) RecordResponse(statusCode int, headers http.Header, body []byte, clientID string, path string) {
	rec.mu.Lock()
	if !rec.recording {
		rec.mu.Unlock()
		return
	}
	format := rec.format
	ch := rec.writeCh
	maxReq := rec.maxRequests
	rec.mu.Unlock()

	// Pre-check: reject if maxRequests already reached (async stop may be in flight).
	if maxReq > 0 && rec.recordCount.Load() >= maxReq {
		return
	}

	respHeaders := make(map[string]string, len(headers))
	for k := range headers {
		respHeaders[k] = headers.Get(k)
	}

	var msg writeMsg
	if format == "pcap" {
		msg = writeMsg{
			pcap: &pcapMsg{
				statusCode:  statusCode,
				respHeaders: respHeaders,
				respBodySz:  int64(len(body)),
			},
		}
	} else {
		entry := captureRecord{
			Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
			ClientID:        clientID,
			Path:            path,
			StatusCode:      statusCode,
			ResponseHeaders: respHeaders,
			ResponseBodySz:  int64(len(body)),
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		data = append(data, '\n')
		msg = writeMsg{data: data}
	}

	if safeSend(ch, msg) {
		newCount := rec.recordCount.Add(1)
		if rec.maxRequests > 0 && newCount >= rec.maxRequests {
			go rec.Stop()
		}
	}
}

// RecordFull writes a complete request+response record with all fields populated.
// This is the preferred recording method when the caller has full round-trip data.
// Data is marshaled outside the mutex and sent to a buffered channel for async disk I/O.
func (rec *Recorder) RecordFull(method, path, clientID string, reqHeaders map[string]string, reqBody []byte,
	statusCode int, respHeaders http.Header, respBodySize int64, latencyMs float64) {
	rec.mu.Lock()
	if !rec.recording {
		rec.mu.Unlock()
		return
	}
	format := rec.format
	ch := rec.writeCh
	maxReq := rec.maxRequests
	rec.mu.Unlock()

	// Pre-check: reject if maxRequests already reached (async stop may be in flight).
	if maxReq > 0 && rec.recordCount.Load() >= maxReq {
		return
	}

	rh := make(map[string]string, len(respHeaders))
	for k := range respHeaders {
		rh[k] = respHeaders.Get(k)
	}

	var msg writeMsg
	if format == "pcap" {
		host := ""
		if reqHeaders != nil {
			host = reqHeaders["Host"]
		}
		if host == "" {
			host = "localhost"
		}

		var bodyStr string
		if len(reqBody) > 0 {
			bodyStr = string(reqBody)
		}

		msg = writeMsg{
			pcap: &pcapMsg{
				hasRequest:  true,
				method:      method,
				path:        path,
				host:        host,
				reqHeaders:  reqHeaders,
				reqBody:     bodyStr,
				statusCode:  statusCode,
				respHeaders: rh,
				respBodySz:  respBodySize,
			},
		}
	} else {
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
		msg = writeMsg{data: data}
	}

	if safeSend(ch, msg) {
		newCount := rec.recordCount.Add(1)
		if rec.maxRequests > 0 && newCount >= rec.maxRequests {
			go rec.Stop()
		}
	}
}

// writerLoop is the background goroutine that performs disk I/O for recorded
// traffic. It reads from ch until the channel is closed, then exits. All file
// writes and rotations happen under rec.mu so they remain safe.
func (rec *Recorder) writerLoop(ch chan writeMsg, done chan struct{}) {
	defer close(done)
	for msg := range ch {
		rec.mu.Lock()
		rec.maybeRotate()
		if msg.pcap != nil {
			if rec.pcapWriter != nil {
				if msg.pcap.hasRequest {
					_ = rec.pcapWriter.WriteHTTPRequest(msg.pcap.method, msg.pcap.path, msg.pcap.host, msg.pcap.reqHeaders, msg.pcap.reqBody)
				}
				_ = rec.pcapWriter.WriteHTTPResponse(msg.pcap.statusCode, msg.pcap.respHeaders, msg.pcap.respBodySz)
				rec.fileSize = rec.pcapWriter.Size()
			}
		} else if msg.data != nil {
			if rec.file != nil {
				n, _ := rec.file.Write(msg.data)
				rec.fileSize += int64(n)
			}
		}
		rec.mu.Unlock()
	}
}

// safeSend attempts a non-blocking send to ch. Returns true if the message was
// sent. Returns false if the channel is full (back-pressure) or closed (race
// with Stop). Recording is best-effort under extreme load, so drops are
// acceptable.
func safeSend(ch chan writeMsg, msg writeMsg) (sent bool) {
	defer func() { recover() }()
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
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
		return rec.handleStart(w, r)
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
const capturesCacheTTL = 2 * time.Second

func (rec *Recorder) GetCaptures() []CaptureInfo {
	rec.mu.Lock()
	activeFile := rec.fileName
	activeCount := rec.recordCount.Load()
	cached := rec.capturesCache
	cachedAt := rec.capturesCacheAt
	rec.mu.Unlock()

	// Return cached result if fresh. For the active file, patch in the live
	// record count so the dashboard shows real-time progress.
	if cached != nil && time.Since(cachedAt) < capturesCacheTTL {
		if activeFile == "" {
			return cached
		}
		// Shallow-copy and patch active file's record count.
		result := make([]CaptureInfo, len(cached))
		copy(result, cached)
		for i := range result {
			if result[i].IsActive {
				result[i].Records = activeCount
			}
		}
		return result
	}

	captures := rec.getCapuresUncached(activeFile, activeCount)

	rec.mu.Lock()
	rec.capturesCache = captures
	rec.capturesCacheAt = time.Now()
	rec.mu.Unlock()

	return captures
}

// InvalidateCapturesCache forces the next GetCaptures call to re-scan the directory.
func (rec *Recorder) InvalidateCapturesCache() {
	rec.mu.Lock()
	rec.capturesCache = nil
	rec.mu.Unlock()
}

func (rec *Recorder) getCapuresUncached(activeFile string, activeCount int64) []CaptureInfo {
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
		if !strings.HasPrefix(name, "capture_") ||
			(!strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".pcap")) {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		startTime := parseFilenameTime(name)
		isActive := name == activeFile

		var records int64
		if isActive {
			records = activeCount
		} else if c, ok := rec.recordCountCache.Load(name); ok {
			records = c.(int64)
		} else {
			records = countRecords(filepath.Join(rec.capturesDir, name), name)
			rec.recordCountCache.Store(name, records)
		}

		captures = append(captures, CaptureInfo{
			Filename:  name,
			StartTime: startTime,
			Records:   records,
			SizeBytes: info.Size(),
			IsActive:  isActive,
		})
	}

	return captures
}

// countRecords returns the record count for a capture file.
// For JSONL files, it counts newlines. For PCAP files, it counts packet headers.
func countRecords(path, name string) int64 {
	if strings.HasSuffix(name, ".pcap") {
		return countPCAPRecords(path)
	}
	return countLines(path)
}

// countPCAPRecords counts the number of PCAP packet records by scanning headers.
func countPCAPRecords(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Skip 24-byte global header.
	if _, err := f.Seek(24, 0); err != nil {
		return 0
	}

	var count int64
	hdr := make([]byte, 16) // each packet record header is 16 bytes
	for {
		if _, err := f.Read(hdr); err != nil {
			break
		}
		// inclLen is at offset 8, 4 bytes, little-endian.
		inclLen := int64(hdr[8]) | int64(hdr[9])<<8 | int64(hdr[10])<<16 | int64(hdr[11])<<24
		if _, err := f.Seek(inclLen, 1); err != nil {
			break
		}
		count++
	}
	return count
}

// --- internal methods ---

// openNewFile creates a new capture file (JSONL or PCAP). Must be called with mu held.
func (rec *Recorder) openNewFile() {
	now := time.Now()

	if rec.format == "pcap" {
		name := fmt.Sprintf("capture_%s.pcap", now.Format("20060102_150405"))
		path := filepath.Join(rec.capturesDir, name)
		pw, err := NewPCAPWriter(path)
		if err != nil {
			return
		}
		rec.pcapWriter = pw
		rec.file = nil
		rec.fileName = name
		rec.fileStart = now
		rec.fileSize = 24 // global header size
		rec.recordCount.Store(0)
		return
	}

	// Default: JSONL
	name := fmt.Sprintf("capture_%s.jsonl", now.Format("20060102_150405"))
	path := filepath.Join(rec.capturesDir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}

	rec.file = f
	rec.pcapWriter = nil
	rec.fileName = name
	rec.fileStart = now
	rec.fileSize = 0
	rec.recordCount.Store(0)
}

// closeFile closes the current capture file. Must be called with mu held.
func (rec *Recorder) closeFile() {
	if rec.pcapWriter != nil {
		_ = rec.pcapWriter.Close()
		rec.pcapWriter = nil
	}
	if rec.file != nil {
		_ = rec.file.Close()
		rec.file = nil
	}
	rec.fileName = ""
}

// maybeRotate checks size and duration limits and rotates the file if needed.
// Must be called with mu held.
func (rec *Recorder) maybeRotate() {
	if rec.file == nil && rec.pcapWriter == nil {
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
// Accepts optional JSON body: {"format":"pcap"} or {"format":"jsonl"}.
func (rec *Recorder) handleStart(w http.ResponseWriter, r *http.Request) int {
	// Try to read format from request body.
	var reqBody struct {
		Format string `json:"format"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
	}

	rec.mu.Lock()
	alreadyRecording := rec.recording
	if !alreadyRecording {
		if reqBody.Format == "pcap" {
			rec.format = "pcap"
		} else if reqBody.Format == "jsonl" || reqBody.Format == "" {
			rec.format = "jsonl"
		}
		rec.startLocked()
	}
	filename := rec.fileName
	format := rec.format
	rec.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"status": "recording",
		"file":   filename,
		"format": format,
	}
	data, _ := json.Marshal(resp)
	_, _ = w.Write(data)
	return http.StatusOK
}

// handleStop stops recording and returns the response.
func (rec *Recorder) handleStop(w http.ResponseWriter) int {
	wasRecording := rec.IsRecording()
	records := rec.recordCount.Load()
	if wasRecording {
		rec.Stop()
	}

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

	contentType := "application/x-ndjson"
	if strings.HasSuffix(filename, ".pcap") {
		contentType = "application/vnd.tcpdump.pcap"
	}
	w.Header().Set("Content-Type", contentType)
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

	rec.InvalidateCapturesCache()
	rec.recordCountCache.Delete(filename)

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
	return strings.HasPrefix(name, "capture_") &&
		(strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".pcap"))
}

// parseFilenameTime extracts the timestamp from a capture filename.
func parseFilenameTime(name string) time.Time {
	// capture_20060102_150405.jsonl or capture_20060102_150405.pcap
	name = strings.TrimPrefix(name, "capture_")
	name = strings.TrimSuffix(name, ".jsonl")
	name = strings.TrimSuffix(name, ".pcap")
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
