// Package replay provides pcap and JSONL capture file loading and replay.
package replay

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Packet represents a single HTTP request extracted from a capture.
type Packet struct {
	Timestamp  time.Time         `json:"timestamp"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Host       string            `json:"host"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	IsRequest  bool              `json:"is_request"`
	StatusCode int               `json:"status_code,omitempty"`
}

// PCAP format constants (matching internal/recorder/pcap.go).
const (
	pcapMagic         = 0xa1b2c3d4
	pcapGlobalHdrLen  = 24
	pcapRecordHdrLen  = 16
	ethernetHeaderLen = 14
	ipv4HeaderLen     = 20
	tcpHeaderLen      = 20
	allHeadersLen     = ethernetHeaderLen + ipv4HeaderLen + tcpHeaderLen
)

// LoadFile auto-detects the capture format from the file extension.
func LoadFile(path string) ([]*Packet, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pcap":
		return LoadPCAP(path)
	case ".jsonl":
		return LoadJSONL(path)
	default:
		return nil, fmt.Errorf("unsupported capture format: %s", ext)
	}
}

// LoadPCAP reads a pcap file and extracts HTTP request packets.
func LoadPCAP(path string) ([]*Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	// Read global header (24 bytes).
	ghdr := make([]byte, pcapGlobalHdrLen)
	if _, err := f.Read(ghdr); err != nil {
		return nil, fmt.Errorf("read pcap global header: %w", err)
	}

	magic := binary.LittleEndian.Uint32(ghdr[0:4])
	if magic != pcapMagic {
		return nil, fmt.Errorf("invalid pcap magic: 0x%x (expected 0x%x)", magic, pcapMagic)
	}

	var packets []*Packet

	for {
		// Read per-packet record header (16 bytes).
		recHdr := make([]byte, pcapRecordHdrLen)
		n, err := f.Read(recHdr)
		if n == 0 || err != nil {
			break // EOF
		}
		if n < pcapRecordHdrLen {
			break
		}

		tsSec := binary.LittleEndian.Uint32(recHdr[0:4])
		tsUsec := binary.LittleEndian.Uint32(recHdr[4:8])
		inclLen := binary.LittleEndian.Uint32(recHdr[8:12])

		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)

		// Read packet data.
		if inclLen == 0 || inclLen > 1<<20 {
			break // sanity check
		}
		data := make([]byte, inclLen)
		n, err = f.Read(data)
		if n < int(inclLen) {
			break
		}

		// Skip Ethernet + IPv4 + TCP headers to get to HTTP payload.
		if int(inclLen) <= allHeadersLen {
			continue
		}
		payload := data[allHeadersLen:]

		pkt := parseHTTPPayload(payload, ts)
		if pkt != nil {
			packets = append(packets, pkt)
		}
	}

	return packets, nil
}

// parseHTTPPayload tries to parse an HTTP request or response from raw bytes.
func parseHTTPPayload(payload []byte, ts time.Time) *Packet {
	s := string(payload)

	// Try HTTP request: "METHOD PATH HTTP/1.x\r\n..."
	if idx := strings.Index(s, "\r\n"); idx > 0 {
		line := s[:idx]
		parts := strings.SplitN(line, " ", 3)
		if len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/") {
			// It's an HTTP request.
			pkt := &Packet{
				Timestamp: ts,
				Method:    parts[0],
				Path:      parts[1],
				IsRequest: true,
				Headers:   make(map[string]string),
			}

			// Parse headers.
			headerSection := s[idx+2:]
			parseHeaders(headerSection, pkt)
			return pkt
		}

		// Try HTTP response: "HTTP/1.x STATUS REASON\r\n..."
		if strings.HasPrefix(parts[0], "HTTP/") && len(parts) >= 2 {
			var statusCode int
			fmt.Sscanf(parts[1], "%d", &statusCode)
			pkt := &Packet{
				Timestamp:  ts,
				IsRequest:  false,
				StatusCode: statusCode,
				Headers:    make(map[string]string),
			}
			headerSection := s[idx+2:]
			parseHeaders(headerSection, pkt)
			return pkt
		}
	}

	return nil
}

func parseHeaders(s string, pkt *Packet) {
	lines := strings.Split(s, "\r\n")
	for _, line := range lines {
		if line == "" {
			break // end of headers
		}
		if idx := strings.Index(line, ": "); idx > 0 {
			key := line[:idx]
			val := line[idx+2:]
			pkt.Headers[key] = val
			if strings.EqualFold(key, "Host") {
				pkt.Host = val
			}
		}
	}
}

// jsonlRecord matches the JSONL format from internal/recorder/recorder.go.
type jsonlRecord struct {
	Timestamp  string            `json:"timestamp"`
	Type       string            `json:"type"` // "request" or "response"
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Host       string            `json:"host"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	StatusCode int               `json:"status_code"`
}

// LoadJSONL reads a JSONL capture file and extracts packets.
func LoadJSONL(path string) ([]*Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open jsonl: %w", err)
	}
	defer f.Close()

	var packets []*Packet
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec jsonlRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		ts, _ := time.Parse(time.RFC3339Nano, rec.Timestamp)

		pkt := &Packet{
			Timestamp:  ts,
			Method:     rec.Method,
			Path:       rec.Path,
			Host:       rec.Host,
			Headers:    rec.Headers,
			IsRequest:  rec.Type == "request" || rec.Type == "",
			StatusCode: rec.StatusCode,
		}
		if rec.Body != "" {
			pkt.Body = []byte(rec.Body)
		}
		if pkt.Headers == nil {
			pkt.Headers = make(map[string]string)
		}

		packets = append(packets, pkt)
	}

	return packets, nil
}

// LoadFromReader loads packets from an io.Reader, auto-detecting format by
// the provided filename extension (.pcap or .jsonl).
func LoadFromReader(r io.Reader, filename string) ([]*Packet, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pcap":
		return loadPCAPFromReader(r)
	case ".jsonl":
		return loadJSONLFromReader(r)
	default:
		return nil, fmt.Errorf("unsupported capture format: %s", ext)
	}
}

// loadPCAPFromReader reads pcap data from an io.Reader.
func loadPCAPFromReader(r io.Reader) ([]*Packet, error) {
	// Read global header (24 bytes).
	ghdr := make([]byte, pcapGlobalHdrLen)
	if _, err := io.ReadFull(r, ghdr); err != nil {
		return nil, fmt.Errorf("read pcap global header: %w", err)
	}

	magic := binary.LittleEndian.Uint32(ghdr[0:4])
	if magic != pcapMagic {
		return nil, fmt.Errorf("invalid pcap magic: 0x%x (expected 0x%x)", magic, pcapMagic)
	}

	var packets []*Packet

	for {
		recHdr := make([]byte, pcapRecordHdrLen)
		_, err := io.ReadFull(r, recHdr)
		if err != nil {
			break // EOF or short read
		}

		tsSec := binary.LittleEndian.Uint32(recHdr[0:4])
		tsUsec := binary.LittleEndian.Uint32(recHdr[4:8])
		inclLen := binary.LittleEndian.Uint32(recHdr[8:12])

		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)

		if inclLen == 0 || inclLen > 1<<20 {
			break // sanity check
		}
		data := make([]byte, inclLen)
		_, err = io.ReadFull(r, data)
		if err != nil {
			break
		}

		if int(inclLen) <= allHeadersLen {
			continue
		}
		payload := data[allHeadersLen:]

		pkt := parseHTTPPayload(payload, ts)
		if pkt != nil {
			packets = append(packets, pkt)
		}
	}

	return packets, nil
}

// loadJSONLFromReader reads JSONL data from an io.Reader.
func loadJSONLFromReader(r io.Reader) ([]*Packet, error) {
	var packets []*Packet
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec jsonlRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		ts, _ := time.Parse(time.RFC3339Nano, rec.Timestamp)

		pkt := &Packet{
			Timestamp:  ts,
			Method:     rec.Method,
			Path:       rec.Path,
			Host:       rec.Host,
			Headers:    rec.Headers,
			IsRequest:  rec.Type == "request" || rec.Type == "",
			StatusCode: rec.StatusCode,
		}
		if rec.Body != "" {
			pkt.Body = []byte(rec.Body)
		}
		if pkt.Headers == nil {
			pkt.Headers = make(map[string]string)
		}

		packets = append(packets, pkt)
	}

	return packets, nil
}

// ParseMetadata analyzes loaded packets and returns summary metadata.
func ParseMetadata(packets []*Packet) map[string]interface{} {
	result := map[string]interface{}{
		"total_packets":    0,
		"total_requests":   0,
		"total_responses":  0,
		"methods":          map[string]int{},
		"status_codes":     map[int]int{},
		"unique_hosts":     []string{},
		"unique_paths":     0,
		"top_paths":        []map[string]interface{}{},
		"time_span_ms":     int64(0),
		"time_start":       "",
		"time_end":         "",
		"avg_request_size": 0,
		"protocols":        []string{},
	}

	if len(packets) == 0 {
		return result
	}

	methods := map[string]int{}
	statusCodes := map[int]int{}
	hosts := map[string]bool{}
	paths := map[string]int{}
	protocols := map[string]bool{}
	totalRequestSize := 0
	requestCount := 0
	responseCount := 0

	var earliest, latest time.Time

	for i, pkt := range packets {
		if i == 0 || pkt.Timestamp.Before(earliest) {
			earliest = pkt.Timestamp
		}
		if i == 0 || pkt.Timestamp.After(latest) {
			latest = pkt.Timestamp
		}

		if pkt.IsRequest {
			requestCount++
			if pkt.Method != "" {
				methods[pkt.Method]++
			}
			if pkt.Path != "" {
				paths[pkt.Path]++
			}
			if pkt.Host != "" {
				hosts[pkt.Host] = true
			}
			totalRequestSize += len(pkt.Body)
			for k, v := range pkt.Headers {
				totalRequestSize += len(k) + len(v)
			}
			// Detect protocol from headers or default
			protocols["HTTP/1.1"] = true
		} else {
			responseCount++
			if pkt.StatusCode > 0 {
				statusCodes[pkt.StatusCode]++
			}
		}
	}

	// Build unique hosts list.
	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)

	// Build top paths (sorted by count, top 10).
	type pathCount struct {
		Path  string
		Count int
	}
	pathSlice := make([]pathCount, 0, len(paths))
	for p, c := range paths {
		pathSlice = append(pathSlice, pathCount{p, c})
	}
	sort.Slice(pathSlice, func(i, j int) bool {
		return pathSlice[i].Count > pathSlice[j].Count
	})
	topN := 10
	if len(pathSlice) < topN {
		topN = len(pathSlice)
	}
	topPaths := make([]map[string]interface{}, topN)
	for i := 0; i < topN; i++ {
		topPaths[i] = map[string]interface{}{
			"path":  pathSlice[i].Path,
			"count": pathSlice[i].Count,
		}
	}

	// Build protocol list.
	protoList := make([]string, 0, len(protocols))
	for p := range protocols {
		protoList = append(protoList, p)
	}
	sort.Strings(protoList)

	avgReqSize := 0
	if requestCount > 0 {
		avgReqSize = totalRequestSize / requestCount
	}

	var timeSpanMs int64
	timeStart := ""
	timeEnd := ""
	if !earliest.IsZero() {
		timeStart = earliest.Format(time.RFC3339)
	}
	if !latest.IsZero() {
		timeEnd = latest.Format(time.RFC3339)
	}
	if !earliest.IsZero() && !latest.IsZero() {
		timeSpanMs = latest.Sub(earliest).Milliseconds()
	}

	result["total_packets"] = len(packets)
	result["total_requests"] = requestCount
	result["total_responses"] = responseCount
	result["methods"] = methods
	result["status_codes"] = statusCodes
	result["unique_hosts"] = hostList
	result["unique_paths"] = len(paths)
	result["top_paths"] = topPaths
	result["time_span_ms"] = timeSpanMs
	result["time_start"] = timeStart
	result["time_end"] = timeEnd
	result["avg_request_size"] = avgReqSize
	result["protocols"] = protoList

	return result
}
