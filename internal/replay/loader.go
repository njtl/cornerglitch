// Package replay provides pcap and JSONL capture file loading and replay.
package replay

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
