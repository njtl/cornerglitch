package recorder

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

// PCAP file format constants.
const (
	pcapMagic      = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	pcapSnapLen    = 65535
	pcapNetwork    = 1 // LINKTYPE_ETHERNET

	ethernetHeaderLen = 14
	ipv4HeaderLen     = 20
	tcpHeaderLen      = 20
	allHeadersLen     = ethernetHeaderLen + ipv4HeaderLen + tcpHeaderLen
)

// PCAPWriter writes packets to a pcap file using only Go stdlib.
// The resulting file has valid pcap magic bytes and can be opened by Wireshark.
type PCAPWriter struct {
	file *os.File
	mu   sync.Mutex
	rng  *rand.Rand
}

// NewPCAPWriter creates a new pcap file at path and writes the global header.
func NewPCAPWriter(path string) (*PCAPWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("pcap: create file: %w", err)
	}

	pw := &PCAPWriter{
		file: f,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	if err := pw.writeGlobalHeader(); err != nil {
		f.Close()
		return nil, fmt.Errorf("pcap: write global header: %w", err)
	}

	return pw, nil
}

// writeGlobalHeader writes the 24-byte pcap global header.
func (pw *PCAPWriter) writeGlobalHeader() error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)  // thiszone (int32, zero)
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], pcapNetwork)
	_, err := pw.file.Write(hdr)
	return err
}

// WritePacket writes a single packet with fake Ethernet/IP/TCP headers wrapping
// the given payload. srcIP and dstIP should be dotted-quad strings (e.g. "10.0.0.1").
func (pw *PCAPWriter) WritePacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file == nil {
		return fmt.Errorf("pcap: writer is closed")
	}

	totalLen := allHeadersLen + len(payload)

	// --- pcap per-packet record header (16 bytes) ---
	now := time.Now()
	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:8], uint32(now.Nanosecond()/1000)) // microseconds
	binary.LittleEndian.PutUint32(recHdr[8:12], uint32(totalLen))             // incl_len
	binary.LittleEndian.PutUint32(recHdr[12:16], uint32(totalLen))            // orig_len

	// --- Ethernet header (14 bytes) ---
	eth := make([]byte, ethernetHeaderLen)
	// dst MAC: 00:00:5e:00:53:01 (documentation range)
	eth[0], eth[1], eth[2], eth[3], eth[4], eth[5] = 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01
	// src MAC: 00:00:5e:00:53:02
	eth[6], eth[7], eth[8], eth[9], eth[10], eth[11] = 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02
	// EtherType: IPv4 (0x0800)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	// --- IPv4 header (20 bytes) ---
	ipTotalLen := ipv4HeaderLen + tcpHeaderLen + len(payload)
	ip := make([]byte, ipv4HeaderLen)
	ip[0] = 0x45 // version=4, IHL=5 (20 bytes)
	ip[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen))
	binary.BigEndian.PutUint16(ip[4:6], uint16(pw.rng.Intn(65536))) // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)                     // flags: Don't Fragment
	ip[8] = 64                                                       // TTL
	ip[9] = 6                                                        // protocol: TCP
	// ip[10:12] = checksum (leave zero for simplicity; Wireshark will note it)
	copy(ip[12:16], parseIPv4(srcIP))
	copy(ip[16:20], parseIPv4(dstIP))
	// Compute IP header checksum
	putIPChecksum(ip)

	// --- TCP header (20 bytes) ---
	tcp := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], uint32(pw.rng.Int31()))  // sequence number
	binary.BigEndian.PutUint32(tcp[8:12], uint32(pw.rng.Int31())) // ack number
	tcp[12] = 0x50 // data offset: 5 words (20 bytes), no options
	tcp[13] = 0x18 // flags: PSH + ACK
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window size
	// tcp[16:18] = checksum (leave zero)
	// tcp[18:20] = urgent pointer (zero)

	// Write everything in one go to minimize syscalls
	buf := make([]byte, 0, 16+totalLen)
	buf = append(buf, recHdr...)
	buf = append(buf, eth...)
	buf = append(buf, ip...)
	buf = append(buf, tcp...)
	buf = append(buf, payload...)

	_, err := pw.file.Write(buf)
	return err
}

// WriteHTTPRequest writes a fake HTTP request packet to the pcap file.
// Uses client IP 10.0.0.1 with a random source port, server IP 10.0.0.2 port 80.
func (pw *PCAPWriter) WriteHTTPRequest(method, path, host string, headers map[string]string, body string) error {
	payload := buildHTTPRequest(method, path, host, headers, body)

	pw.mu.Lock()
	srcPort := uint16(1024 + pw.rng.Intn(64511))
	pw.mu.Unlock()

	return pw.WritePacket("10.0.0.1", "10.0.0.2", srcPort, 80, payload)
}

// WriteHTTPResponse writes a fake HTTP response packet to the pcap file.
// Uses server IP 10.0.0.2 port 80, client IP 10.0.0.1 with a random destination port.
func (pw *PCAPWriter) WriteHTTPResponse(statusCode int, headers map[string]string, bodySize int64) error {
	payload := buildHTTPResponse(statusCode, headers, bodySize)

	pw.mu.Lock()
	dstPort := uint16(1024 + pw.rng.Intn(64511))
	pw.mu.Unlock()

	return pw.WritePacket("10.0.0.2", "10.0.0.1", 80, dstPort, payload)
}

// Close closes the underlying file.
func (pw *PCAPWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file == nil {
		return nil
	}
	err := pw.file.Close()
	pw.file = nil
	return err
}

// Size returns the current size of the pcap file in bytes.
func (pw *PCAPWriter) Size() int64 {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file == nil {
		return 0
	}
	info, err := pw.file.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}

// --- helpers ---

// parseIPv4 parses a dotted-quad IP string into a 4-byte slice.
// Returns 0.0.0.0 on failure.
func parseIPv4(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return []byte{0, 0, 0, 0}
	}
	v4 := ip.To4()
	if v4 == nil {
		return []byte{0, 0, 0, 0}
	}
	return v4
}

// putIPChecksum computes the IPv4 header checksum and writes it into bytes 10-11.
func putIPChecksum(hdr []byte) {
	// Clear checksum field
	hdr[10] = 0
	hdr[11] = 0

	var sum uint32
	for i := 0; i < len(hdr)-1; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	cs := ^uint16(sum)
	binary.BigEndian.PutUint16(hdr[10:12], cs)
}

// buildHTTPRequest constructs the text of an HTTP/1.1 request.
func buildHTTPRequest(method, path, host string, headers map[string]string, body string) []byte {
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	for k, v := range headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	if body != "" {
		req += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	req += "\r\n"
	req += body
	return []byte(req)
}

// buildHTTPResponse constructs the text of an HTTP/1.1 response (headers only, no body).
func buildHTTPResponse(statusCode int, headers map[string]string, bodySize int64) []byte {
	statusText := httpStatusText(statusCode)
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText)
	for k, v := range headers {
		resp += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	resp += fmt.Sprintf("Content-Length: %d\r\n", bodySize)
	resp += "\r\n"
	return []byte(resp)
}

// httpStatusText returns a reason phrase for common HTTP status codes.
func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}
