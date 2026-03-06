// Package h3chaos provides HTTP/3 and QUIC chaos emulation.
// It does NOT implement real HTTP/3 — it emulates and weaponizes
// the protocol to confuse, crash, and disrupt HTTP clients and servers.
//
// Attack vectors:
//   - Alt-Svc header injection: trick clients into attempting QUIC connections
//   - Fake QUIC UDP listener: respond with malformed QUIC packets
//   - Alt-Svc confusion: conflicting, malformed, and impossible Alt-Svc values
//   - QUIC version negotiation abuse
package h3chaos

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
)

// Engine provides HTTP/3 chaos injection capabilities.
type Engine struct {
	mu      sync.RWMutex
	enabled bool
	level   int // 0-4: off, subtle, moderate, aggressive, nightmare
	rng     *rand.Rand

	// UDP listener for fake QUIC responses
	udpConn *net.UDPConn
	udpPort int
	stop    chan struct{}
}

// NewEngine creates an H3 chaos engine.
func NewEngine() *Engine {
	return &Engine{
		enabled: false,
		level:   0,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		stop:    make(chan struct{}),
	}
}

// SetEnabled enables or disables H3 chaos.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
	if enabled && e.udpConn == nil {
		e.startUDPListener()
	}
	if !enabled && e.udpConn != nil {
		e.stopUDPListener()
	}
}

// IsEnabled returns whether H3 chaos is enabled.
func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// SetLevel sets the chaos level (0-4).
func (e *Engine) SetLevel(level int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if level < 0 {
		level = 0
	}
	if level > 4 {
		level = 4
	}
	e.level = level
}

// GetLevel returns the current chaos level.
func (e *Engine) GetLevel() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.level
}

// UDPPort returns the port the fake QUIC listener is on (0 if not running).
func (e *Engine) UDPPort() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.udpPort
}

// Shutdown stops the UDP listener.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopUDPListener()
}

// InjectHeaders adds H3 chaos headers to the response.
// Called by the server handler on responses.
func (e *Engine) InjectHeaders(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	enabled := e.enabled
	level := e.level
	udpPort := e.udpPort
	e.mu.RUnlock()

	if !enabled || level == 0 {
		return
	}

	seed := e.seed(r)

	switch {
	case level >= 4:
		e.injectNightmare(w, seed, udpPort)
	case level >= 3:
		e.injectAggressive(w, seed, udpPort)
	case level >= 2:
		e.injectModerate(w, seed, udpPort)
	default:
		e.injectSubtle(w, seed, udpPort)
	}
}

func (e *Engine) seed(r *http.Request) uint64 {
	h := sha256.Sum256([]byte(r.URL.Path + "|" + r.RemoteAddr + "|h3chaos"))
	return binary.BigEndian.Uint64(h[:8])
}

func bit(seed uint64, slot int, pct float64) bool {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", seed, slot)))
	v := binary.BigEndian.Uint64(h[:8])
	return float64(v%10000)/10000.0 < pct
}

// Level 1: Subtle — advertise H3 on a port that doesn't exist
func (e *Engine) injectSubtle(w http.ResponseWriter, seed uint64, udpPort int) {
	if bit(seed, 1, 0.5) {
		// Advertise h3 on UDP port that may or may not have our fake listener
		port := udpPort
		if port == 0 {
			port = 443
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, port))
	}
}

// Level 2: Moderate — conflicting Alt-Svc, wrong ports
func (e *Engine) injectModerate(w http.ResponseWriter, seed uint64, udpPort int) {
	e.injectSubtle(w, seed, udpPort)

	if bit(seed, 10, 0.6) {
		// Multiple conflicting Alt-Svc entries
		w.Header().Add("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Add("Alt-Svc", `h3=":8443"; ma=1`)
		w.Header().Add("Alt-Svc", `h3=":0"; ma=86400`)         // Port 0
		w.Header().Add("Alt-Svc", `h3=":65535"; ma=86400`)     // Max port
	}

	if bit(seed, 11, 0.4) {
		// Alt-Svc clear directive mixed with advertisements
		w.Header().Add("Alt-Svc", "clear")
		w.Header().Add("Alt-Svc", `h3=":443"; ma=86400`)
	}
}

// Level 3: Aggressive — malformed Alt-Svc, fake protocols
func (e *Engine) injectAggressive(w http.ResponseWriter, seed uint64, udpPort int) {
	e.injectModerate(w, seed, udpPort)

	if bit(seed, 20, 0.5) {
		// Malformed Alt-Svc values
		badValues := []string{
			`h3=":-1"; ma=86400`,                   // Negative port
			`h3=""; ma=86400`,                       // Empty authority
			`h3=":99999"; ma=86400`,                 // Port > 65535
			`h99=":443"; ma=86400`,                  // Nonexistent protocol
			`h3=":443"; ma=-1`,                      // Negative max-age
			`h3=":443"; ma=99999999999999`,           // Huge max-age
			`h3=":443"; persist=1; ma=0`,             // persist but ma=0
			fmt.Sprintf(`h3=":%d"; ma=86400, h3-29=":443"`, udpPort), // Old draft version
		}
		for _, v := range badValues {
			w.Header().Add("Alt-Svc", v)
		}
	}

	if bit(seed, 21, 0.4) {
		// QUIC version hint headers (nonstandard but some clients read them)
		w.Header().Set("X-QUIC-Version", "Q046,Q050,ff000020")
		w.Header().Set("X-QUIC-Status", "0x1 CONNECTION_REFUSED")
	}
}

// Level 4: Nightmare — everything at once
func (e *Engine) injectNightmare(w http.ResponseWriter, seed uint64, udpPort int) {
	e.injectAggressive(w, seed, udpPort)

	// Alt-Svc with emoji (crashes Alt-Svc parsers)
	w.Header().Add("Alt-Svc", "h3=\":\xF0\x9F\x92\xA9\"; ma=86400") // 💩 as port
	// Alt-Svc with null bytes
	w.Header().Add("Alt-Svc", "h3=\":443\x00\"; ma=86400")
	// Alt-Svc with injection attempts
	w.Header().Add("Alt-Svc", "h3=\":443\"; ma=86400\r\nX-Injected: yes")
	// ALPS header (Application-Layer Protocol Settings for HTTP/3)
	w.Header().Set("Accept-CH", "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Mobile")
	// Upgrade header suggesting h3 (nonsensical for TCP)
	w.Header().Add("Upgrade", "h3")
	w.Header().Add("Connection", "Upgrade")
}

// startUDPListener starts a fake QUIC UDP listener that responds with
// malformed QUIC packets to any incoming connection attempts.
func (e *Engine) startUDPListener() {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	e.udpConn = conn
	e.udpPort = conn.LocalAddr().(*net.UDPAddr).Port
	e.stop = make(chan struct{})

	go e.udpLoop()
}

func (e *Engine) stopUDPListener() {
	if e.udpConn != nil {
		close(e.stop)
		e.udpConn.Close()
		e.udpConn = nil
		e.udpPort = 0
	}
}

// udpLoop handles incoming QUIC connection attempts with malformed responses.
func (e *Engine) udpLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-e.stop:
			return
		default:
		}

		e.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := e.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 1 {
			continue
		}

		// Respond with a malformed QUIC packet
		go e.sendMalformedQUIC(remoteAddr, buf[:n])
	}
}

// sendMalformedQUIC sends various malformed QUIC responses to confuse clients.
func (e *Engine) sendMalformedQUIC(addr *net.UDPAddr, clientPacket []byte) {
	e.mu.Lock()
	choice := e.rng.Intn(6)
	e.mu.Unlock()

	var response []byte

	switch choice {
	case 0:
		// QUIC Version Negotiation packet — advertise impossible versions
		response = BuildVersionNegotiation(clientPacket)
	case 1:
		// Retry packet with garbage token
		response = BuildRetryPacket(clientPacket)
	case 2:
		// Initial packet with wrong version
		response = BuildInitialWrongVersion()
	case 3:
		// Pure garbage that looks like QUIC header
		response = BuildGarbageQUIC()
	case 4:
		// Stateless reset (random bytes after connection ID)
		response = BuildStatelessReset()
	case 5:
		// Flood: send many small packets rapidly
		for i := 0; i < 50; i++ {
			pkt := BuildGarbageQUIC()
			e.udpConn.WriteToUDP(pkt, addr)
		}
		return
	}

	if len(response) > 0 {
		e.udpConn.WriteToUDP(response, addr)
	}
}

// BuildVersionNegotiation creates a QUIC Version Negotiation packet (exported for scanner).
// Header: 0x80 | version=0x00000000 | DCID from client | SCID random | supported versions
func BuildVersionNegotiation(clientPacket []byte) []byte {
	pkt := make([]byte, 0, 128)
	pkt = append(pkt, 0x80)                         // Long header form
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)       // Version 0 = version negotiation
	// Extract DCID length from client packet if possible
	dcidLen := byte(8)
	if len(clientPacket) > 5 {
		dcidLen = clientPacket[5]
		if dcidLen > 20 {
			dcidLen = 8
		}
	}
	pkt = append(pkt, dcidLen)
	// Copy DCID from client or use random
	if len(clientPacket) > 6+int(dcidLen) {
		pkt = append(pkt, clientPacket[6:6+dcidLen]...)
	} else {
		for i := byte(0); i < dcidLen; i++ {
			pkt = append(pkt, byte(i+0x42))
		}
	}
	pkt = append(pkt, 8)                             // SCID length
	pkt = append(pkt, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE) // SCID
	// Advertise fake/impossible QUIC versions
	fakeVersions := []uint32{
		0xFF000000, // Reserved for negotiation
		0xFF000001, // Greased
		0x00000002, // Version 2
		0xDEADBEEF, // Garbage
		0x51474F00, // "QGO\0"
		0x00000001, // QUIC v1
	}
	for _, v := range fakeVersions {
		pkt = binary.BigEndian.AppendUint32(pkt, v)
	}
	return pkt
}

// BuildRetryPacket creates a QUIC Retry packet with a garbage retry token (exported for scanner).
func BuildRetryPacket(clientPacket []byte) []byte {
	pkt := make([]byte, 0, 256)
	pkt = append(pkt, 0xF0)                         // Long header, Retry type
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x01)       // Version 1
	pkt = append(pkt, 8)                             // DCID length
	pkt = append(pkt, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
	pkt = append(pkt, 0)                             // SCID length = 0
	// Garbage retry token (128 bytes of pseudo-random)
	token := make([]byte, 128)
	for i := range token {
		token[i] = byte(i * 7)
	}
	pkt = append(pkt, token...)
	// Retry Integrity Tag (16 bytes of garbage)
	pkt = append(pkt, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99)
	return pkt
}

// BuildInitialWrongVersion creates a QUIC Initial packet with wrong version (exported for scanner).
func BuildInitialWrongVersion() []byte {
	pkt := make([]byte, 0, 64)
	pkt = append(pkt, 0xC0)                         // Long header, Initial type
	pkt = append(pkt, 0xBA, 0xAD, 0xF0, 0x0D)       // Bogus version
	pkt = append(pkt, 8)                             // DCID length
	pkt = append(pkt, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01)
	pkt = append(pkt, 0)                             // SCID length
	pkt = append(pkt, 0)                             // Token length
	pkt = append(pkt, 0x00, 0x10)                    // Packet length (16)
	pkt = append(pkt, make([]byte, 16)...)           // Encrypted garbage
	return pkt
}

// BuildGarbageQUIC creates bytes that look like QUIC but are garbage (exported for scanner).
func BuildGarbageQUIC() []byte {
	pkt := make([]byte, 64)
	pkt[0] = 0x80 | byte(rand.Intn(16)) // Long header form with random type
	// Fill rest with pseudo-random
	for i := 1; i < len(pkt); i++ {
		pkt[i] = byte(i * 13)
	}
	return pkt
}

// BuildStatelessReset creates a QUIC Stateless Reset packet (exported for scanner).
func BuildStatelessReset() []byte {
	pkt := make([]byte, 48)
	// Stateless reset looks like a short header packet
	pkt[0] = 0x40 | byte(rand.Intn(64)) // Short header form
	// Random bytes
	for i := 1; i < len(pkt)-16; i++ {
		pkt[i] = byte(i * 23)
	}
	// Last 16 bytes are the stateless reset token
	copy(pkt[len(pkt)-16:], []byte("GLITCH_RESET_TOK"))
	return pkt
}
