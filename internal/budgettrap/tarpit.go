package budgettrap

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// applyTarpit delays the response based on escalation level.
// Level 1: 1-5s delay, then normal 200 with HTML.
// Level 2: 10-30s delay, slow headers via hijack.
// Level 3: 30-120s delay, or keepalive abuse (hold connection open).
// Returns (statusCode, "tarpit"). statusCode is 200 for delay types, 0 for connection-kill.
func applyTarpit(w http.ResponseWriter, r *http.Request, level int, rng *rand.Rand) (int, string) {
	switch level {
	case 1:
		return tarpitLevel1(w, r, rng)
	case 2:
		return tarpitLevel2(w, r, rng)
	default:
		return tarpitLevel3(w, r, rng)
	}
}

// tarpitLevel1 applies a short delay (1-5s) then serves normal HTML.
func tarpitLevel1(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	delay := time.Duration(rng.Intn(5)+1) * time.Second
	time.Sleep(delay)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Response-Time", fmt.Sprintf("%dms", delay.Milliseconds()))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Acme Corp Portal</title></head><body>
<nav><a href="/">Home</a> | <a href="/about">About</a> | <a href="/products">Products</a></nav>
<main><h1>Welcome to Acme Corp</h1>
<p>Your request has been processed successfully.</p>
<p>If you need assistance, please contact support@acmecorp.example.com</p>
</main></body></html>`))
	return http.StatusOK, "tarpit"
}

// tarpitLevel2 hijacks the connection and sends headers byte-by-byte with delays.
func tarpitLevel2(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		// Fallback: just delay and respond normally
		delay := time.Duration(rng.Intn(21)+10) * time.Second
		time.Sleep(delay)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Loading...</h1></body></html>"))
		return http.StatusOK, "tarpit"
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return http.StatusOK, "tarpit"
	}
	defer conn.Close()

	// Send response headers very slowly
	header := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.2.1\r\n\r\n"
	for i := 0; i < len(header); i++ {
		buf.WriteByte(header[i])
		buf.Flush()
		time.Sleep(time.Duration(rng.Intn(400)+200) * time.Millisecond)
	}

	// Then drip the body
	body := `<!DOCTYPE html><html><head><title>Loading</title></head><body><h1>Processing</h1><p>Please wait...</p></body></html>`
	for i := 0; i < len(body); i++ {
		conn.Write([]byte{body[i]})
		time.Sleep(time.Duration(rng.Intn(200)+50) * time.Millisecond)
	}

	return http.StatusOK, "tarpit"
}

// tarpitLevel3 either does a very long delay or abuses keepalive to hold the connection.
func tarpitLevel3(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	// 50% chance of keepalive abuse, 50% chance of long tarpit
	if rng.Float64() < 0.5 {
		return tarpitKeepaliveAbuse(w, r, rng)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		delay := time.Duration(rng.Intn(91)+30) * time.Second
		time.Sleep(delay)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Done</h1></body></html>"))
		return http.StatusOK, "tarpit"
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return http.StatusOK, "tarpit"
	}
	defer conn.Close()

	// Write a partial HTTP response, then drip very slowly
	buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
	buf.Flush()

	// Send small chunks with long pauses
	chunks := []string{
		"<html><head>",
		"<title>Loading data</title>",
		"</head><body>",
		"<h1>Processing</h1>",
		"<p>Retrieving records",
	}
	for _, chunk := range chunks {
		fmt.Fprintf(buf, "%x\r\n%s\r\n", len(chunk), chunk)
		buf.Flush()
		time.Sleep(time.Duration(rng.Intn(20)+10) * time.Second)
	}

	// Final dots dripped one at a time
	for i := 0; i < rng.Intn(10)+5; i++ {
		fmt.Fprintf(buf, "1\r\n.\r\n")
		buf.Flush()
		time.Sleep(time.Duration(rng.Intn(15)+5) * time.Second)
	}

	buf.WriteString("0\r\n\r\n")
	buf.Flush()
	return http.StatusOK, "tarpit"
}

// tarpitKeepaliveAbuse writes a valid response with keepalive headers,
// then holds the connection open for a long time.
func tarpitKeepaliveAbuse(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		time.Sleep(60 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return http.StatusOK, "tarpit"
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return 0, "tarpit"
	}

	// Send a valid response with keepalive, then hold open
	buf.WriteString("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=999, max=1000\r\nContent-Type: text/html\r\nContent-Length: 89\r\n\r\n")
	buf.WriteString("<html><body><h1>OK</h1><p>Request processed. Connection will be reused.</p></body></html>")
	buf.Flush()

	// Hold connection open, periodically tickle it to prevent idle timeout
	holdTime := time.Duration(rng.Intn(91)+30) * time.Second
	deadline := time.Now().Add(holdTime)
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	conn.SetDeadline(deadline)

	// Block until deadline
	buf1 := make([]byte, 1)
	conn.Read(buf1)
	conn.Close()

	return 0, "tarpit"
}
