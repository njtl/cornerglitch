package websocket

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocket magic GUID per RFC 6455 Section 4.2.2.
const wsMagicGUID = "258EAFA5-E914-47DA-95CA-5AB53E09BE11"

// WebSocket opcodes.
const (
	opText  = 0x1
	opClose = 0x8
	opPing  = 0x9
	opPong  = 0xA
)

// Handler emulates WebSocket endpoints with fake real-time data streams.
type Handler struct {
	endpoints map[string]wsEndpoint
}

// wsEndpoint defines how to run a single WebSocket endpoint after upgrade.
type wsEndpoint struct {
	name        string
	description string
	run         func(conn net.Conn, path string)
}

// NewHandler creates a new WebSocket handler.
func NewHandler() *Handler {
	h := &Handler{
		endpoints: make(map[string]wsEndpoint),
	}

	h.endpoints["/ws/feed"] = wsEndpoint{
		name:        "Social Media Feed",
		description: "Real-time social media activity stream (posts, likes, comments)",
		run:         h.runFeed,
	}
	h.endpoints["/ws/notifications"] = wsEndpoint{
		name:        "Push Notifications",
		description: "Push notification stream (emails, friend requests, alerts)",
		run:         h.runNotifications,
	}
	h.endpoints["/ws/chat"] = wsEndpoint{
		name:        "Chat Room",
		description: "Interactive chat room with bot participants",
		run:         h.runChat,
	}
	h.endpoints["/ws/ticker"] = wsEndpoint{
		name:        "Price Ticker",
		description: "Stock and crypto price ticker with 1-second updates",
		run:         h.runTicker,
	}
	h.endpoints["/ws/metrics"] = wsEndpoint{
		name:        "Server Metrics",
		description: "Live server metrics stream (CPU, memory, request rate)",
		run:         h.runMetrics,
	}

	// Honeypot endpoints — budget-draining traps that look like real data streams.
	h.endpoints["/ws/live-data"] = wsEndpoint{
		name:        "Live Data Stream",
		description: "Aggregated real-time data feed (market, metrics, alerts)",
		run:         h.runHoneypot,
	}
	h.endpoints["/ws/events"] = wsEndpoint{
		name:        "Event Stream",
		description: "Server-sent event stream for real-time updates",
		run:         h.runHoneypot,
	}
	h.endpoints["/ws/stream"] = wsEndpoint{
		name:        "Data Stream",
		description: "Streaming data endpoint for live dashboards",
		run:         h.runHoneypot,
	}

	return h
}

// ShouldHandle returns true for paths this handler serves.
func (h *Handler) ShouldHandle(path string) bool {
	if path == "/ws/" || path == "/ws" {
		return true
	}
	_, ok := h.endpoints[path]
	return ok
}

// ServeHTTP handles WebSocket upgrade or shows an HTML info page. Returns status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	// Index page listing all endpoints.
	if path == "/ws/" || path == "/ws" {
		return h.serveIndex(w, r)
	}

	ep, ok := h.endpoints[path]
	if !ok {
		http.NotFound(w, r)
		return http.StatusNotFound
	}

	// If not a WebSocket upgrade request, show endpoint info page.
	if !isWebSocketUpgrade(r) {
		return h.serveEndpointInfo(w, r, path, ep)
	}

	// Perform WebSocket upgrade.
	conn, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	// Run endpoint handler in a goroutine; the HTTP handler returns 101.
	go func() {
		defer conn.Close()
		ep.run(conn, path)
	}()

	return http.StatusSwitchingProtocols
}

// ---------------------------------------------------------------------------
// WebSocket handshake and framing (stdlib-only, RFC 6455)
// ---------------------------------------------------------------------------

func isWebSocketUpgrade(r *http.Request) bool {
	return headerContains(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerContains(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// upgradeWebSocket performs the WebSocket opening handshake and returns the
// hijacked connection. The caller owns the connection after this returns.
func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("server does not support hijacking")
	}

	// Compute accept value.
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsMagicGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	// Write the 101 Switching Protocols response.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n" +
		"\r\n"
	_, err = buf.WriteString(resp)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write handshake: %w", err)
	}
	if err = buf.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("flush handshake: %w", err)
	}

	return conn, nil
}

// readFrame reads one WebSocket frame from conn and returns the unmasked
// payload. It handles text, close, ping, and pong opcodes. For ping it sends
// a pong automatically and continues reading. For close it returns an error.
func readFrame(conn net.Conn) (opcode byte, payload []byte, err error) {
	for {
		var header [2]byte
		if _, err = readFull(conn, header[:]); err != nil {
			return 0, nil, err
		}

		op := header[0] & 0x0F
		masked := (header[1] & 0x80) != 0
		length := uint64(header[1] & 0x7F)

		switch {
		case length == 126:
			var ext [2]byte
			if _, err = readFull(conn, ext[:]); err != nil {
				return 0, nil, err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case length == 127:
			var ext [8]byte
			if _, err = readFull(conn, ext[:]); err != nil {
				return 0, nil, err
			}
			length = binary.BigEndian.Uint64(ext[:])
		}

		var maskKey [4]byte
		if masked {
			if _, err = readFull(conn, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		data := make([]byte, length)
		if length > 0 {
			if _, err = readFull(conn, data); err != nil {
				return 0, nil, err
			}
		}

		if masked {
			for i := range data {
				data[i] ^= maskKey[i%4]
			}
		}

		switch op {
		case opClose:
			// Send close frame back.
			_ = writeClose(conn)
			return opClose, data, fmt.Errorf("received close frame")
		case opPing:
			// Respond with pong and keep reading.
			_ = writeControlFrame(conn, opPong, data)
			continue
		case opPong:
			// Ignore unsolicited pong frames.
			continue
		default:
			return op, data, nil
		}
	}
}

// writeFrame writes a WebSocket text frame (server-to-client, unmasked).
func writeFrame(conn net.Conn, data []byte) error {
	length := len(data)
	var header []byte

	switch {
	case length <= 125:
		header = []byte{0x81, byte(length)}
	case length <= 65535:
		header = make([]byte, 4)
		header[0] = 0x81
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		header = make([]byte, 10)
		header[0] = 0x81
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// writeClose sends a WebSocket close frame.
func writeClose(conn net.Conn) error {
	return writeControlFrame(conn, opClose, nil)
}

// writeControlFrame sends a WebSocket control frame (close, ping, pong).
func writeControlFrame(conn net.Conn, op byte, payload []byte) error {
	length := len(payload)
	if length > 125 {
		length = 125
		payload = payload[:125]
	}
	frame := make([]byte, 2+length)
	frame[0] = 0x80 | op // FIN + opcode
	frame[1] = byte(length)
	copy(frame[2:], payload)
	_, err := conn.Write(frame)
	return err
}

// writePing sends a WebSocket ping frame.
func writePing(conn net.Conn) error {
	return writeControlFrame(conn, opPing, []byte("ping"))
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// Deterministic seeding helper
// ---------------------------------------------------------------------------

func pathSeed(path string) int64 {
	h := sha256.Sum256([]byte(path))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

// ---------------------------------------------------------------------------
// Connection runner: common lifecycle wrapper
// ---------------------------------------------------------------------------

// connRunner manages the read/write lifecycle for a WebSocket endpoint.
type connRunner struct {
	conn     net.Conn
	incoming chan []byte // client messages
	done     chan struct{}
	once     sync.Once
}

func newConnRunner(conn net.Conn) *connRunner {
	return &connRunner{
		conn:     conn,
		incoming: make(chan []byte, 64),
		done:     make(chan struct{}),
	}
}

func (cr *connRunner) close() {
	cr.once.Do(func() {
		close(cr.done)
		_ = writeClose(cr.conn)
	})
}

// readLoop reads client frames in a background goroutine. It resets the
// read deadline on every frame and closes the runner on error or timeout.
func (cr *connRunner) readLoop() {
	defer cr.close()
	for {
		cr.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		op, data, err := readFrame(cr.conn)
		if err != nil {
			return
		}
		if op == opText {
			select {
			case cr.incoming <- data:
			default:
				// Drop message if the channel is full.
			}
		}
	}
}

// pingLoop sends a ping every 30 seconds to keep the connection alive.
func (cr *connRunner) pingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cr.done:
			return
		case <-ticker.C:
			if err := writePing(cr.conn); err != nil {
				cr.close()
				return
			}
		}
	}
}

// send writes a text frame; returns false if the connection is closed.
func (cr *connRunner) send(data []byte) bool {
	select {
	case <-cr.done:
		return false
	default:
	}
	if err := writeFrame(cr.conn, data); err != nil {
		cr.close()
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Endpoint: /ws/feed — Social media activity feed
// ---------------------------------------------------------------------------

func (h *Handler) runFeed(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path)))
	counter := 0

	users := []string{"Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Hank", "Ivy", "Jack"}
	contents := []string{
		"Just deployed a new microservice architecture!",
		"Anyone else seeing increased latency on the east coast?",
		"Hot take: monoliths are underrated.",
		"TIL about WebSocket frames. Fascinating protocol.",
		"Working from home productivity is through the roof.",
		"New blog post: Scaling to 10M concurrent users.",
		"Coffee count today: 5. Send help.",
		"Pushed 47 commits today. Refactoring is life.",
		"Our error budget is looking healthy this quarter.",
		"Just finished a chaos engineering drill. Everything broke.",
		"The new dashboard redesign is gorgeous.",
		"Kubernetes cluster auto-scaled to 200 pods. Wild.",
		"Pair programming session went great today.",
		"Benchmarks show a 3x improvement. Worth the rewrite.",
		"On-call shift was quiet. Almost suspicious.",
	}

	for {
		select {
		case <-cr.done:
			return
		case <-time.After(time.Duration(2000+rng.Intn(1000)) * time.Millisecond):
		}

		counter++
		user := users[rng.Intn(len(users))]
		now := time.Now().UTC().Format(time.RFC3339)

		var msg string
		kind := rng.Intn(3)
		switch kind {
		case 0: // post
			content := contents[rng.Intn(len(contents))]
			likes := rng.Intn(500)
			msg = fmt.Sprintf(`{"type":"post","user":"%s","content":"%s","likes":%d,"timestamp":"%s","id":%d}`,
				user, content, likes, now, counter)
		case 1: // like
			target := rng.Intn(counter) + 1
			msg = fmt.Sprintf(`{"type":"like","user":"%s","target_post":%d,"timestamp":"%s"}`,
				user, target, now)
		case 2: // comment
			comment := contents[rng.Intn(len(contents))]
			target := rng.Intn(counter) + 1
			msg = fmt.Sprintf(`{"type":"comment","user":"%s","content":"%s","target_post":%d,"timestamp":"%s"}`,
				user, comment, target, now)
		}

		if !cr.send([]byte(msg)) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Endpoint: /ws/notifications — Push notifications
// ---------------------------------------------------------------------------

func (h *Handler) runNotifications(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path)))

	categories := []string{"email_received", "friend_request", "mention", "achievement", "system_alert", "security_warning"}

	titles := map[string][]string{
		"email_received":   {"New message from team", "Weekly digest available", "Invoice attached", "Meeting invite", "Deployment report"},
		"friend_request":   {"Connection request from Alex", "New follower: Jordan", "Team invite from DevOps", "Collaboration request"},
		"mention":          {"You were mentioned in #general", "Tagged in a code review", "Referenced in issue #42", "Mentioned in standup notes"},
		"achievement":      {"100 commits milestone!", "First merge to main", "Zero downtime for 30 days", "Code review champion"},
		"system_alert":     {"CPU usage above 90%", "Disk space warning", "SSL certificate expiring", "Database connection pool full"},
		"security_warning": {"Login from new device", "API key rotation needed", "Suspicious activity detected", "Failed login attempts"},
	}

	bodies := map[string][]string{
		"email_received":   {"Click to view the full message.", "3 attachments included.", "Reply requested by EOD.", "Marked as high priority."},
		"friend_request":   {"Accept or decline this request.", "You have 5 mutual connections.", "From your organization.", "Recommended by the system."},
		"mention":          {"View the full thread for context.", "Your input is requested.", "Action item assigned to you.", "Discussion is ongoing."},
		"achievement":      {"Share this milestone with your team!", "You're in the top 10%.", "Keep up the great work!", "New badge unlocked."},
		"system_alert":     {"Investigate immediately.", "Auto-scaling has been triggered.", "Runbook: check monitoring dashboard.", "Threshold exceeded for 5 minutes."},
		"security_warning": {"Review your recent activity.", "Change your password.", "Enable two-factor authentication.", "Contact security team if unexpected."},
	}

	for {
		select {
		case <-cr.done:
			return
		case <-time.After(time.Duration(3000+rng.Intn(2000)) * time.Millisecond):
		}

		cat := categories[rng.Intn(len(categories))]
		catTitles := titles[cat]
		catBodies := bodies[cat]
		title := catTitles[rng.Intn(len(catTitles))]
		body := catBodies[rng.Intn(len(catBodies))]
		now := time.Now().UTC().Format(time.RFC3339)

		msg := fmt.Sprintf(`{"type":"notification","category":"%s","title":"%s","body":"%s","read":false,"timestamp":"%s"}`,
			cat, title, body, now)

		if !cr.send([]byte(msg)) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Endpoint: /ws/chat — Chat room simulation
// ---------------------------------------------------------------------------

func (h *Handler) runChat(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path)))

	bots := []string{"Alice", "Bob", "Charlie", "Eve", "Mallory"}

	chatter := []string{
		"Has anyone tried the new deploy pipeline?",
		"I'm seeing some weird metrics on the dashboard.",
		"Lunch break, back in 30.",
		"PR #247 is ready for review.",
		"The staging environment is acting up again.",
		"Anyone want to pair on the auth module?",
		"Great standup today, team!",
		"I think we should refactor the queue handler.",
		"Just found a race condition in the cache layer.",
		"The CI build is green! Ship it!",
		"Who changed the config on prod?",
		"New RFC posted in the docs channel.",
		"Can someone check the error logs?",
		"Sprint retro at 3pm, don't forget.",
		"The load balancer config looks off.",
	}

	replies := []string{
		"Interesting point! I'll look into that.",
		"Agreed, let's fix that ASAP.",
		"I had the same issue yesterday.",
		"Good catch! Filing a ticket now.",
		"Let me pull up the logs...",
		"That's a known issue, working on a patch.",
		"Can you share more details?",
		"I'll add that to the backlog.",
		"Nice work on that one!",
		"Let's discuss in the next standup.",
	}

	// Send joined message.
	now := time.Now().UTC().Format(time.RFC3339)
	joined := fmt.Sprintf(`{"type":"system","message":"You have joined the chat room","users":["%s"],"timestamp":"%s"}`,
		strings.Join(bots, `","`), now)
	if !cr.send([]byte(joined)) {
		return
	}

	// pendingReply signals that a client message was received and a bot
	// reply should be sent after a short delay.
	pendingReply := make(chan string, 8)

	// Background chatter ticker: 5-10 seconds.
	chatterInterval := func() time.Duration {
		return time.Duration(5000+rng.Intn(5000)) * time.Millisecond
	}
	chatterTimer := time.NewTimer(chatterInterval())
	defer chatterTimer.Stop()

	for {
		select {
		case <-cr.done:
			return

		case clientMsg := <-cr.incoming:
			// Echo back.
			now = time.Now().UTC().Format(time.RFC3339)
			echo := fmt.Sprintf(`{"type":"message","user":"you","content":"[echo] %s","timestamp":"%s"}`,
				sanitize(string(clientMsg)), now)
			if !cr.send([]byte(echo)) {
				return
			}
			// Schedule bot reply.
			select {
			case pendingReply <- string(clientMsg):
			default:
			}

		case <-time.After(time.Duration(1000+rng.Intn(1000)) * time.Millisecond):
			// Check for pending bot reply.
			select {
			case <-pendingReply:
				bot := bots[rng.Intn(len(bots))]
				reply := replies[rng.Intn(len(replies))]
				now = time.Now().UTC().Format(time.RFC3339)
				msg := fmt.Sprintf(`{"type":"message","user":"%s","content":"%s","timestamp":"%s"}`,
					bot, reply, now)
				if !cr.send([]byte(msg)) {
					return
				}
			default:
			}

		case <-chatterTimer.C:
			// Periodic bot chatter.
			bot := bots[rng.Intn(len(bots))]
			text := chatter[rng.Intn(len(chatter))]
			now = time.Now().UTC().Format(time.RFC3339)
			msg := fmt.Sprintf(`{"type":"message","user":"%s","content":"%s","timestamp":"%s"}`,
				bot, text, now)
			if !cr.send([]byte(msg)) {
				return
			}
			chatterTimer.Reset(chatterInterval())
		}
	}
}

// sanitize escapes double quotes and backslashes for JSON embedding.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// ---------------------------------------------------------------------------
// Endpoint: /ws/ticker — Stock/crypto price ticker
// ---------------------------------------------------------------------------

type tickerSymbol struct {
	symbol    string
	basePrice float64
}

func (h *Handler) runTicker(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path)))

	symbols := []tickerSymbol{
		{"AAPL", 185.00},
		{"GOOGL", 140.00},
		{"MSFT", 415.00},
		{"AMZN", 185.00},
		{"BTC-USD", 62500.00},
		{"ETH-USD", 3400.00},
		{"TSLA", 245.00},
		{"NVDA", 880.00},
	}

	// Track current prices so they drift over time.
	prices := make([]float64, len(symbols))
	for i, s := range symbols {
		prices[i] = s.basePrice
	}

	for {
		select {
		case <-cr.done:
			return
		case <-time.After(1 * time.Second):
		}

		// Pick a random symbol to update.
		idx := rng.Intn(len(symbols))
		sym := symbols[idx]

		// Random walk: drift by up to +/-2%.
		drift := (rng.Float64() - 0.5) * 0.04
		prices[idx] *= (1 + drift)
		price := prices[idx]
		change := price - sym.basePrice
		volume := rng.Intn(50000000) + 1000000

		now := time.Now().UTC().Format(time.RFC3339)
		msg := fmt.Sprintf(`{"type":"tick","symbol":"%s","price":%.2f,"change":%.2f,"volume":%d,"timestamp":"%s"}`,
			sym.symbol, price, change, volume, now)

		if !cr.send([]byte(msg)) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Endpoint: /ws/metrics — Server metrics stream
// ---------------------------------------------------------------------------

func (h *Handler) runMetrics(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path)))

	startTime := time.Now()

	// Base values that fluctuate.
	baseRPS := 40.0
	baseConns := 12
	baseErrRate := 0.02
	baseCPU := 22.0
	baseMem := 150.0

	for {
		select {
		case <-cr.done:
			return
		case <-time.After(2 * time.Second):
		}

		uptime := time.Since(startTime).Seconds()

		rps := baseRPS + (rng.Float64()-0.5)*20
		if rps < 0 {
			rps = 0.1
		}
		conns := baseConns + rng.Intn(20) - 10
		if conns < 0 {
			conns = 1
		}
		errRate := baseErrRate + (rng.Float64()-0.5)*0.03
		if errRate < 0 {
			errRate = 0
		}
		cpu := baseCPU + (rng.Float64()-0.5)*30
		if cpu < 0 {
			cpu = 0.1
		}
		if cpu > 100 {
			cpu = 99.9
		}
		mem := baseMem + (rng.Float64()-0.5)*40
		if mem < 50 {
			mem = 50
		}

		now := time.Now().UTC().Format(time.RFC3339)
		msg := fmt.Sprintf(`{"type":"metrics","requests_per_sec":%.1f,"active_connections":%d,"error_rate":%.4f,"cpu_usage":%.1f,"memory_mb":%.0f,"uptime_seconds":%.0f,"timestamp":"%s"}`,
			rps, conns, errRate, cpu, mem, uptime, now)

		if !cr.send([]byte(msg)) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// HTML info pages (non-WebSocket requests)
// ---------------------------------------------------------------------------

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var rows strings.Builder
	for path, ep := range h.endpoints {
		rows.WriteString(fmt.Sprintf(`
        <tr>
          <td><code>%s</code></td>
          <td>%s</td>
          <td>%s</td>
          <td><a href="%s">Info</a></td>
        </tr>`, path, ep.name, ep.description, path))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WebSocket Endpoints — GlitchServer</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; padding: 2em; }
    h1 { color: #0f0; }
    table { border-collapse: collapse; width: 100%%; margin-top: 1em; }
    th, td { border: 1px solid #333; padding: 0.5em 1em; text-align: left; }
    th { background: #222; color: #0f0; }
    a { color: #0ff; }
    code { color: #ff0; }
    pre { background: #1a1a1a; padding: 1em; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>WebSocket Endpoints</h1>
  <p>Connect using the <code>ws://</code> protocol. All endpoints send JSON text frames.</p>

  <table>
    <thead>
      <tr><th>Path</th><th>Name</th><th>Description</th><th>Details</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>

  <h2>Quick Connect</h2>
  <pre>
// Browser console example
const ws = new WebSocket("ws://" + location.host + "/ws/feed");
ws.onmessage = (e) => console.log(JSON.parse(e.data));
ws.onclose = (e) => console.log("closed", e.code);
  </pre>

  <h2>Available Endpoints</h2>
  <ul>
    <li><code>/ws/feed</code> — Social media activity (posts, likes, comments)</li>
    <li><code>/ws/notifications</code> — Push notifications stream</li>
    <li><code>/ws/chat</code> — Interactive chat room with bots</li>
    <li><code>/ws/ticker</code> — Stock/crypto price ticker (1s updates)</li>
    <li><code>/ws/metrics</code> — Live server metrics</li>
  </ul>
</body>
</html>`, rows.String())

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveEndpointInfo(w http.ResponseWriter, r *http.Request, path string, ep wsEndpoint) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Endpoint-specific message format examples.
	examples := map[string]string{
		"/ws/feed": `// Messages you will receive:
{"type":"post","user":"Alice","content":"Just deployed!","likes":42,"timestamp":"...","id":1}
{"type":"like","user":"Bob","target_post":1,"timestamp":"..."}
{"type":"comment","user":"Charlie","content":"Nice work!","target_post":1,"timestamp":"..."}`,

		"/ws/notifications": `// Messages you will receive:
{"type":"notification","category":"email_received","title":"New message","body":"Click to view.","read":false,"timestamp":"..."}
{"type":"notification","category":"security_warning","title":"Login from new device","body":"Review activity.","read":false,"timestamp":"..."}`,

		"/ws/chat": `// Messages you will receive:
{"type":"system","message":"You have joined the chat room","users":["Alice","Bob",...],"timestamp":"..."}
{"type":"message","user":"Alice","content":"Hello!","timestamp":"..."}

// Send a message (text frame):
Hello everyone!
// The server echoes it back and bots reply.`,

		"/ws/ticker": `// Messages you will receive (every 1 second):
{"type":"tick","symbol":"AAPL","price":185.42,"change":-0.53,"volume":12345678,"timestamp":"..."}
{"type":"tick","symbol":"BTC-USD","price":62534.17,"change":34.17,"volume":28000000,"timestamp":"..."}`,

		"/ws/metrics": `// Messages you will receive (every 2 seconds):
{"type":"metrics","requests_per_sec":42.5,"active_connections":15,"error_rate":0.0200,"cpu_usage":23.4,"memory_mb":156,"uptime_seconds":3600,"timestamp":"..."}`,
	}

	example := examples[path]
	if example == "" {
		example = "// Connect to see messages"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>%s — GlitchServer WebSocket</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; padding: 2em; max-width: 800px; }
    h1 { color: #0f0; }
    h2 { color: #0ff; margin-top: 1.5em; }
    code { color: #ff0; }
    pre { background: #1a1a1a; padding: 1em; border-radius: 4px; overflow-x: auto; color: #ccc; }
    a { color: #0ff; }
    .path { font-size: 1.2em; color: #ff0; }
  </style>
</head>
<body>
  <h1>%s</h1>
  <p>%s</p>
  <p class="path">Endpoint: <code>%s</code></p>

  <h2>Connection</h2>
  <pre>
const ws = new WebSocket("ws://" + location.host + "%s");
ws.onopen = () => console.log("connected");
ws.onmessage = (e) => console.log(JSON.parse(e.data));
ws.onclose = (e) => console.log("closed", e.code, e.reason);
ws.onerror = (e) => console.error("error", e);
  </pre>

  <h2>Message Format</h2>
  <pre>%s</pre>

  <h2>Notes</h2>
  <ul>
    <li>All messages are JSON text frames.</li>
    <li>Connection timeout: 5 minutes of inactivity.</li>
    <li>Server sends ping frames every 30 seconds.</li>
    <li>Respond to pings with pong to keep the connection alive.</li>
  </ul>

  <p><a href="/ws/">Back to all endpoints</a></p>
</body>
</html>`, ep.name, ep.name, ep.description, path, path, example)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}
