package email

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Pools of fake data
// ---------------------------------------------------------------------------

var firstNames = []string{
	"Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Heidi",
	"Ivan", "Judy", "Karl", "Laura", "Mallory", "Niaj", "Oscar", "Peggy",
	"Quinn", "Rupert", "Sybil", "Trent", "Ursula", "Victor", "Wendy",
	"Xavier", "Yvonne", "Zach", "Nora", "Miles", "Priya", "Liam", "Hana",
	"Jorge", "Rita", "Sven", "Amara",
}

var lastNames = []string{
	"Anderson", "Brown", "Chen", "Diaz", "Evans", "Fischer", "Garcia",
	"Hernandez", "Ibrahim", "Johnson", "Kim", "Lee", "Martinez", "Nguyen",
	"Okafor", "Patel", "Quinn", "Rossi", "Singh", "Torres", "Ueda",
	"Volkov", "Wang", "Xu", "Yamamoto", "Zhang", "Baker", "Clark",
	"Davis", "Edwards", "Foster", "Green", "Harris", "Jackson", "Kelly",
}

var domains = []string{
	"example.com", "acme-corp.com", "globex.net", "initech.io",
	"megacorp.org", "widgets.co", "fakemail.dev", "testco.biz",
	"contoso.com", "northwind.org",
}

var subjectTemplates = []string{
	"Meeting tomorrow at %d:%02d",
	"Re: Q%d budget review",
	"Your order #%05d has shipped",
	"Action required: update your profile",
	"Weekly digest - %s",
	"Invitation: %s team standup",
	"[JIRA] %s-%d assigned to you",
	"Your invoice #INV-%04d is ready",
	"Newsletter: %s trends this month",
	"Reminder: password expires in %d days",
	"FYI: %s release notes v%d.%d",
	"Lunch plans for %s?",
	"Feedback requested on %s",
	"Travel itinerary - confirmation #%06d",
	"Congratulations on your %s milestone!",
	"Alert: unusual sign-in from %s",
	"Expense report #%05d approved",
	"Welcome to %s!",
	"Quick question about %s",
	"Document shared: %s Q%d report",
}

var bodyParagraphs = []string{
	"Hi there, I wanted to follow up on our conversation from earlier today. Please let me know if you have any questions.",
	"As discussed in yesterday's meeting, we need to finalize the deliverables by the end of the week. Please review the attached documents and provide your feedback.",
	"I'm reaching out to confirm the schedule for next week's conference call. Could you let me know your availability?",
	"Thank you for your recent purchase. Your order is being processed and you will receive a shipping notification shortly.",
	"Please find the updated report attached. I've incorporated the changes we discussed and added the new metrics.",
	"Just a friendly reminder that your subscription is due for renewal. Visit your account settings to update your payment method.",
	"I hope this email finds you well. I wanted to share some exciting updates about our upcoming product launch.",
	"Per our discussion, I've drafted the proposal and attached it for your review. Feel free to suggest any modifications.",
	"The quarterly numbers are looking strong. Revenue is up 12%% year-over-year, and customer retention remains above 95%%.",
	"We've identified a few issues in the latest deployment. The engineering team is investigating and we'll have an update by EOD.",
	"Your feedback on the beta program has been invaluable. We've addressed the top concerns and released a patch today.",
	"The new hire onboarding documents are ready. Please complete the forms in your portal before your start date.",
	"I wanted to flag a potential conflict with the project timeline. We may need to adjust the milestones for Phase 2.",
	"Great news! The client approved the proposal. Let's schedule a kickoff meeting for early next week.",
	"Please review the attached security advisory. We recommend updating your credentials as a precautionary measure.",
}

var topics = []string{
	"Engineering", "Marketing", "Sales", "Operations", "Finance",
	"Product", "Design", "Platform", "Infrastructure", "Analytics",
	"Security", "Support", "Research", "Strategy", "Mobile",
}

var cities = []string{
	"New York", "London", "Berlin", "Tokyo", "Sydney",
	"Toronto", "Paris", "Singapore", "Sao Paulo", "Mumbai",
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

// Handler emulates email-related web endpoints: webmail, verification,
// password reset, unsubscribe, mailing list archives, and a send API.
type Handler struct{}

// NewHandler creates a new email Handler.
func NewHandler() *Handler {
	return &Handler{}
}

// ShouldHandle returns true if the request path belongs to the email subsystem.
func (h *Handler) ShouldHandle(path string) bool {
	switch path {
	case "/webmail", "/webmail/", "/webmail/login", "/webmail/inbox",
		"/api/email/send", "/verify", "/forgot-password", "/reset-password",
		"/unsubscribe":
		return true
	}
	if strings.HasPrefix(path, "/webmail/message/") {
		return true
	}
	if strings.HasPrefix(path, "/archive/") {
		return true
	}
	return false
}

// ServeHTTP dispatches email-related requests and returns the HTTP status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch {
	case path == "/webmail" || path == "/webmail/":
		return h.serveWebmailLogin(w, r)
	case path == "/webmail/login":
		return h.serveWebmailLoginPost(w, r)
	case path == "/webmail/inbox":
		return h.serveInbox(w, r)
	case strings.HasPrefix(path, "/webmail/message/"):
		return h.serveMessage(w, r)
	case path == "/api/email/send":
		return h.serveSendAPI(w, r)
	case path == "/verify":
		return h.serveVerify(w, r)
	case path == "/forgot-password":
		return h.serveForgotPassword(w, r)
	case path == "/reset-password":
		return h.serveResetPassword(w, r)
	case path == "/unsubscribe":
		return h.serveUnsubscribe(w, r)
	case strings.HasPrefix(path, "/archive/"):
		return h.serveArchive(w, r)
	}

	http.NotFound(w, r)
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Deterministic RNG helper
// ---------------------------------------------------------------------------

// seedRNG returns a deterministic *rand.Rand seeded from the provided string.
func seedRNG(key string) *rand.Rand {
	h := sha256.Sum256([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

// ---------------------------------------------------------------------------
// Fake email data generators
// ---------------------------------------------------------------------------

func randomPerson(rng *rand.Rand) (string, string) {
	first := firstNames[rng.Intn(len(firstNames))]
	last := lastNames[rng.Intn(len(lastNames))]
	domain := domains[rng.Intn(len(domains))]
	name := first + " " + last
	addr := strings.ToLower(first) + "." + strings.ToLower(last) + "@" + domain
	return name, addr
}

func randomSubject(rng *rand.Rand) string {
	tpl := subjectTemplates[rng.Intn(len(subjectTemplates))]
	topic := topics[rng.Intn(len(topics))]
	city := cities[rng.Intn(len(cities))]

	// The templates use various verbs; fill them with plausible values.
	switch {
	case strings.Contains(tpl, "%d:%02d"):
		return fmt.Sprintf(tpl, 8+rng.Intn(4), rng.Intn(60))
	case strings.Contains(tpl, "#%05d") || strings.Contains(tpl, "#%06d"):
		return fmt.Sprintf(tpl, rng.Intn(100000))
	case strings.Contains(tpl, "#INV-%04d"):
		return fmt.Sprintf(tpl, rng.Intn(10000))
	case strings.Contains(tpl, "v%d.%d"):
		return fmt.Sprintf(tpl, topic, rng.Intn(10), rng.Intn(20))
	case strings.Contains(tpl, "Q%d budget"):
		return fmt.Sprintf(tpl, 1+rng.Intn(4))
	case strings.Contains(tpl, "Q%d report"):
		return fmt.Sprintf(tpl, topic, 1+rng.Intn(4))
	case strings.Contains(tpl, "%s-%d"):
		return fmt.Sprintf(tpl, strings.ToUpper(topic[:3]), 1000+rng.Intn(9000))
	case strings.Contains(tpl, "expires in %d days"):
		return fmt.Sprintf(tpl, 1+rng.Intn(14))
	case strings.Count(tpl, "%s") == 1:
		// One string placeholder — use topic or city.
		if rng.Intn(2) == 0 {
			return fmt.Sprintf(tpl, topic)
		}
		return fmt.Sprintf(tpl, city)
	default:
		return fmt.Sprintf(tpl, topic)
	}
}

func randomBody(rng *rand.Rand, paragraphs int) string {
	var sb strings.Builder
	for i := 0; i < paragraphs; i++ {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(bodyParagraphs[rng.Intn(len(bodyParagraphs))])
	}
	return sb.String()
}

func randomDate(rng *rand.Rand, daysBack int) time.Time {
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	offset := time.Duration(rng.Intn(daysBack*24)) * time.Hour
	return now.Add(-offset)
}

type fakeEmail struct {
	ID      int
	From    string
	FromAddr string
	To      string
	ToAddr  string
	Subject string
	Date    time.Time
	Body    string
}

func generateEmail(rng *rand.Rand, id int) fakeEmail {
	fromName, fromAddr := randomPerson(rng)
	toName, toAddr := randomPerson(rng)
	return fakeEmail{
		ID:       id,
		From:     fromName,
		FromAddr: fromAddr,
		To:       toName,
		ToAddr:   toAddr,
		Subject:  randomSubject(rng),
		Date:     randomDate(rng, 30),
		Body:     randomBody(rng, 2+rng.Intn(3)),
	}
}

// ---------------------------------------------------------------------------
// Shared CSS
// ---------------------------------------------------------------------------

const webmailCSS = `
body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f0f2f5; color: #333; }
.header { background: #2c3e50; color: #ecf0f1; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
.header h1 { margin: 0; font-size: 20px; }
.header nav a { color: #bdc3c7; text-decoration: none; margin-left: 16px; font-size: 14px; }
.header nav a:hover { color: #fff; }
.container { max-width: 960px; margin: 24px auto; background: #fff; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,.12); overflow: hidden; }
.login-wrap { display: flex; justify-content: center; align-items: center; min-height: 80vh; }
.login-box { background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.15); width: 340px; }
.login-box h2 { margin: 0 0 24px; text-align: center; color: #2c3e50; }
.login-box label { display: block; margin-bottom: 4px; font-size: 13px; color: #555; }
.login-box input[type="email"], .login-box input[type="password"] { width: 100%; padding: 10px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
.login-box button { width: 100%; padding: 10px; background: #2980b9; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
.login-box button:hover { background: #2471a3; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 14px; }
th { background: #f7f8fa; color: #555; font-weight: 600; }
tr:hover { background: #f5f8fc; }
tr a { color: #2980b9; text-decoration: none; }
tr a:hover { text-decoration: underline; }
.email-view { padding: 24px; }
.email-meta { margin-bottom: 20px; border-bottom: 1px solid #eee; padding-bottom: 16px; }
.email-meta h2 { margin: 0 0 8px; color: #2c3e50; }
.email-meta .field { font-size: 13px; color: #666; margin-bottom: 4px; }
.email-meta .field strong { color: #333; }
.email-body { line-height: 1.7; white-space: pre-wrap; }
.btn { display: inline-block; padding: 8px 16px; margin-right: 8px; margin-top: 16px; background: #2980b9; color: #fff; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 13px; }
.btn.secondary { background: #7f8c8d; }
.btn.danger { background: #c0392b; }
.btn:hover { opacity: .85; }
.page-box { max-width: 520px; margin: 60px auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.15); }
.page-box h2 { margin: 0 0 16px; color: #2c3e50; }
.page-box p { color: #555; line-height: 1.6; }
.page-box input[type="email"], .page-box input[type="password"], .page-box input[type="text"] { width: 100%; padding: 10px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
.page-box button { padding: 10px 24px; background: #2980b9; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
.page-box button:hover { background: #2471a3; }
.success { color: #27ae60; }
.error { color: #c0392b; }
`

// ---------------------------------------------------------------------------
// /webmail — login page
// ---------------------------------------------------------------------------

func (h *Handler) serveWebmailLogin(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Webmail Login</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="login-wrap">
<div class="login-box">
<h2>Sign In</h2>
<form method="POST" action="/webmail/login">
<label for="email">Email Address</label>
<input type="email" id="email" name="email" placeholder="you@example.com" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<p style="text-align:center;margin-top:16px;font-size:13px;"><a href="/forgot-password" style="color:#2980b9;">Forgot password?</a></p>
</div>
</div>
</body>
</html>`, webmailCSS)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /webmail/login — process login
// ---------------------------------------------------------------------------

func (h *Handler) serveWebmailLoginPost(w http.ResponseWriter, r *http.Request) int {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/webmail", http.StatusSeeOther)
		return http.StatusSeeOther
	}

	// Generate 5 fake inbox preview emails
	rng := seedRNG("login-preview")
	var rows strings.Builder
	for i := 1; i <= 5; i++ {
		e := generateEmail(rng, i)
		rows.WriteString(fmt.Sprintf(`<tr>
<td><strong>%s</strong> &lt;%s&gt;</td>
<td><a href="/webmail/message/%d">%s</a></td>
<td>%s</td>
</tr>`, e.From, e.FromAddr, e.ID, e.Subject, e.Date.Format("Jan 02, 15:04")))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Login Successful - GlitchMail</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail/inbox">Inbox</a><a href="/webmail">Logout</a></nav></div>
<div class="container">
<div style="padding:24px;">
<p class="success" style="font-size:15px;font-weight:600;">Login successful. Welcome back!</p>
<h3 style="margin:20px 0 12px;color:#2c3e50;">Recent Messages</h3>
<table>
<thead><tr><th>From</th><th>Subject</th><th>Date</th></tr></thead>
<tbody>%s</tbody>
</table>
<p style="margin-top:16px;"><a href="/webmail/inbox" class="btn">Go to Inbox</a></p>
</div>
</div>
</body>
</html>`, webmailCSS, rows.String())

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /webmail/inbox — 20 emails
// ---------------------------------------------------------------------------

func (h *Handler) serveInbox(w http.ResponseWriter, _ *http.Request) int {
	rng := seedRNG("inbox-list")
	var rows strings.Builder
	for i := 1; i <= 20; i++ {
		e := generateEmail(rng, i)
		bold := ""
		if i <= 5 {
			bold = "font-weight:600;"
		}
		rows.WriteString(fmt.Sprintf(`<tr style="%s">
<td>%s &lt;%s&gt;</td>
<td><a href="/webmail/message/%d">%s</a></td>
<td>%s</td>
</tr>`, bold, e.From, e.FromAddr, e.ID, e.Subject, e.Date.Format("Jan 02, 2006 15:04")))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Inbox - GlitchMail</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail/inbox">Inbox</a><a href="/webmail">Logout</a></nav></div>
<div class="container">
<div style="padding:16px 24px;border-bottom:1px solid #eee;display:flex;justify-content:space-between;align-items:center;">
<h3 style="margin:0;color:#2c3e50;">Inbox <span style="color:#999;font-weight:400;">(20 messages)</span></h3>
</div>
<table>
<thead><tr><th>From</th><th>Subject</th><th>Date</th></tr></thead>
<tbody>%s</tbody>
</table>
</div>
</body>
</html>`, webmailCSS, rows.String())

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /webmail/message/{id}
// ---------------------------------------------------------------------------

func (h *Handler) serveMessage(w http.ResponseWriter, r *http.Request) int {
	idStr := strings.TrimPrefix(r.URL.Path, "/webmail/message/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return http.StatusNotFound
	}

	rng := seedRNG(fmt.Sprintf("message-%d", id))
	e := generateEmail(rng, id)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>%s - GlitchMail</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail/inbox">Inbox</a><a href="/webmail">Logout</a></nav></div>
<div class="container">
<div class="email-view">
<div class="email-meta">
<h2>%s</h2>
<div class="field"><strong>From:</strong> %s &lt;%s&gt;</div>
<div class="field"><strong>To:</strong> %s &lt;%s&gt;</div>
<div class="field"><strong>Date:</strong> %s</div>
</div>
<div class="email-body">%s</div>
<div style="margin-top:24px;border-top:1px solid #eee;padding-top:16px;">
<a href="/webmail/inbox" class="btn">Reply</a>
<a href="/webmail/inbox" class="btn secondary">Forward</a>
<a href="/webmail/inbox" class="btn danger">Delete</a>
<a href="/webmail/inbox" class="btn secondary" style="float:right;">Back to Inbox</a>
</div>
</div>
</div>
</body>
</html>`, e.Subject, webmailCSS, e.Subject, e.From, e.FromAddr,
		e.To, e.ToAddr, e.Date.Format("Mon, 02 Jan 2006 15:04:05 -0700"), e.Body)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /api/email/send
// ---------------------------------------------------------------------------

func (h *Handler) serveSendAPI(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed, use POST"})
		return http.StatusMethodNotAllowed
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to read request body"})
		return http.StatusBadRequest
	}
	defer r.Body.Close()

	var req struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return http.StatusBadRequest
	}

	if req.To == "" || req.Subject == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{"error": "to and subject are required"})
		return http.StatusUnprocessableEntity
	}

	// Generate a deterministic message ID from the payload.
	sum := sha256.Sum256(body)
	msgID := "msg_" + hex.EncodeToString(sum[:8])

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "sent",
		"message_id": msgID,
		"queued_at":  time.Now().UTC().Format(time.RFC3339),
	})
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /verify
// ---------------------------------------------------------------------------

func (h *Handler) serveVerify(w http.ResponseWriter, r *http.Request) int {
	token := r.URL.Query().Get("token")
	valid := len(token) > 0 && isHex(token)

	var statusLine, detail string
	if valid {
		statusLine = `<p class="success" style="font-size:18px;font-weight:600;">Your email has been verified!</p>`
		detail = `<p>Thank you for confirming your email address. Your account is now fully activated and you can access all features.</p>`
	} else {
		statusLine = `<p class="error" style="font-size:18px;font-weight:600;">Invalid token</p>`
		detail = `<p>The verification link is invalid or has expired. Please request a new verification email from your account settings.</p>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Email Verification</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav></nav></div>
<div class="page-box">
<h2>Email Verification</h2>
%s
%s
<p style="margin-top:24px;"><a href="/webmail" class="btn">Go to Webmail</a></p>
</div>
</body>
</html>`, webmailCSS, statusLine, detail)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// isHex reports whether s is a non-empty hex string.
func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// /forgot-password
// ---------------------------------------------------------------------------

func (h *Handler) serveForgotPassword(w http.ResponseWriter, r *http.Request) int {
	if r.Method == http.MethodPost {
		return h.serveForgotPasswordPost(w, r)
	}
	// GET: show form
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Forgot Password</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="page-box">
<h2>Reset Your Password</h2>
<p>Enter your email address and we'll send you a link to reset your password.</p>
<form method="POST" action="/forgot-password">
<label for="email" style="display:block;margin-bottom:4px;font-size:13px;color:#555;">Email Address</label>
<input type="email" id="email" name="email" placeholder="you@example.com" required>
<button type="submit">Send Reset Link</button>
</form>
<p style="margin-top:16px;font-size:13px;"><a href="/webmail" style="color:#2980b9;">Back to login</a></p>
</div>
</body>
</html>`, webmailCSS)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveForgotPasswordPost(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reset Link Sent</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="page-box">
<h2>Check Your Email</h2>
<p class="success" style="font-weight:600;">Reset link sent!</p>
<p>If an account exists with that email address, we've sent a password reset link. The link will expire in 30 minutes.</p>
<p>Didn't receive the email? Check your spam folder or <a href="/forgot-password" style="color:#2980b9;">try again</a>.</p>
<p style="margin-top:24px;"><a href="/webmail" class="btn secondary">Back to Login</a></p>
</div>
</body>
</html>`, webmailCSS)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /reset-password
// ---------------------------------------------------------------------------

func (h *Handler) serveResetPassword(w http.ResponseWriter, r *http.Request) int {
	token := r.URL.Query().Get("token")

	if r.Method == http.MethodPost {
		return h.serveResetPasswordPost(w, r)
	}

	// GET: show reset form
	if token == "" || !isHex(token) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Invalid Reset Link</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="page-box">
<h2>Invalid Reset Link</h2>
<p class="error">This password reset link is invalid or has expired.</p>
<p><a href="/forgot-password" style="color:#2980b9;">Request a new reset link</a></p>
</div>
</body>
</html>`, webmailCSS)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
		return http.StatusOK
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reset Password</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="page-box">
<h2>Set New Password</h2>
<form method="POST" action="/reset-password?token=%s">
<label for="password" style="display:block;margin-bottom:4px;font-size:13px;color:#555;">New Password</label>
<input type="password" id="password" name="password" placeholder="New password" required>
<label for="confirm" style="display:block;margin-bottom:4px;font-size:13px;color:#555;">Confirm Password</label>
<input type="password" id="confirm" name="confirm" placeholder="Confirm password" required>
<button type="submit">Update Password</button>
</form>
</div>
</body>
</html>`, webmailCSS, token)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveResetPasswordPost(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Password Updated</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Login</a></nav></div>
<div class="page-box">
<h2>Password Updated</h2>
<p class="success" style="font-weight:600;">Your password has been updated successfully.</p>
<p>You can now sign in with your new password.</p>
<p style="margin-top:24px;"><a href="/webmail" class="btn">Go to Login</a></p>
</div>
</body>
</html>`, webmailCSS)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /unsubscribe
// ---------------------------------------------------------------------------

func (h *Handler) serveUnsubscribe(w http.ResponseWriter, r *http.Request) int {
	emailAddr := r.URL.Query().Get("email")
	list := r.URL.Query().Get("list")
	if emailAddr == "" {
		emailAddr = "user@example.com"
	}
	if list == "" {
		list = "newsletter"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Unsubscribe</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav></nav></div>
<div class="page-box">
<h2>Unsubscribed</h2>
<p class="success" style="font-weight:600;">You have been unsubscribed.</p>
<p><strong>%s</strong> has been removed from the <strong>%s</strong> mailing list.</p>
<p>You will no longer receive emails from this list. It may take up to 24 hours for this change to take full effect.</p>
<div style="margin-top:24px;padding:16px;background:#f7f8fa;border-radius:4px;">
<p style="margin:0 0 8px;font-size:13px;color:#666;">Changed your mind?</p>
<form method="GET" action="/unsubscribe" style="display:inline;">
<input type="hidden" name="email" value="%s">
<input type="hidden" name="list" value="%s">
<button type="button" onclick="alert('You have been re-subscribed!')" class="btn secondary" style="font-size:13px;padding:6px 12px;">Re-subscribe</button>
</form>
</div>
</div>
</body>
</html>`, webmailCSS, emailAddr, list, emailAddr, list)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// /archive/{year}/{month}/
// ---------------------------------------------------------------------------

func (h *Handler) serveArchive(w http.ResponseWriter, r *http.Request) int {
	// Parse /archive/{year}/{month}/ or /archive/{year}/{month}/msg/{id}
	path := strings.TrimPrefix(r.URL.Path, "/archive/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		http.NotFound(w, r)
		return http.StatusNotFound
	}

	year, err := strconv.Atoi(parts[0])
	if err != nil || year < 2000 || year > 2100 {
		http.NotFound(w, r)
		return http.StatusNotFound
	}
	month, err := strconv.Atoi(parts[1])
	if err != nil || month < 1 || month > 12 {
		http.NotFound(w, r)
		return http.StatusNotFound
	}

	// /archive/{year}/{month}/msg/{id} — individual archive message
	if len(parts) == 4 && parts[2] == "msg" {
		return h.serveArchiveMessage(w, year, month, parts[3])
	}

	// Listing page
	seed := fmt.Sprintf("archive-%d-%02d", year, month)
	rng := seedRNG(seed)
	count := 10 + rng.Intn(11) // 10-20 emails

	var rows strings.Builder
	for i := 1; i <= count; i++ {
		e := generateEmail(rng, i)
		// Override date to fall within the requested month
		day := 1 + rng.Intn(28)
		hour := rng.Intn(24)
		min := rng.Intn(60)
		e.Date = time.Date(year, time.Month(month), day, hour, min, 0, 0, time.UTC)
		rows.WriteString(fmt.Sprintf(`<tr>
<td>%s &lt;%s&gt;</td>
<td><a href="/archive/%d/%02d/msg/%d">%s</a></td>
<td>%s</td>
</tr>`, e.From, e.FromAddr, year, month, i, e.Subject, e.Date.Format("Jan 02, 2006 15:04")))
	}

	monthName := time.Month(month).String()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Archive: %s %d - GlitchMail</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/webmail">Webmail</a></nav></div>
<div class="container">
<div style="padding:16px 24px;border-bottom:1px solid #eee;">
<h3 style="margin:0;color:#2c3e50;">Mailing List Archive: %s %d <span style="color:#999;font-weight:400;">(%d messages)</span></h3>
<p style="margin:8px 0 0;font-size:13px;color:#666;">
Showing all messages from the <strong>dev-announce</strong> mailing list for %s %d.
</p>
</div>
<table>
<thead><tr><th>From</th><th>Subject</th><th>Date</th></tr></thead>
<tbody>%s</tbody>
</table>
<div style="padding:16px 24px;border-top:1px solid #eee;display:flex;justify-content:space-between;font-size:13px;">
<a href="/archive/%d/%02d/" style="color:#2980b9;">Previous Month</a>
<a href="/archive/%d/%02d/" style="color:#2980b9;">Next Month</a>
</div>
</div>
</body>
</html>`, monthName, year, webmailCSS,
		monthName, year, count, monthName, year,
		rows.String(),
		prevYear(year, month), prevMonth(month),
		nextYear(year, month), nextMonth(month))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveArchiveMessage(w http.ResponseWriter, year, month int, idStr string) int {
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Message not found"))
		return http.StatusNotFound
	}

	seed := fmt.Sprintf("archive-%d-%02d-msg-%d", year, month, id)
	rng := seedRNG(seed)
	e := generateEmail(rng, id)
	day := 1 + rng.Intn(28)
	hour := rng.Intn(24)
	min := rng.Intn(60)
	e.Date = time.Date(year, time.Month(month), day, hour, min, 0, 0, time.UTC)

	monthName := time.Month(month).String()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>%s - Archive - GlitchMail</title>
<style>%s</style>
</head>
<body>
<div class="header"><h1>GlitchMail</h1><nav><a href="/archive/%d/%02d/">Back to %s %d</a><a href="/webmail">Webmail</a></nav></div>
<div class="container">
<div class="email-view">
<div class="email-meta">
<h2>%s</h2>
<div class="field"><strong>From:</strong> %s &lt;%s&gt;</div>
<div class="field"><strong>To:</strong> dev-announce@glitchmail.dev</div>
<div class="field"><strong>Date:</strong> %s</div>
<div class="field"><strong>List:</strong> dev-announce</div>
</div>
<div class="email-body">%s</div>
<div style="margin-top:24px;border-top:1px solid #eee;padding-top:16px;">
<a href="/archive/%d/%02d/" class="btn secondary">Back to Archive</a>
</div>
</div>
</div>
</body>
</html>`, e.Subject, webmailCSS,
		year, month, monthName, year,
		e.Subject, e.From, e.FromAddr,
		e.Date.Format("Mon, 02 Jan 2006 15:04:05 -0700"),
		e.Body,
		year, month)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Month navigation helpers
// ---------------------------------------------------------------------------

func prevMonth(m int) int {
	if m == 1 {
		return 12
	}
	return m - 1
}

func nextMonth(m int) int {
	if m == 12 {
		return 1
	}
	return m + 1
}

func prevYear(y, m int) int {
	if m == 1 {
		return y - 1
	}
	return y
}

func nextYear(y, m int) int {
	if m == 12 {
		return y + 1
	}
	return y
}
