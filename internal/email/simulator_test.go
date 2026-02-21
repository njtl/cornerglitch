package email

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: create a Handler and fire a request, return the recorder
// ---------------------------------------------------------------------------

func doRequest(t *testing.T, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rr := httptest.NewRecorder()
	h := NewHandler()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// ShouldHandle
// ---------------------------------------------------------------------------

func TestShouldHandle_PositivePaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/webmail",
		"/webmail/",
		"/webmail/login",
		"/webmail/inbox",
		"/api/email/send",
		"/verify",
		"/forgot-password",
		"/reset-password",
		"/unsubscribe",
		"/webmail/message/1",
		"/webmail/message/42",
		"/archive/2025/06/",
		"/archive/2024/01/msg/3",
	}
	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_NegativePaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/",
		"/index.html",
		"/api/metrics",
		"/login",
		"/mail",
		"/webmail-extra",
		"/archives/2025/06/",
	}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// /webmail — login page (GET)
// ---------------------------------------------------------------------------

func TestWebmailLoginPage(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /webmail status = %d, want %d", rr.Code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "GlitchMail") {
		t.Error("body missing GlitchMail branding")
	}
	if !strings.Contains(body, "Sign In") {
		t.Error("body missing Sign In heading")
	}
	if !strings.Contains(body, `action="/webmail/login"`) {
		t.Error("body missing form action /webmail/login")
	}
}

func TestWebmailLoginPageTrailingSlash(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /webmail/ status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "Sign In") {
		t.Error("body missing Sign In heading for trailing-slash variant")
	}
}

// ---------------------------------------------------------------------------
// /webmail/login — GET redirects, POST shows success
// ---------------------------------------------------------------------------

func TestWebmailLoginGETRedirects(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/login", "")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("GET /webmail/login status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	loc := rr.Header().Get("Location")
	if loc != "/webmail" {
		t.Errorf("redirect location = %q, want /webmail", loc)
	}
}

func TestWebmailLoginPOST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/webmail/login", strings.NewReader("email=test@example.com&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h := NewHandler()
	status := h.ServeHTTP(rr, req)

	if status != http.StatusOK {
		t.Fatalf("POST /webmail/login returned status %d, want %d", status, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Login successful") {
		t.Error("body missing Login successful message")
	}
	if !strings.Contains(body, "/webmail/inbox") {
		t.Error("body missing link to inbox")
	}
	// Should contain 5 preview email rows
	count := strings.Count(body, "/webmail/message/")
	if count < 5 {
		t.Errorf("expected at least 5 message links, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// /webmail/inbox — 20 emails
// ---------------------------------------------------------------------------

func TestInbox(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/inbox", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /webmail/inbox status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Inbox") {
		t.Error("body missing Inbox heading")
	}
	if !strings.Contains(body, "20 messages") {
		t.Error("body missing '20 messages' count")
	}
	// Should have links for all 20 messages
	for i := 1; i <= 20; i++ {
		link := "/webmail/message/" + strings.TrimSpace(strings.Repeat(" ", 0)) + itoa(i)
		if !strings.Contains(body, link) {
			t.Errorf("body missing link to message %d", i)
		}
	}
}

func TestInboxIsDeterministic(t *testing.T) {
	rr1 := doRequest(t, http.MethodGet, "/webmail/inbox", "")
	rr2 := doRequest(t, http.MethodGet, "/webmail/inbox", "")
	if rr1.Body.String() != rr2.Body.String() {
		t.Error("inbox is not deterministic: two identical requests produced different output")
	}
}

// ---------------------------------------------------------------------------
// /webmail/message/{id}
// ---------------------------------------------------------------------------

func TestMessage_Valid(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/message/1", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /webmail/message/1 status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "From:") {
		t.Error("body missing From: field")
	}
	if !strings.Contains(body, "To:") {
		t.Error("body missing To: field")
	}
	if !strings.Contains(body, "Date:") {
		t.Error("body missing Date: field")
	}
	// Check action buttons exist
	for _, btn := range []string{"Reply", "Forward", "Delete"} {
		if !strings.Contains(body, btn) {
			t.Errorf("body missing %s button", btn)
		}
	}
}

func TestMessage_DifferentIDsDifferentContent(t *testing.T) {
	rr1 := doRequest(t, http.MethodGet, "/webmail/message/1", "")
	rr2 := doRequest(t, http.MethodGet, "/webmail/message/2", "")
	if rr1.Body.String() == rr2.Body.String() {
		t.Error("message/1 and message/2 produced identical output")
	}
}

func TestMessage_Deterministic(t *testing.T) {
	rr1 := doRequest(t, http.MethodGet, "/webmail/message/7", "")
	rr2 := doRequest(t, http.MethodGet, "/webmail/message/7", "")
	if rr1.Body.String() != rr2.Body.String() {
		t.Error("same message ID produced different output on repeated requests")
	}
}

func TestMessage_InvalidID_NotNumeric(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/message/abc", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /webmail/message/abc status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestMessage_InvalidID_Zero(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/message/0", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /webmail/message/0 status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestMessage_InvalidID_Negative(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/webmail/message/-5", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /webmail/message/-5 status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// /api/email/send
// ---------------------------------------------------------------------------

func TestSendAPI_Success(t *testing.T) {
	payload := `{"to":"bob@example.com","subject":"Hello","body":"Test body"}`
	rr := doRequest(t, http.MethodPost, "/api/email/send", payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/email/send status = %d, want %d", rr.Code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
	if resp["status"] != "sent" {
		t.Errorf("status = %q, want sent", resp["status"])
	}
	if resp["message_id"] == "" {
		t.Error("message_id is empty")
	}
	if !strings.HasPrefix(resp["message_id"], "msg_") {
		t.Errorf("message_id = %q, expected msg_ prefix", resp["message_id"])
	}
	if resp["queued_at"] == "" {
		t.Error("queued_at is empty")
	}
}

func TestSendAPI_DeterministicMessageID(t *testing.T) {
	payload := `{"to":"alice@test.com","subject":"Deterministic","body":"Same body"}`
	rr1 := doRequest(t, http.MethodPost, "/api/email/send", payload)
	rr2 := doRequest(t, http.MethodPost, "/api/email/send", payload)
	var resp1, resp2 map[string]string
	json.Unmarshal(rr1.Body.Bytes(), &resp1)
	json.Unmarshal(rr2.Body.Bytes(), &resp2)
	if resp1["message_id"] != resp2["message_id"] {
		t.Errorf("message_id differs for identical payloads: %q vs %q", resp1["message_id"], resp2["message_id"])
	}
}

func TestSendAPI_MethodNotAllowed(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/api/email/send", "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/email/send status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestSendAPI_InvalidJSON(t *testing.T) {
	rr := doRequest(t, http.MethodPost, "/api/email/send", "not json at all")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/email/send with bad JSON status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "invalid JSON") {
		t.Errorf("error = %q, want 'invalid JSON'", resp["error"])
	}
}

func TestSendAPI_MissingFields(t *testing.T) {
	// Missing subject
	rr := doRequest(t, http.MethodPost, "/api/email/send", `{"to":"bob@example.com","body":"hi"}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /api/email/send (no subject) status = %d, want %d", rr.Code, http.StatusUnprocessableEntity)
	}

	// Missing to
	rr2 := doRequest(t, http.MethodPost, "/api/email/send", `{"subject":"Hi","body":"hi"}`)
	if rr2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /api/email/send (no to) status = %d, want %d", rr2.Code, http.StatusUnprocessableEntity)
	}

	// Both missing
	rr3 := doRequest(t, http.MethodPost, "/api/email/send", `{"body":"hi"}`)
	if rr3.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /api/email/send (no to, no subject) status = %d, want %d", rr3.Code, http.StatusUnprocessableEntity)
	}
}

// ---------------------------------------------------------------------------
// /verify
// ---------------------------------------------------------------------------

func TestVerify_ValidHexToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/verify?token=abcdef1234567890", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /verify?token=... status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "verified") {
		t.Error("body missing verified confirmation")
	}
	if strings.Contains(body, "Invalid token") {
		t.Error("body should not contain Invalid token for valid hex token")
	}
}

func TestVerify_InvalidToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/verify?token=not-hex!", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /verify?token=not-hex! status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid token") {
		t.Error("body missing Invalid token message")
	}
}

func TestVerify_NoToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/verify", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /verify status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid token") {
		t.Error("body missing Invalid token for empty token")
	}
}

// ---------------------------------------------------------------------------
// /forgot-password
// ---------------------------------------------------------------------------

func TestForgotPasswordGET(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/forgot-password", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /forgot-password status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Reset Your Password") {
		t.Error("body missing Reset Your Password heading")
	}
	if !strings.Contains(body, `action="/forgot-password"`) {
		t.Error("body missing form action /forgot-password")
	}
}

func TestForgotPasswordPOST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader("email=user@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h := NewHandler()
	status := h.ServeHTTP(rr, req)

	if status != http.StatusOK {
		t.Fatalf("POST /forgot-password status = %d, want %d", status, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Reset link sent") {
		t.Error("body missing Reset link sent confirmation")
	}
	if !strings.Contains(body, "Check Your Email") {
		t.Error("body missing Check Your Email heading")
	}
}

// ---------------------------------------------------------------------------
// /reset-password
// ---------------------------------------------------------------------------

func TestResetPasswordGET_ValidToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/reset-password?token=abc123def456", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /reset-password?token=abc123 status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Set New Password") {
		t.Error("body missing Set New Password heading")
	}
	if !strings.Contains(body, "abc123def456") {
		t.Error("body missing token in form action")
	}
}

func TestResetPasswordGET_NoToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/reset-password", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /reset-password (no token) status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid Reset Link") {
		t.Error("body missing Invalid Reset Link message")
	}
}

func TestResetPasswordGET_InvalidToken(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/reset-password?token=xyz!@#", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /reset-password?token=xyz! status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid Reset Link") {
		t.Error("body missing Invalid Reset Link for non-hex token")
	}
}

func TestResetPasswordPOST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/reset-password?token=abcd1234", strings.NewReader("password=newpass&confirm=newpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h := NewHandler()
	status := h.ServeHTTP(rr, req)

	if status != http.StatusOK {
		t.Fatalf("POST /reset-password status = %d, want %d", status, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Password Updated") {
		t.Error("body missing Password Updated heading")
	}
	if !strings.Contains(body, "updated successfully") {
		t.Error("body missing success confirmation")
	}
}

// ---------------------------------------------------------------------------
// /unsubscribe
// ---------------------------------------------------------------------------

func TestUnsubscribe_WithParams(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/unsubscribe?email=alice@test.com&list=updates", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /unsubscribe status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Unsubscribed") {
		t.Error("body missing Unsubscribed heading")
	}
	if !strings.Contains(body, "alice@test.com") {
		t.Error("body missing provided email address")
	}
	if !strings.Contains(body, "updates") {
		t.Error("body missing provided list name")
	}
}

func TestUnsubscribe_DefaultValues(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/unsubscribe", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /unsubscribe status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "user@example.com") {
		t.Error("body missing default email address")
	}
	if !strings.Contains(body, "newsletter") {
		t.Error("body missing default list name")
	}
}

// ---------------------------------------------------------------------------
// /archive/{year}/{month}/
// ---------------------------------------------------------------------------

func TestArchiveListing(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/06/", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /archive/2025/06/ status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "June") {
		t.Error("body missing month name June")
	}
	if !strings.Contains(body, "2025") {
		t.Error("body missing year 2025")
	}
	if !strings.Contains(body, "dev-announce") {
		t.Error("body missing mailing list name")
	}
	// Should contain links to archive messages
	if !strings.Contains(body, "/archive/2025/06/msg/") {
		t.Error("body missing archive message links")
	}
}

func TestArchiveListing_Deterministic(t *testing.T) {
	rr1 := doRequest(t, http.MethodGet, "/archive/2024/03/", "")
	rr2 := doRequest(t, http.MethodGet, "/archive/2024/03/", "")
	if rr1.Body.String() != rr2.Body.String() {
		t.Error("archive listing is not deterministic")
	}
}

func TestArchiveListing_DifferentMonthsDiffer(t *testing.T) {
	rr1 := doRequest(t, http.MethodGet, "/archive/2025/01/", "")
	rr2 := doRequest(t, http.MethodGet, "/archive/2025/02/", "")
	if rr1.Body.String() == rr2.Body.String() {
		t.Error("different months produced identical archive content")
	}
}

func TestArchiveListing_NavigationLinks(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/06/", "")
	body := rr.Body.String()
	// Previous: May 2025
	if !strings.Contains(body, "/archive/2025/05/") {
		t.Error("body missing previous month navigation link")
	}
	// Next: July 2025
	if !strings.Contains(body, "/archive/2025/07/") {
		t.Error("body missing next month navigation link")
	}
}

func TestArchiveListing_JanuaryPrevIsDecember(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/01/", "")
	body := rr.Body.String()
	// Previous month from January 2025 should be December 2024
	if !strings.Contains(body, "/archive/2024/12/") {
		t.Error("body missing previous month link (December of previous year)")
	}
}

func TestArchiveListing_DecemberNextIsJanuary(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/12/", "")
	body := rr.Body.String()
	// Next month from December 2025 should be January 2026
	if !strings.Contains(body, "/archive/2026/01/") {
		t.Error("body missing next month link (January of next year)")
	}
}

func TestArchive_InvalidPath_TooShort(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/2025 status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestArchive_InvalidYear(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/1999/06/", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/1999/06/ status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestArchive_InvalidMonth(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/13/", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/2025/13/ status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	rr2 := doRequest(t, http.MethodGet, "/archive/2025/00/", "")
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/2025/00/ status = %d, want %d", rr2.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// /archive/{year}/{month}/msg/{id}
// ---------------------------------------------------------------------------

func TestArchiveMessage_Valid(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/06/msg/3", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /archive/2025/06/msg/3 status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "From:") {
		t.Error("body missing From: field")
	}
	if !strings.Contains(body, "dev-announce@glitchmail.dev") {
		t.Error("body missing dev-announce mailing list To address")
	}
	if !strings.Contains(body, "Back to Archive") {
		t.Error("body missing Back to Archive link")
	}
}

func TestArchiveMessage_InvalidID(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/06/msg/abc", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/2025/06/msg/abc status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestArchiveMessage_ZeroID(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/archive/2025/06/msg/0", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /archive/2025/06/msg/0 status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// Unmatched paths return 404
// ---------------------------------------------------------------------------

func TestUnmatchedPath(t *testing.T) {
	rr := doRequest(t, http.MethodGet, "/nonexistent", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /nonexistent status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// Internal helpers: isHex
// ---------------------------------------------------------------------------

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", false},
		{"0", true},
		{"abcdef", true},
		{"ABCDEF", true},
		{"0123456789abcdef", true},
		{"0123456789ABCDEF", true},
		{"xyz", false},
		{"abc!", false},
		{"12 34", false},
		{"GG", false},
	}
	for _, tc := range tests {
		got := isHex(tc.input)
		if got != tc.want {
			t.Errorf("isHex(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Month/Year navigation helpers
// ---------------------------------------------------------------------------

func TestPrevMonth(t *testing.T) {
	cases := []struct{ in, want int }{
		{1, 12}, {2, 1}, {6, 5}, {12, 11},
	}
	for _, tc := range cases {
		if got := prevMonth(tc.in); got != tc.want {
			t.Errorf("prevMonth(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestNextMonth(t *testing.T) {
	cases := []struct{ in, want int }{
		{12, 1}, {1, 2}, {6, 7}, {11, 12},
	}
	for _, tc := range cases {
		if got := nextMonth(tc.in); got != tc.want {
			t.Errorf("nextMonth(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPrevYear(t *testing.T) {
	cases := []struct{ y, m, want int }{
		{2025, 1, 2024}, // January wraps to previous year
		{2025, 2, 2025}, // February stays
		{2025, 12, 2025},
	}
	for _, tc := range cases {
		if got := prevYear(tc.y, tc.m); got != tc.want {
			t.Errorf("prevYear(%d, %d) = %d, want %d", tc.y, tc.m, got, tc.want)
		}
	}
}

func TestNextYear(t *testing.T) {
	cases := []struct{ y, m, want int }{
		{2025, 12, 2026}, // December wraps to next year
		{2025, 11, 2025}, // November stays
		{2025, 1, 2025},
	}
	for _, tc := range cases {
		if got := nextYear(tc.y, tc.m); got != tc.want {
			t.Errorf("nextYear(%d, %d) = %d, want %d", tc.y, tc.m, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// seedRNG determinism
// ---------------------------------------------------------------------------

func TestSeedRNG_Deterministic(t *testing.T) {
	rng1 := seedRNG("test-key")
	rng2 := seedRNG("test-key")
	for i := 0; i < 20; i++ {
		v1 := rng1.Intn(1000000)
		v2 := rng2.Intn(1000000)
		if v1 != v2 {
			t.Fatalf("seedRNG not deterministic: iteration %d, got %d vs %d", i, v1, v2)
		}
	}
}

func TestSeedRNG_DifferentKeys(t *testing.T) {
	rng1 := seedRNG("key-a")
	rng2 := seedRNG("key-b")
	same := true
	for i := 0; i < 10; i++ {
		if rng1.Intn(1000000) != rng2.Intn(1000000) {
			same = false
			break
		}
	}
	if same {
		t.Error("different seed keys produced identical sequences")
	}
}

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}
}

// ---------------------------------------------------------------------------
// Content-Type checks across endpoints
// ---------------------------------------------------------------------------

func TestContentTypeHTML(t *testing.T) {
	htmlPaths := []string{
		"/webmail",
		"/webmail/inbox",
		"/webmail/message/1",
		"/verify?token=aabbccdd",
		"/forgot-password",
		"/reset-password?token=aabb",
		"/unsubscribe",
		"/archive/2025/06/",
		"/archive/2025/06/msg/1",
	}
	for _, p := range htmlPaths {
		rr := doRequest(t, http.MethodGet, p, "")
		ct := rr.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("GET %s Content-Type = %q, want text/html", p, ct)
		}
	}
}

func TestContentTypeJSON_SendAPI(t *testing.T) {
	// Successful POST
	rr := doRequest(t, http.MethodPost, "/api/email/send", `{"to":"a@b.com","subject":"s","body":"b"}`)
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("POST /api/email/send Content-Type = %q, want application/json", ct)
	}

	// Method not allowed (GET)
	rr2 := doRequest(t, http.MethodGet, "/api/email/send", "")
	ct2 := rr2.Header().Get("Content-Type")
	if !strings.Contains(ct2, "application/json") {
		t.Errorf("GET /api/email/send Content-Type = %q, want application/json", ct2)
	}
}

// ---------------------------------------------------------------------------
// small helper to avoid importing strconv in test
// ---------------------------------------------------------------------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
