package captcha

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// ChallengeType defines the kind of CAPTCHA or anti-bot challenge to serve.
type ChallengeType int

const (
	ChallengeRecaptchaV2    ChallengeType = iota // Google reCAPTCHA v2 checkbox + image grid
	ChallengeRecaptchaV3                         // Invisible reCAPTCHA v3 score-based
	ChallengeHCaptcha                            // hCaptcha image selection
	ChallengeTurnstile                           // Cloudflare Turnstile widget
	ChallengeCloudflareUAM                       // Cloudflare Under Attack Mode 5s challenge
	ChallengeAWSWAF                              // AWS WAF CAPTCHA page
	ChallengeMathProblem                         // Simple math question
	ChallengeSVGText                             // SVG-rendered distorted text CAPTCHA
	challengeCount                               // sentinel for modular selection
)

// Engine emulates various CAPTCHA and anti-bot challenge systems.
// Certain paths or request patterns trigger challenge pages. "Solving" the
// challenge either passes through or escalates into another challenge.
type Engine struct {
	challenges []ChallengeType
}

// NewEngine creates a captcha engine with all challenge types enabled.
func NewEngine() *Engine {
	challenges := make([]ChallengeType, int(challengeCount))
	for i := range challenges {
		challenges[i] = ChallengeType(i)
	}
	return &Engine{
		challenges: challenges,
	}
}

// ShouldChallenge returns true when the request should be interrupted with a
// CAPTCHA or anti-bot challenge page.
func (e *Engine) ShouldChallenge(path string, clientClass string, requestCount int) bool {
	// Protected path prefixes always trigger a challenge
	if strings.HasPrefix(path, "/secure/") ||
		strings.HasPrefix(path, "/protected/") ||
		strings.HasPrefix(path, "/members/") {
		return true
	}

	// AI scrapers and script bots: 30% chance
	if clientClass == "ai_scraper" || clientClass == "script_bot" {
		return rand.Float64() < 0.30
	}

	// Load testers: 50% chance
	if clientClass == "load_tester" {
		return rand.Float64() < 0.50
	}

	// High request count clients: 10% chance for anyone
	if requestCount > 100 {
		return rand.Float64() < 0.10
	}

	return false
}

// SelectChallenge deterministically picks a challenge type based on SHA-256
// of the clientID, so the same client always sees the same challenge family.
func (e *Engine) SelectChallenge(clientID string) ChallengeType {
	h := sha256.Sum256([]byte(clientID))
	idx := binary.BigEndian.Uint32(h[:4])
	return e.challenges[int(idx)%len(e.challenges)]
}

// ServeChallenge generates a full HTML challenge page for the given type and
// writes it to w. Returns the HTTP status code written.
func (e *Engine) ServeChallenge(w http.ResponseWriter, r *http.Request, ct ChallengeType) int {
	redirect := r.URL.Path
	if r.URL.RawQuery != "" {
		redirect += "?" + r.URL.RawQuery
	}
	csrf := e.csrfToken(r.URL.Path)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	var html string
	switch ct {
	case ChallengeRecaptchaV2:
		html = e.recaptchaV2Page(redirect, csrf)
	case ChallengeRecaptchaV3:
		html = e.recaptchaV3Page(redirect, csrf)
		w.Header().Set("X-ReCaptcha-Score", "0.9")
	case ChallengeHCaptcha:
		html = e.hcaptchaPage(redirect, csrf)
	case ChallengeTurnstile:
		html = e.turnstilePage(redirect, csrf)
	case ChallengeCloudflareUAM:
		html = e.cloudflareUAMPage(redirect, csrf)
	case ChallengeAWSWAF:
		html = e.awsWAFPage(redirect, csrf)
	case ChallengeMathProblem:
		html = e.mathProblemPage(r.URL.Path, redirect, csrf)
	case ChallengeSVGText:
		html = e.svgTextPage(r.URL.Path, redirect, csrf)
	default:
		html = e.recaptchaV2Page(redirect, csrf)
	}

	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
	return http.StatusForbidden
}

// HandleVerify processes POST to /captcha/verify. It always "passes" the
// challenge with a 302 redirect back to the original path, or 50% of the
// time escalates by serving another challenge instead.
func (e *Engine) HandleVerify(w http.ResponseWriter, r *http.Request) int {
	r.ParseForm()
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}

	// 50% chance of escalation: serve another challenge instead of passing
	if rand.Float64() < 0.50 {
		// Pick a different challenge based on form token + randomness
		token := r.FormValue("csrf_token")
		h := sha256.Sum256([]byte(token + fmt.Sprintf("%d", rand.Int63())))
		idx := binary.BigEndian.Uint32(h[:4])
		ct := e.challenges[int(idx)%len(e.challenges)]

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		csrf := e.csrfToken(redirect)
		var html string
		switch ct {
		case ChallengeRecaptchaV2:
			html = e.recaptchaV2Page(redirect, csrf)
		case ChallengeRecaptchaV3:
			html = e.recaptchaV3Page(redirect, csrf)
			w.Header().Set("X-ReCaptcha-Score", "0.3")
		case ChallengeHCaptcha:
			html = e.hcaptchaPage(redirect, csrf)
		case ChallengeTurnstile:
			html = e.turnstilePage(redirect, csrf)
		case ChallengeCloudflareUAM:
			html = e.cloudflareUAMPage(redirect, csrf)
		case ChallengeAWSWAF:
			html = e.awsWAFPage(redirect, csrf)
		case ChallengeMathProblem:
			html = e.mathProblemPage(redirect, redirect, csrf)
		case ChallengeSVGText:
			html = e.svgTextPage(redirect, redirect, csrf)
		default:
			html = e.recaptchaV2Page(redirect, csrf)
		}

		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(html))
		return http.StatusForbidden
	}

	// Pass: redirect to the original page
	http.Redirect(w, r, redirect, http.StatusFound)
	return http.StatusFound
}

// csrfToken generates a deterministic CSRF token from the path seed.
func (e *Engine) csrfToken(path string) string {
	h := sha256.Sum256([]byte("csrf-salt-glitch:" + path))
	return fmt.Sprintf("%x", h[:16])
}

// pathSeed derives a deterministic int64 seed from a path string.
func pathSeed(path string) int64 {
	h := sha256.Sum256([]byte(path))
	return int64(binary.BigEndian.Uint64(h[:8]))
}

// ---------------------------------------------------------------------------
// Challenge page generators
// ---------------------------------------------------------------------------

func (e *Engine) recaptchaV2Page(redirect, csrf string) string {
	// Generate a 3x3 grid of colored SVG squares for the image challenge
	var grid strings.Builder
	colors := []string{"#4a7c59", "#8b4513", "#2f4f4f", "#556b2f", "#6b3a2a", "#3d5c5c", "#7a6b3a", "#4a6741", "#5c3d2e"}
	for i := 0; i < 9; i++ {
		checked := ""
		if i == 2 || i == 5 || i == 7 {
			checked = "checked"
		}
		grid.WriteString(fmt.Sprintf(`<label class="grid-cell">
              <input type="checkbox" name="tile_%d" value="1" %s>
              <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
                <rect width="100" height="100" fill="%s"/>
                <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#333" stroke-width="2"/>
                <circle cx="%d" cy="%d" r="%d" fill="%s" opacity="0.6"/>
              </svg>
            </label>`, i, checked, colors[i],
			10+i*8, 10+i*5, 90-i*3, 90-i*7,
			30+i*7, 40+i*5, 10+i*2, colors[(i+3)%len(colors)]))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>reCAPTCHA verification</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Roboto, "Segoe UI", Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .recaptcha-container { background: #fff; border: 1px solid #d3d3d3; border-radius: 3px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 400px; }
    .recaptcha-header { background: #4a90d9; color: #fff; padding: 12px 16px; font-size: 14px; font-weight: 500; border-radius: 3px 3px 0 0; }
    .recaptcha-header .brand { font-size: 11px; opacity: 0.8; margin-top: 2px; }
    .recaptcha-body { padding: 16px; }
    .challenge-text { font-size: 15px; color: #202124; margin-bottom: 12px; font-weight: 500; }
    .challenge-subtext { font-size: 13px; color: #5f6368; margin-bottom: 16px; }
    .image-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2px; margin-bottom: 16px; background: #e0e0e0; border: 2px solid #e0e0e0; }
    .grid-cell { position: relative; cursor: pointer; display: block; }
    .grid-cell input { position: absolute; opacity: 0; width: 0; height: 0; }
    .grid-cell svg { display: block; width: 100%%; height: auto; }
    .grid-cell input:checked + svg { outline: 3px solid #4a90d9; outline-offset: -3px; }
    .checkbox-row { display: flex; align-items: center; padding: 12px 0; border-top: 1px solid #e0e0e0; margin-top: 8px; }
    .g-recaptcha-checkbox { width: 28px; height: 28px; border: 2px solid #c1c1c1; border-radius: 3px; margin-right: 12px; cursor: pointer; background: #fff; display: flex; align-items: center; justify-content: center; }
    .g-recaptcha-checkbox:hover { border-color: #4a90d9; }
    .checkbox-label { font-size: 14px; color: #202124; }
    .recaptcha-footer { display: flex; justify-content: space-between; align-items: center; padding: 8px 16px; background: #f9f9f9; border-top: 1px solid #e0e0e0; border-radius: 0 0 3px 3px; }
    .recaptcha-logo { display: flex; align-items: center; gap: 8px; }
    .recaptcha-logo svg { width: 32px; height: 32px; }
    .recaptcha-logo-text { font-size: 10px; color: #555; line-height: 1.3; }
    .recaptcha-logo-text a { color: #4a90d9; text-decoration: none; }
    .verify-btn { background: #4a90d9; color: #fff; border: none; padding: 10px 24px; font-size: 14px; border-radius: 3px; cursor: pointer; }
    .verify-btn:hover { background: #357abd; }
  </style>
</head>
<body>
  <form method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="recaptcha_v2">
    <div class="recaptcha-container">
      <div class="recaptcha-header">
        <div>Select all images with <strong>traffic lights</strong></div>
        <div class="brand">powered by reCAPTCHA</div>
      </div>
      <div class="recaptcha-body">
        <div class="challenge-text">Select all images with traffic lights</div>
        <div class="challenge-subtext">If there are none, click verify</div>
        <div class="image-grid">
          %s
        </div>
        <div class="checkbox-row">
          <div class="g-recaptcha-checkbox" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI">
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path d="M2 9L7 14L16 4" stroke="#4a90d9" stroke-width="2.5" fill="none" stroke-linecap="round"/>
            </svg>
          </div>
          <span class="checkbox-label">I'm not a robot</span>
        </div>
      </div>
      <div class="recaptcha-footer">
        <div class="recaptcha-logo">
          <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
            <path d="M32 2a30 30 0 1 0 0 60 30 30 0 0 0 0-60zm0 5a25 25 0 0 1 22 13H10A25 25 0 0 1 32 7z" fill="#4a90d9"/>
            <path d="M32 22a10 10 0 1 0 0 20 10 10 0 0 0 0-20z" fill="#357abd"/>
          </svg>
          <div class="recaptcha-logo-text">
            <a href="#">reCAPTCHA</a><br>
            <a href="#">Privacy</a> - <a href="#">Terms</a>
          </div>
        </div>
        <button type="submit" class="verify-btn">Verify</button>
      </div>
    </div>
  </form>
  <div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" style="display:none;"></div>
  <script>
    // reCAPTCHA v2 client-side integration
    var grecaptcha = grecaptcha || {};
    grecaptcha.ready = function(cb) { setTimeout(cb, 100); };
    grecaptcha.execute = function(sitekey, opts) { return Promise.resolve("03AGdBq24PBCbwiDRaS_MJ7Z...faketoken...Zk9"); };
  </script>
</body>
</html>`, redirect, csrf, grid.String())
}

func (e *Engine) recaptchaV3Page(redirect, csrf string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying...</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Segoe UI", Roboto, Arial, sans-serif; background: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .v3-container { text-align: center; }
    .spinner { width: 40px; height: 40px; border: 3px solid #e0e0e0; border-top: 3px solid #4a90d9; border-radius: 50%%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .v3-text { font-size: 14px; color: #5f6368; }
    .v3-badge { position: fixed; bottom: 14px; right: 14px; background: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 3px; padding: 8px 12px; font-size: 10px; color: #555; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .v3-badge a { color: #4a90d9; text-decoration: none; }
    .v3-badge img { width: 24px; vertical-align: middle; margin-right: 4px; }
  </style>
</head>
<body>
  <form id="v3form" method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="recaptcha_v3">
    <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response" value="">
  </form>
  <div class="v3-container">
    <div class="spinner"></div>
    <div class="v3-text">Verifying you are human...</div>
  </div>
  <div class="v3-badge">
    protected by <a href="#">reCAPTCHA</a>
    <br><a href="#">Privacy</a> - <a href="#">Terms</a>
  </div>
  <script src="https://www.google.com/recaptcha/api.js?render=6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"></script>
  <script>
    // reCAPTCHA v3 integration — invisible score-based check
    var grecaptcha = window.grecaptcha || { ready: function(cb) { setTimeout(cb, 500); }, execute: function() { return Promise.resolve("03AGdBq26...fakeV3Token...xYz"); } };
    grecaptcha.ready(function() {
      grecaptcha.execute('6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe', {action: 'submit'}).then(function(token) {
        document.getElementById('g-recaptcha-response').value = token;
        // Simulate verification delay
        setTimeout(function() {
          document.getElementById('v3form').submit();
        }, 2000);
      });
    });
  </script>
</body>
</html>`, redirect, csrf)
}

func (e *Engine) hcaptchaPage(redirect, csrf string) string {
	// Generate a 3x3 image selection grid for hCaptcha
	var grid strings.Builder
	hueStart := 120 // green range for "plants"
	for i := 0; i < 9; i++ {
		hue := hueStart + i*25
		grid.WriteString(fmt.Sprintf(`<label class="hc-cell">
              <input type="checkbox" name="hc_tile_%d" value="1">
              <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
                <rect width="100" height="100" fill="hsl(%d, 45%%%%, 40%%%%)"/>
                <rect x="%d" y="%d" width="%d" height="%d" fill="hsl(%d, 55%%%%, 55%%%%)" rx="4"/>
                <circle cx="%d" cy="%d" r="%d" fill="hsl(%d, 40%%%%, 30%%%%)" opacity="0.5"/>
              </svg>
            </label>`, i, hue, 15+i*3, 20+i*4, 30+i*2, 25+i*3, hue+30, 60+i*3, 55+i*2, 8+i, hue-20))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>hCaptcha Security Check</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .hcaptcha-container { background: #fff; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); width: 340px; overflow: hidden; }
    .hc-header { background: linear-gradient(135deg, #00838f, #0097a7); color: #fff; padding: 14px 18px; }
    .hc-header h3 { font-size: 14px; font-weight: 600; }
    .hc-header .hc-brand { font-size: 11px; opacity: 0.85; margin-top: 2px; }
    .hc-body { padding: 16px; }
    .hc-prompt { font-size: 14px; color: #333; margin-bottom: 14px; font-weight: 500; }
    .hc-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 3px; margin-bottom: 14px; }
    .hc-cell { display: block; cursor: pointer; position: relative; }
    .hc-cell input { position: absolute; opacity: 0; width: 0; height: 0; }
    .hc-cell svg { display: block; width: 100%%; height: auto; border-radius: 2px; }
    .hc-cell input:checked + svg { outline: 3px solid #0097a7; outline-offset: -3px; }
    .hc-footer { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px; background: #fafafa; border-top: 1px solid #e0e0e0; }
    .hc-logo { font-size: 11px; color: #888; }
    .hc-logo a { color: #0097a7; text-decoration: none; }
    .hc-submit { background: #0097a7; color: #fff; border: none; padding: 8px 20px; border-radius: 3px; cursor: pointer; font-size: 13px; }
    .hc-submit:hover { background: #00838f; }
    .h-captcha { display: none; }
  </style>
</head>
<body>
  <form method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="hcaptcha">
    <input type="hidden" name="h-captcha-response" value="">
    <div class="hcaptcha-container">
      <div class="hc-header">
        <h3>Please complete this security check</h3>
        <div class="hc-brand">hCaptcha</div>
      </div>
      <div class="hc-body">
        <div class="hc-prompt">Select all images containing a <strong>plant</strong></div>
        <div class="hc-grid">
          %s
        </div>
      </div>
      <div class="hc-footer">
        <div class="hc-logo"><a href="#">hCaptcha</a> &middot; <a href="#">Privacy</a></div>
        <button type="submit" class="hc-submit">Check</button>
      </div>
    </div>
    <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
  </form>
  <script>
    // hCaptcha integration stub
    var hcaptcha = hcaptcha || {};
    hcaptcha.render = function(el, opts) { return "hcaptcha-widget-id-0"; };
    hcaptcha.getResponse = function() { return "10000000-aaaa-bbbb-cccc-000000000001"; };
  </script>
</body>
</html>`, redirect, csrf, grid.String())
}

func (e *Engine) turnstilePage(redirect, csrf string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Just a moment...</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8f8f8; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .turnstile-container { background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 32px 40px; text-align: center; width: 380px; }
    .ts-title { font-size: 18px; color: #333; margin-bottom: 8px; font-weight: 600; }
    .ts-subtitle { font-size: 13px; color: #777; margin-bottom: 24px; }
    .cf-turnstile { display: flex; justify-content: center; align-items: center; height: 65px; background: #fafafa; border: 1px solid #e5e5e5; border-radius: 4px; margin-bottom: 20px; }
    .ts-spinner { width: 28px; height: 28px; border: 3px solid #e5e5e5; border-top: 3px solid #f48120; border-radius: 50%%; animation: tsSpin 0.7s linear infinite; margin-right: 12px; }
    @keyframes tsSpin { to { transform: rotate(360deg); } }
    .ts-check-text { font-size: 13px; color: #555; }
    .ts-success { display: none; color: #2ecc71; font-size: 14px; font-weight: 600; }
    .ts-branding { margin-top: 16px; font-size: 11px; color: #999; }
    .ts-branding a { color: #f48120; text-decoration: none; }
    .ts-branding svg { width: 18px; height: 18px; vertical-align: middle; margin-right: 4px; }
  </style>
</head>
<body>
  <form id="tsForm" method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="turnstile">
    <input type="hidden" name="cf-turnstile-response" id="cf-turnstile-response" value="">
    <div class="turnstile-container">
      <div class="ts-title">Verifying you are human</div>
      <div class="ts-subtitle">This may take a few seconds</div>
      <div class="cf-turnstile" data-sitekey="0x4AAAAAAAB1cDE2fGHiJKlm" data-callback="tsCallback">
        <div class="ts-spinner" id="tsSpinner"></div>
        <span class="ts-check-text" id="tsText">Verifying...</span>
        <span class="ts-success" id="tsSuccess">&#10003; Verified</span>
      </div>
      <div class="ts-branding">
        <svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg">
          <circle cx="20" cy="20" r="18" fill="none" stroke="#f48120" stroke-width="3"/>
          <path d="M20 8 L20 22 L28 22" stroke="#f48120" stroke-width="2.5" fill="none" stroke-linecap="round"/>
        </svg>
        Managed by <a href="#">Cloudflare Turnstile</a>
      </div>
    </div>
  </form>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>
  <script>
    // Cloudflare Turnstile client integration
    var turnstile = window.turnstile || { render: function(el, opts) { if (opts.callback) setTimeout(function() { opts.callback("0.turnstileToken.fakeValue.abcdef1234"); }, 3000); } };
    function tsCallback(token) {
      document.getElementById('cf-turnstile-response').value = token;
      document.getElementById('tsSpinner').style.display = 'none';
      document.getElementById('tsText').style.display = 'none';
      document.getElementById('tsSuccess').style.display = 'inline';
      setTimeout(function() {
        document.getElementById('tsForm').submit();
      }, 800);
    }
    // Start verification
    setTimeout(function() {
      tsCallback("0.turnstileToken.fakeValue." + Math.random().toString(36).slice(2));
    }, 3000);
  </script>
</body>
</html>`, redirect, csrf)
}

func (e *Engine) cloudflareUAMPage(redirect, csrf string) string {
	rayID := fmt.Sprintf("%x", sha256.Sum256([]byte("ray:"+redirect)))[:16]
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Just a moment... | Cloudflare</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f5f5f5; color: #333; }
    .cf-wrapper { max-width: 550px; margin: 80px auto; text-align: center; }
    .cf-shield { margin-bottom: 24px; }
    .cf-shield svg { width: 64px; height: 64px; }
    .cf-title { font-size: 24px; font-weight: 600; margin-bottom: 8px; color: #1a1a1a; }
    .cf-subtitle { font-size: 14px; color: #555; margin-bottom: 32px; }
    .cf-domain { font-weight: 600; color: #f6821f; }
    .cf-progress-container { background: #e0e0e0; border-radius: 4px; height: 6px; margin: 0 40px 16px; overflow: hidden; }
    .cf-progress-bar { background: linear-gradient(90deg, #f6821f, #ff9f43); height: 100%%; width: 0%%; border-radius: 4px; animation: cfProgress 5s ease-in-out forwards; }
    @keyframes cfProgress { 0%% { width: 0%%; } 40%% { width: 45%%; } 70%% { width: 80%%; } 100%% { width: 100%%; } }
    .cf-countdown { font-size: 13px; color: #777; margin-bottom: 24px; }
    .cf-countdown #cfTime { font-weight: 600; color: #f6821f; }
    .cf-info { background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; padding: 16px 24px; margin: 0 20px 24px; text-align: left; }
    .cf-info-title { font-size: 13px; font-weight: 600; color: #1a1a1a; margin-bottom: 6px; }
    .cf-info-text { font-size: 12px; color: #666; line-height: 1.5; }
    .cf-footer { font-size: 11px; color: #999; margin-top: 40px; padding-top: 16px; border-top: 1px solid #e0e0e0; }
    .cf-footer a { color: #f6821f; text-decoration: none; }
    .cf-ray { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 11px; color: #aaa; }
    .cf-challenge-form { display: none; }
    .cf-logo-text { font-size: 13px; color: #999; margin-top: 12px; }
    .cf-logo-text a { color: #f6821f; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="cf-wrapper">
    <div class="cf-shield">
      <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
        <path d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z" fill="#f6821f" opacity="0.15"/>
        <path d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z" fill="none" stroke="#f6821f" stroke-width="2"/>
        <path d="M26 32l4 4 8-8" stroke="#f6821f" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <div class="cf-title">Checking your browser before accessing</div>
    <div class="cf-subtitle"><span class="cf-domain">this site</span> needs to verify your connection is secure</div>
    <div class="cf-progress-container">
      <div class="cf-progress-bar"></div>
    </div>
    <div class="cf-countdown">Please wait <span id="cfTime">5</span> seconds...</div>
    <div class="cf-info">
      <div class="cf-info-title">Why am I seeing this page?</div>
      <div class="cf-info-text">
        This process is automatic. Your browser will redirect to your requested content shortly.
        Please allow up to 5 seconds. This security check is performed to protect the website
        from online attacks. DDoS protection by Cloudflare.
      </div>
    </div>
    <form id="uamForm" class="cf-challenge-form" method="POST" action="/captcha/verify">
      <input type="hidden" name="redirect" value="%s">
      <input type="hidden" name="csrf_token" value="%s">
      <input type="hidden" name="challenge_type" value="cloudflare_uam">
      <input type="hidden" name="jschl_vc" id="jschl_vc" value="">
      <input type="hidden" name="jschl_answer" id="jschl_answer" value="">
      <input type="hidden" name="pass" value="1620000000.000-fakeuampass">
    </form>
    <div class="cf-footer">
      <div class="cf-ray">Ray ID: %s</div>
      <div class="cf-logo-text">Performance &amp; security by <a href="#">Cloudflare</a></div>
    </div>
  </div>
  <script>
    // Cloudflare UAM JavaScript challenge computation
    (function() {
      var t = document.getElementById('cfTime');
      var count = 5;
      var interval = setInterval(function() {
        count--;
        if (t) t.textContent = count;
        if (count <= 0) {
          clearInterval(interval);
          // Perform "challenge" computation
          var a = 0;
          for (var i = 0; i < 10000; i++) { a += Math.sqrt(i) * Math.sin(i); }
          document.getElementById('jschl_answer').value = a.toFixed(10);
          document.getElementById('jschl_vc').value = '%s';
          document.getElementById('uamForm').submit();
        }
      }, 1000);
    })();
  </script>
</body>
</html>`, redirect, csrf, rayID, rayID)
}

func (e *Engine) awsWAFPage(redirect, csrf string) string {
	requestID := fmt.Sprintf("%x", sha256.Sum256([]byte("aws:"+redirect)))[:32]
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Request Blocked</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Amazon Ember", "Helvetica Neue", Helvetica, Arial, sans-serif; background: #f2f3f3; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .aws-container { background: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); max-width: 520px; width: 100%%; overflow: hidden; }
    .aws-header { background: #232f3e; padding: 14px 24px; display: flex; align-items: center; }
    .aws-header svg { width: 36px; height: 22px; margin-right: 12px; }
    .aws-header-text { color: #ff9900; font-size: 14px; font-weight: 700; letter-spacing: 0.5px; }
    .aws-body { padding: 28px 24px; }
    .aws-alert { display: flex; align-items: flex-start; padding: 12px 16px; background: #fef3cd; border: 1px solid #ffc107; border-radius: 4px; margin-bottom: 20px; }
    .aws-alert-icon { color: #856404; font-size: 18px; margin-right: 10px; flex-shrink: 0; }
    .aws-alert-text { font-size: 13px; color: #856404; line-height: 1.5; }
    .aws-title { font-size: 20px; color: #16191f; margin-bottom: 12px; font-weight: 600; }
    .aws-text { font-size: 13px; color: #545b64; line-height: 1.6; margin-bottom: 16px; }
    .aws-captcha-widget { background: #fafafa; border: 1px solid #d5dbdb; border-radius: 4px; padding: 20px; margin-bottom: 20px; text-align: center; }
    .aws-captcha-label { font-size: 13px; color: #16191f; margin-bottom: 12px; font-weight: 500; }
    .aws-checkbox-row { display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 16px; }
    .aws-checkbox { width: 22px; height: 22px; border: 2px solid #879596; border-radius: 3px; cursor: pointer; background: #fff; }
    .aws-checkbox-text { font-size: 14px; color: #16191f; }
    .aws-submit { background: #ff9900; color: #fff; border: none; padding: 8px 20px; border-radius: 3px; cursor: pointer; font-size: 13px; font-weight: 600; }
    .aws-submit:hover { background: #ec7211; }
    .aws-footer { background: #fafafa; border-top: 1px solid #eaeded; padding: 12px 24px; }
    .aws-meta { font-size: 11px; color: #879596; }
    .aws-meta code { font-family: "SFMono-Regular", Consolas, monospace; background: #f2f3f3; padding: 1px 4px; border-radius: 2px; }
  </style>
</head>
<body>
  <form method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="aws_waf">
    <div class="aws-container">
      <div class="aws-header">
        <svg viewBox="0 0 60 36" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 24c-6 3-12 4-18 2 0 0 6 5 18 5s16-4 16-4l-4-3z" fill="#ff9900"/>
          <path d="M30 6C18 6 10 14 10 22c0 2 0 4 2 6 8-10 20-14 30-10 2-4 2-8 0-12z" fill="#fff"/>
        </svg>
        <span class="aws-header-text">AWS WAF</span>
      </div>
      <div class="aws-body">
        <div class="aws-alert">
          <span class="aws-alert-icon">&#9888;</span>
          <span class="aws-alert-text">Your request has been blocked by a security rule. Please complete the verification below to continue.</span>
        </div>
        <div class="aws-title">Request Blocked</div>
        <div class="aws-text">
          The request could not be satisfied. This site is protected by AWS WAF (Web Application Firewall).
          If you believe this is an error, please complete the CAPTCHA challenge below to verify your identity.
        </div>
        <div class="aws-captcha-widget">
          <div class="aws-captcha-label">Complete this verification to continue</div>
          <div class="aws-checkbox-row">
            <input type="checkbox" name="aws_captcha_check" value="1" class="aws-checkbox" required>
            <span class="aws-checkbox-text">I am not a robot</span>
          </div>
          <button type="submit" class="aws-submit">Submit</button>
        </div>
      </div>
      <div class="aws-footer">
        <div class="aws-meta">
          Request ID: <code>%s</code><br>
          If this problem persists, contact the site administrator.
        </div>
      </div>
    </div>
  </form>
  <script>
    // AWS WAF CAPTCHA integration stub
    window.AwsWafIntegration = window.AwsWafIntegration || {
      getToken: function() { return Promise.resolve({ token: "aws-waf-token-" + Date.now() }); },
      forceRefresh: function() { return this.getToken(); }
    };
  </script>
</body>
</html>`, redirect, csrf, requestID)
}

func (e *Engine) mathProblemPage(path, redirect, csrf string) string {
	// Deterministic math problem from path
	rng := rand.New(rand.NewSource(pathSeed(path)))
	a := rng.Intn(20) + 1
	b := rng.Intn(20) + 1
	ops := []string{"+", "-", "*"}
	op := ops[rng.Intn(len(ops))]

	var question string
	switch op {
	case "+":
		question = fmt.Sprintf("%d + %d", a, b)
	case "-":
		// Ensure positive result
		if a < b {
			a, b = b, a
		}
		question = fmt.Sprintf("%d - %d", a, b)
	case "*":
		// Keep numbers small for multiplication
		a = rng.Intn(12) + 1
		b = rng.Intn(12) + 1
		question = fmt.Sprintf("%d &times; %d", a, b)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Check</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Segoe UI", Roboto, Arial, sans-serif; background: linear-gradient(135deg, #667eea, #764ba2); display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .math-container { background: #fff; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); padding: 36px 40px; width: 380px; text-align: center; }
    .math-icon { font-size: 48px; margin-bottom: 16px; }
    .math-title { font-size: 20px; color: #333; margin-bottom: 8px; font-weight: 600; }
    .math-subtitle { font-size: 13px; color: #777; margin-bottom: 28px; }
    .math-question { font-size: 32px; color: #333; font-weight: 700; margin-bottom: 20px; padding: 16px; background: #f4f4f9; border-radius: 8px; font-family: "SF Mono", "Fira Code", monospace; }
    .math-input { width: 120px; padding: 10px; font-size: 20px; text-align: center; border: 2px solid #ddd; border-radius: 6px; outline: none; font-family: "SF Mono", "Fira Code", monospace; }
    .math-input:focus { border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.2); }
    .math-submit { display: block; width: 100%%; margin-top: 20px; padding: 12px; background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; border: none; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; }
    .math-submit:hover { opacity: 0.9; }
    .math-note { font-size: 11px; color: #aaa; margin-top: 16px; }
  </style>
</head>
<body>
  <form method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="math">
    <div class="math-container">
      <div class="math-icon">&#128274;</div>
      <div class="math-title">Human Verification</div>
      <div class="math-subtitle">Please solve the following problem to continue</div>
      <div class="math-question">%s = ?</div>
      <input type="text" name="answer" class="math-input" placeholder="?" autocomplete="off" autofocus required>
      <button type="submit" class="math-submit">Verify</button>
      <div class="math-note">This challenge helps us prevent automated access</div>
    </div>
  </form>
</body>
</html>`, redirect, csrf, question)
}

func (e *Engine) svgTextPage(path, redirect, csrf string) string {
	// Generate deterministic CAPTCHA text from path
	rng := rand.New(rand.NewSource(pathSeed(path)))
	chars := "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	length := 5 + rng.Intn(2) // 5-6 chars
	text := make([]byte, length)
	for i := range text {
		text[i] = chars[rng.Intn(len(chars))]
	}

	// Build SVG with distorted text and noise
	var svg strings.Builder
	svg.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="240" height="80" viewBox="0 0 240 80">`)
	// Background
	svg.WriteString(`<rect width="240" height="80" fill="#f0f0f0" rx="4"/>`)

	// Noise lines
	for i := 0; i < 8; i++ {
		x1 := rng.Intn(240)
		y1 := rng.Intn(80)
		x2 := rng.Intn(240)
		y2 := rng.Intn(80)
		colors := []string{"#ccc", "#ddd", "#bbb", "#aaa", "#c5c5c5"}
		svg.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="%d"/>`,
			x1, y1, x2, y2, colors[rng.Intn(len(colors))], rng.Intn(2)+1))
	}

	// Noise dots
	for i := 0; i < 40; i++ {
		cx := rng.Intn(240)
		cy := rng.Intn(80)
		r := rng.Intn(3) + 1
		opacity := 0.2 + rng.Float64()*0.4
		svg.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="%d" fill="#888" opacity="%.2f"/>`,
			cx, cy, r, opacity))
	}

	// Render each character with individual transforms
	charColors := []string{"#2a2a2a", "#3a3a3a", "#1a4a1a", "#2a2a5a", "#4a1a1a", "#333", "#444"}
	for i := 0; i < length; i++ {
		x := 20 + i*36
		y := 45 + rng.Intn(16) - 8
		rot := rng.Intn(30) - 15
		fontSize := 28 + rng.Intn(10)
		color := charColors[rng.Intn(len(charColors))]
		fonts := []string{"serif", "sans-serif", "monospace", "Georgia", "Verdana"}
		font := fonts[rng.Intn(len(fonts))]
		svg.WriteString(fmt.Sprintf(
			`<text x="%d" y="%d" font-size="%d" font-family="%s" fill="%s" transform="rotate(%d %d %d)" font-weight="%d">%c</text>`,
			x, y, fontSize, font, color, rot, x, y, 400+rng.Intn(400), text[i]))
	}

	// More noise lines on top
	for i := 0; i < 4; i++ {
		x1 := rng.Intn(240)
		y1 := rng.Intn(80)
		x2 := rng.Intn(240)
		y2 := rng.Intn(80)
		svg.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#999" stroke-width="1" opacity="0.5"/>`,
			x1, y1, x2, y2))
	}

	// Wavy distortion path
	svg.WriteString(fmt.Sprintf(`<path d="M0 %d Q60 %d 120 %d T240 %d" stroke="#bbb" stroke-width="1" fill="none" opacity="0.6"/>`,
		30+rng.Intn(20), 20+rng.Intn(40), 25+rng.Intn(30), 30+rng.Intn(20)))

	svg.WriteString(`</svg>`)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CAPTCHA Verification</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: "Segoe UI", Roboto, Arial, sans-serif; background: #eef1f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .captcha-container { background: #fff; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.1); padding: 32px; width: 360px; text-align: center; }
    .captcha-title { font-size: 18px; color: #333; margin-bottom: 6px; font-weight: 600; }
    .captcha-subtitle { font-size: 12px; color: #888; margin-bottom: 20px; }
    .captcha-image { margin: 0 auto 16px; display: flex; justify-content: center; background: #f8f8f8; border: 1px solid #e0e0e0; border-radius: 6px; padding: 8px; }
    .captcha-image svg { display: block; }
    .captcha-refresh { display: inline-block; font-size: 12px; color: #4a90d9; cursor: pointer; margin-bottom: 16px; text-decoration: none; }
    .captcha-refresh:hover { text-decoration: underline; }
    .captcha-input { width: 180px; padding: 10px; font-size: 18px; text-align: center; border: 2px solid #ddd; border-radius: 6px; outline: none; letter-spacing: 6px; font-family: monospace; }
    .captcha-input:focus { border-color: #4a90d9; box-shadow: 0 0 0 3px rgba(74,144,217,0.15); }
    .captcha-submit { display: block; width: 100%%; margin-top: 16px; padding: 11px; background: #4a90d9; color: #fff; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; }
    .captcha-submit:hover { background: #357abd; }
    .captcha-note { font-size: 11px; color: #aaa; margin-top: 14px; line-height: 1.4; }
  </style>
</head>
<body>
  <form method="POST" action="/captcha/verify">
    <input type="hidden" name="redirect" value="%s">
    <input type="hidden" name="csrf_token" value="%s">
    <input type="hidden" name="challenge_type" value="svg_text">
    <div class="captcha-container">
      <div class="captcha-title">Enter the characters you see</div>
      <div class="captcha-subtitle">This helps us verify you are not a robot</div>
      <div class="captcha-image">
        %s
      </div>
      <a class="captcha-refresh" href="javascript:void(0)">&#8635; Try different characters</a>
      <br>
      <input type="text" name="captcha_text" class="captcha-input" placeholder="..." autocomplete="off" maxlength="8" autofocus required>
      <button type="submit" class="captcha-submit">Submit</button>
      <div class="captcha-note">Characters are case-sensitive. If you cannot read the image, click the refresh link above.</div>
    </div>
  </form>
</body>
</html>`, redirect, csrf, svg.String())
}
