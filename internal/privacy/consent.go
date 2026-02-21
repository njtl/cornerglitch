package privacy

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Handler emulates GDPR/CCPA cookie consent banners and privacy policy endpoints.
type Handler struct{}

// NewHandler creates a new privacy consent handler.
func NewHandler() *Handler {
	return &Handler{}
}

// ShouldHandle returns true for privacy-related endpoints.
func (h *Handler) ShouldHandle(path string) bool {
	switch path {
	case "/privacy-policy", "/terms-of-service", "/cookie-policy",
		"/.well-known/gpc",
		"/consent/preferences", "/consent/accept", "/consent/reject":
		return true
	}
	return false
}

// ServeHTTP dispatches privacy/consent requests and returns the HTTP status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	// Do Not Track support
	if r.Header.Get("DNT") == "1" {
		w.Header().Set("Tk", "N")
	}

	path := r.URL.Path

	switch {
	case path == "/privacy-policy":
		return h.servePrivacyPolicy(w, r)
	case path == "/terms-of-service":
		return h.serveTermsOfService(w, r)
	case path == "/cookie-policy":
		return h.serveCookiePolicy(w, r)
	case path == "/.well-known/gpc":
		return h.serveGPC(w, r)
	case path == "/consent/preferences" && r.Method == http.MethodGet:
		return h.servePreferencesPage(w, r)
	case path == "/consent/preferences" && r.Method == http.MethodPost:
		return h.processPreferences(w, r)
	case path == "/consent/accept" && r.Method == http.MethodPost:
		return h.acceptAll(w, r)
	case path == "/consent/reject" && r.Method == http.MethodPost:
		return h.rejectAll(w, r)
	}

	http.NotFound(w, r)
	return http.StatusNotFound
}

// ConsentBanner returns an HTML/JS snippet for a cookie consent banner in the given style.
// Valid styles: "onetrust", "cookiebot", "minimal".
func (h *Handler) ConsentBanner(style string) string {
	switch style {
	case "onetrust":
		return consentBannerOneTrust()
	case "cookiebot":
		return consentBannerCookieBot()
	case "minimal":
		return consentBannerMinimal()
	default:
		return consentBannerOneTrust()
	}
}

// ConsentSnippet returns a randomly-selected default consent banner snippet.
func (h *Handler) ConsentSnippet() string {
	styles := []string{"onetrust", "cookiebot", "minimal"}
	return h.ConsentBanner(styles[rand.Intn(len(styles))])
}

// ---------------------------------------------------------------------------
// Consent banner generators
// ---------------------------------------------------------------------------

func consentBannerOneTrust() string {
	return `<div id="onetrust-consent-sdk" style="position:fixed;bottom:0;left:0;right:0;background:#212529;color:#f8f9fa;padding:18px 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;z-index:999999;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;box-shadow:0 -2px 10px rgba(0,0,0,0.3);">
  <div style="flex:1;min-width:300px;margin-right:20px;">
    <p style="margin:0 0 4px 0;font-weight:600;">We value your privacy</p>
    <p style="margin:0;opacity:0.85;line-height:1.5;">We use cookies and similar technologies to enhance your browsing experience, serve personalized content and ads, and analyze our traffic. By clicking "Accept All", you consent to our use of cookies. Read our <a href="/cookie-policy" style="color:#6ea8fe;text-decoration:underline;">Cookie Policy</a> and <a href="/privacy-policy" style="color:#6ea8fe;text-decoration:underline;">Privacy Policy</a>.</p>
  </div>
  <div style="display:flex;gap:10px;margin-top:8px;">
    <button onclick="__otRejectAll()" style="padding:10px 20px;background:transparent;color:#f8f9fa;border:1px solid #6c757d;border-radius:4px;cursor:pointer;font-size:14px;">Reject All</button>
    <button onclick="window.location.href='/consent/preferences'" style="padding:10px 20px;background:transparent;color:#f8f9fa;border:1px solid #6c757d;border-radius:4px;cursor:pointer;font-size:14px;">Customize</button>
    <button onclick="__otAcceptAll()" style="padding:10px 20px;background:#0d6efd;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;font-weight:600;">Accept All</button>
  </div>
</div>
<script>
(function(){
  if(document.cookie.indexOf('CookieConsent=')!==-1){
    var el=document.getElementById('onetrust-consent-sdk');
    if(el)el.style.display='none';
  }
})();
function __otAcceptAll(){
  fetch('/consent/accept',{method:'POST',credentials:'same-origin'}).then(function(){
    var el=document.getElementById('onetrust-consent-sdk');
    if(el)el.style.display='none';
    location.reload();
  });
}
function __otRejectAll(){
  fetch('/consent/reject',{method:'POST',credentials:'same-origin'}).then(function(){
    var el=document.getElementById('onetrust-consent-sdk');
    if(el)el.style.display='none';
    location.reload();
  });
}
</script>`
}

func consentBannerCookieBot() string {
	return `<div id="CybotCookiebotDialog" style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#fff;color:#333;width:520px;max-width:90vw;border-radius:8px;box-shadow:0 4px 30px rgba(0,0,0,0.35);z-index:999999;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;overflow:hidden;">
  <div id="CybotCookiebotDialogOverlay" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999998;" onclick=""></div>
  <div style="position:relative;z-index:999999;background:#fff;border-radius:8px;">
    <div style="display:flex;border-bottom:1px solid #e0e0e0;">
      <button class="cb-tab cb-tab-active" onclick="__cbShowTab('consent')" style="flex:1;padding:14px;background:#fff;border:none;border-bottom:3px solid #0066cc;font-weight:600;cursor:pointer;font-size:13px;">Consent</button>
      <button class="cb-tab" onclick="__cbShowTab('details')" style="flex:1;padding:14px;background:#f5f5f5;border:none;border-bottom:3px solid transparent;cursor:pointer;font-size:13px;">Details</button>
      <button class="cb-tab" onclick="__cbShowTab('about')" style="flex:1;padding:14px;background:#f5f5f5;border:none;border-bottom:3px solid transparent;cursor:pointer;font-size:13px;">About</button>
    </div>
    <div id="cb-tab-consent" style="padding:20px;">
      <p style="margin:0 0 12px 0;font-weight:600;font-size:16px;">This website uses cookies</p>
      <p style="margin:0 0 16px 0;line-height:1.6;color:#555;">We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media, advertising and analytics partners.</p>
      <div style="margin-bottom:12px;">
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><input type="checkbox" checked disabled> <strong>Necessary</strong> <span style="color:#888;font-size:12px;">(Always active)</span></label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><input type="checkbox" id="cb-analytics" checked> <strong>Analytics</strong></label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><input type="checkbox" id="cb-marketing" checked> <strong>Marketing</strong></label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><input type="checkbox" id="cb-preferences" checked> <strong>Preferences</strong></label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><input type="checkbox" id="cb-social" checked> <strong>Social Media</strong></label>
      </div>
    </div>
    <div id="cb-tab-details" style="padding:20px;display:none;">
      <p style="margin:0 0 10px 0;font-weight:600;">Cookie Details</p>
      <p style="margin:0;line-height:1.6;color:#555;font-size:13px;">Necessary cookies help make a website usable by enabling basic functions. The website cannot function properly without these cookies.<br><br>Analytics cookies help website owners understand how visitors interact with websites by collecting and reporting information anonymously.<br><br>Marketing cookies are used to track visitors across websites to display relevant advertisements.<br><br>Preference cookies enable a website to remember information that changes the way the website behaves or looks.<br><br>Social media cookies are set by social media services to enable sharing and engagement.</p>
    </div>
    <div id="cb-tab-about" style="padding:20px;display:none;">
      <p style="margin:0 0 10px 0;font-weight:600;">About Cookies</p>
      <p style="margin:0;line-height:1.6;color:#555;font-size:13px;">Cookies are small text files that can be used by websites to make a user's experience more efficient. The law states that we can store cookies on your device if they are strictly necessary for the operation of this site. For all other types of cookies we need your permission. This site uses different types of cookies. Some cookies are placed by third party services that appear on our pages. Learn more in our <a href="/privacy-policy" style="color:#0066cc;">Privacy Policy</a>.</p>
    </div>
    <div style="padding:12px 20px;display:flex;gap:10px;border-top:1px solid #e0e0e0;background:#fafafa;">
      <button onclick="__cbDecline()" style="flex:1;padding:10px;background:#fff;color:#333;border:1px solid #ccc;border-radius:4px;cursor:pointer;font-size:13px;">Decline</button>
      <button onclick="__cbAcceptSelected()" style="flex:1;padding:10px;background:#5c9e31;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px;">Accept Selected</button>
      <button onclick="__cbAcceptAll()" style="flex:1;padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600;">Accept All</button>
    </div>
  </div>
</div>
<script>
(function(){
  if(document.cookie.indexOf('CookieConsent=')!==-1){
    var el=document.getElementById('CybotCookiebotDialog');
    var ov=document.getElementById('CybotCookiebotDialogOverlay');
    if(el)el.style.display='none';
    if(ov)ov.style.display='none';
  }
})();
function __cbShowTab(name){
  ['consent','details','about'].forEach(function(t){
    var el=document.getElementById('cb-tab-'+t);
    if(el)el.style.display=t===name?'block':'none';
  });
}
function __cbAcceptAll(){
  fetch('/consent/accept',{method:'POST',credentials:'same-origin'}).then(function(){
    var el=document.getElementById('CybotCookiebotDialog');
    var ov=document.getElementById('CybotCookiebotDialogOverlay');
    if(el)el.style.display='none';
    if(ov)ov.style.display='none';
    location.reload();
  });
}
function __cbDecline(){
  fetch('/consent/reject',{method:'POST',credentials:'same-origin'}).then(function(){
    var el=document.getElementById('CybotCookiebotDialog');
    var ov=document.getElementById('CybotCookiebotDialogOverlay');
    if(el)el.style.display='none';
    if(ov)ov.style.display='none';
    location.reload();
  });
}
function __cbAcceptSelected(){
  var data=new URLSearchParams();
  data.append('necessary','true');
  data.append('analytics',document.getElementById('cb-analytics').checked?'true':'false');
  data.append('marketing',document.getElementById('cb-marketing').checked?'true':'false');
  data.append('preferences',document.getElementById('cb-preferences').checked?'true':'false');
  data.append('social_media',document.getElementById('cb-social').checked?'true':'false');
  fetch('/consent/preferences',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:data.toString()}).then(function(){
    var el=document.getElementById('CybotCookiebotDialog');
    var ov=document.getElementById('CybotCookiebotDialogOverlay');
    if(el)el.style.display='none';
    if(ov)ov.style.display='none';
    location.reload();
  });
}
</script>`
}

func consentBannerMinimal() string {
	return `<div id="cookie-notice-minimal" style="position:fixed;bottom:20px;left:20px;background:#fff;color:#333;padding:16px 20px;border-radius:8px;box-shadow:0 2px 16px rgba(0,0,0,0.15);z-index:999999;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;max-width:340px;line-height:1.5;">
  <p style="margin:0 0 10px 0;">We use cookies to improve your experience. By continuing to browse, you agree to our <a href="/cookie-policy" style="color:#0066cc;text-decoration:underline;">cookie policy</a>.</p>
  <div style="display:flex;gap:8px;align-items:center;">
    <button onclick="__mnAccept()" style="padding:6px 16px;background:#333;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px;">Accept</button>
    <a href="/consent/preferences" style="color:#666;font-size:12px;text-decoration:underline;">Settings</a>
  </div>
</div>
<script>
(function(){
  if(document.cookie.indexOf('CookieConsent=')!==-1){
    var el=document.getElementById('cookie-notice-minimal');
    if(el)el.style.display='none';
  }
})();
function __mnAccept(){
  fetch('/consent/accept',{method:'POST',credentials:'same-origin'}).then(function(){
    var el=document.getElementById('cookie-notice-minimal');
    if(el)el.style.display='none';
  });
}
</script>`
}

// ---------------------------------------------------------------------------
// Consent cookie helpers
// ---------------------------------------------------------------------------

func setConsentCookies(w http.ResponseWriter, analytics, marketing, preferences bool) {
	consent := map[string]bool{
		"necessary":   true,
		"analytics":   analytics,
		"marketing":   marketing,
		"preferences": preferences,
	}
	consentJSON, _ := json.Marshal(consent)

	gdprValue := "necessary_only"
	if analytics && marketing && preferences {
		gdprValue = "accepted"
	}

	maxAge := 31536000 // 1 year

	http.SetCookie(w, &http.Cookie{
		Name:     "__consent",
		Value:    string(consentJSON),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "_gdpr_consent",
		Value:    gdprValue,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "CookieConsent",
		Value:    "true",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// ---------------------------------------------------------------------------
// Endpoint handlers
// ---------------------------------------------------------------------------

func (h *Handler) acceptAll(w http.ResponseWriter, r *http.Request) int {
	setConsentCookies(w, true, true, true)
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
	return http.StatusSeeOther
}

func (h *Handler) rejectAll(w http.ResponseWriter, r *http.Request) int {
	setConsentCookies(w, false, false, false)
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
	return http.StatusSeeOther
}

func (h *Handler) processPreferences(w http.ResponseWriter, r *http.Request) int {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	analytics := r.FormValue("analytics") == "true"
	marketing := r.FormValue("marketing") == "true"
	preferences := r.FormValue("preferences") == "true"

	setConsentCookies(w, analytics, marketing, preferences)

	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
	return http.StatusSeeOther
}

func (h *Handler) serveGPC(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]interface{}{
		"gpc":        true,
		"lastUpdate": "2025-01-01",
	}
	json.NewEncoder(w).Encode(resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Preference center page
// ---------------------------------------------------------------------------

func (h *Handler) servePreferencesPage(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, preferencesPageHTML())
	return http.StatusOK
}

func preferencesPageHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cookie Preferences - GlitchApp Inc.</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f5f7;color:#333;line-height:1.6;}
  .container{max-width:680px;margin:40px auto;padding:0 20px;}
  h1{font-size:28px;margin-bottom:8px;color:#1a1a1a;}
  .subtitle{color:#666;margin-bottom:32px;font-size:15px;}
  .card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.08);padding:24px;margin-bottom:16px;}
  .card h2{font-size:18px;margin-bottom:4px;}
  .card p{font-size:14px;color:#555;margin-bottom:12px;}
  .toggle-row{display:flex;justify-content:space-between;align-items:center;}
  .toggle{position:relative;width:48px;height:26px;}
  .toggle input{opacity:0;width:0;height:0;}
  .slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#ccc;border-radius:26px;transition:.3s;}
  .slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.3s;}
  input:checked+.slider{background:#0d6efd;}
  input:checked+.slider:before{transform:translateX(22px);}
  input:disabled+.slider{background:#0d6efd;opacity:0.6;cursor:default;}
  .actions{display:flex;gap:12px;margin-top:24px;}
  .btn{padding:12px 24px;border:none;border-radius:6px;font-size:15px;cursor:pointer;font-weight:500;}
  .btn-primary{background:#0d6efd;color:#fff;}
  .btn-success{background:#198754;color:#fff;}
  .btn-outline{background:#fff;color:#333;border:1px solid #ccc;}
</style>
</head>
<body>
<div class="container">
  <h1>Cookie Preferences</h1>
  <p class="subtitle">Manage your cookie consent preferences. Necessary cookies cannot be disabled as they are required for the site to function.</p>
  <form method="POST" action="/consent/preferences">

  <div class="card">
    <div class="toggle-row">
      <div>
        <h2>Necessary Cookies</h2>
        <p>Essential for the website to function. These cookies ensure basic functionalities and security features.</p>
      </div>
      <label class="toggle"><input type="checkbox" name="necessary" value="true" checked disabled><span class="slider"></span></label>
    </div>
  </div>

  <div class="card">
    <div class="toggle-row">
      <div>
        <h2>Analytics Cookies</h2>
        <p>Help us understand how visitors interact with our website by collecting and reporting information anonymously.</p>
      </div>
      <label class="toggle"><input type="checkbox" name="analytics" value="true" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="card">
    <div class="toggle-row">
      <div>
        <h2>Marketing Cookies</h2>
        <p>Used to track visitors across websites to display relevant and engaging advertisements.</p>
      </div>
      <label class="toggle"><input type="checkbox" name="marketing" value="true" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="card">
    <div class="toggle-row">
      <div>
        <h2>Preference Cookies</h2>
        <p>Allow the website to remember choices you make such as language, region, and other customizations.</p>
      </div>
      <label class="toggle"><input type="checkbox" name="preferences" value="true" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="card">
    <div class="toggle-row">
      <div>
        <h2>Social Media Cookies</h2>
        <p>Enable sharing content through social media platforms and may track your browsing activity.</p>
      </div>
      <label class="toggle"><input type="checkbox" name="social_media" value="true" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="actions">
    <button type="submit" class="btn btn-primary">Save Preferences</button>
    <button type="button" class="btn btn-success" onclick="acceptAll()">Accept All</button>
    <button type="button" class="btn btn-outline" onclick="rejectAll()">Reject All</button>
  </div>

  </form>
</div>
<script>
function acceptAll(){
  fetch('/consent/accept',{method:'POST',credentials:'same-origin'}).then(function(){window.location.href='/';});
}
function rejectAll(){
  fetch('/consent/reject',{method:'POST',credentials:'same-origin'}).then(function(){window.location.href='/';});
}
</script>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// Privacy policy
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyPolicy(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, privacyPolicyHTML())
	return http.StatusOK
}

func privacyPolicyHTML() string {
	updated := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC).Format("January 2, 2006")
	effective := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC).Format("January 2, 2006")

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy - GlitchApp Inc.</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:Georgia,'Times New Roman',serif;background:#fff;color:#333;line-height:1.8;padding:40px 20px;}
  .container{max-width:800px;margin:0 auto;}
  h1{font-size:32px;margin-bottom:6px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  h2{font-size:22px;margin-top:36px;margin-bottom:12px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border-bottom:1px solid #e0e0e0;padding-bottom:6px;}
  h3{font-size:17px;margin-top:20px;margin-bottom:8px;color:#333;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  p{margin-bottom:14px;font-size:15px;}
  ul,ol{margin:0 0 14px 28px;font-size:15px;}
  li{margin-bottom:6px;}
  .meta{color:#888;font-size:14px;margin-bottom:32px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  a{color:#0066cc;}
  .toc{background:#f8f9fa;padding:20px 28px;border-radius:6px;margin-bottom:32px;}
  .toc ol{margin-bottom:0;}
  .toc li{margin-bottom:4px;font-size:14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  .toc a{text-decoration:none;}
</style>
</head>
<body>
<div class="container">
<h1>Privacy Policy</h1>
`)
	sb.WriteString(fmt.Sprintf(`<p class="meta">Last updated: %s | Effective date: %s</p>`, updated, effective))
	sb.WriteString(`
<div class="toc">
<p style="font-weight:600;margin-bottom:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">Table of Contents</p>
<ol>
  <li><a href="#introduction">Introduction</a></li>
  <li><a href="#information-we-collect">Information We Collect</a></li>
  <li><a href="#how-we-use">How We Use Your Information</a></li>
  <li><a href="#legal-basis">Legal Basis for Processing (GDPR)</a></li>
  <li><a href="#data-retention">Data Retention</a></li>
  <li><a href="#your-rights">Your Rights (GDPR)</a></li>
  <li><a href="#california-privacy">California Privacy Rights (CCPA)</a></li>
  <li><a href="#international-transfers">International Transfers</a></li>
  <li><a href="#data-security">Data Security</a></li>
  <li><a href="#children">Children's Privacy</a></li>
  <li><a href="#changes">Changes to This Policy</a></li>
  <li><a href="#contact">Contact Information</a></li>
</ol>
</div>

<h2 id="introduction">1. Introduction</h2>
<p>GlitchApp Inc. ("GlitchApp," "we," "us," or "our") is committed to protecting the privacy and security of your personal information. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you visit our website, use our services, or interact with us in any way.</p>
<p>This Privacy Policy applies to all information collected through our website (the "Site"), our applications, and any related services, sales, marketing, or events (collectively, the "Services"). By accessing or using our Services, you acknowledge that you have read, understood, and agree to be bound by this Privacy Policy. If you do not agree with the terms of this Privacy Policy, please do not access the Site or use our Services.</p>
<p>We may update this Privacy Policy from time to time in order to reflect changes to our practices or for other operational, legal, or regulatory reasons. We encourage you to review this Privacy Policy periodically to stay informed about how we are protecting your information. Your continued use of the Services after any modifications to this Privacy Policy will constitute your acknowledgment of the modifications and your consent to abide and be bound by the updated Privacy Policy.</p>
<p>This policy has been drafted in compliance with the European Union General Data Protection Regulation (GDPR), the California Consumer Privacy Act (CCPA) as amended by the California Privacy Rights Act (CPRA), the Virginia Consumer Data Protection Act (VCDPA), the Colorado Privacy Act (CPA), the Connecticut Data Privacy Act (CTDPA), and other applicable data protection laws.</p>

<h2 id="information-we-collect">2. Information We Collect</h2>

<h3>2.1 Personal Data</h3>
<p>We may collect personal information that you voluntarily provide to us when you register on the Site, express an interest in obtaining information about us or our products and services, participate in activities on the Site, or otherwise contact us. The personal information we collect may include:</p>
<ul>
  <li>Name, email address, and contact information</li>
  <li>Mailing address and telephone number</li>
  <li>Username and password for account creation</li>
  <li>Billing information and payment card details (processed through secure third-party payment processors)</li>
  <li>Professional or employment-related information</li>
  <li>Any other information you choose to provide, such as profile photos, biographical details, or preferences</li>
</ul>

<h3>2.2 Usage Data</h3>
<p>We automatically collect certain information when you visit, use, or navigate the Site. This information does not reveal your specific identity (like your name or contact information) but may include:</p>
<ul>
  <li>Device and browser information, including IP address, browser type and version, operating system, device type, and screen resolution</li>
  <li>Usage patterns, including pages visited, time spent on pages, links clicked, and navigation paths</li>
  <li>Referral source, including the URL of the website that directed you to our Site</li>
  <li>Date and time stamps of access, including session duration and frequency of visits</li>
  <li>Geographic location data derived from IP addresses (city/country level only)</li>
  <li>Performance data such as page load times and error reports</li>
</ul>

<h3>2.3 Cookies and Tracking Technologies</h3>
<p>We use cookies, web beacons, tracking pixels, and similar technologies to collect information about your browsing activities. Cookies are small data files placed on your device that help us improve our Site, provide a better user experience, and understand which areas and features are popular. The types of cookies we use include:</p>
<ul>
  <li><strong>Strictly Necessary Cookies:</strong> Required for the operation of our Site. They include, for example, cookies that enable you to log into secure areas of our Site and use session management features.</li>
  <li><strong>Analytical/Performance Cookies:</strong> Allow us to recognise and count the number of visitors and to see how visitors move around our Site. This helps us improve the way our Site works by ensuring that users find what they are looking for easily.</li>
  <li><strong>Functionality Cookies:</strong> Used to recognise you when you return to our Site. This enables us to personalise our content for you, greet you by name, and remember your preferences (for example, your choice of language or region).</li>
  <li><strong>Targeting Cookies:</strong> Record your visit to our Site, the pages you have visited, and the links you have followed. We will use this information to make our Site and the advertising displayed on it more relevant to your interests.</li>
</ul>
<p>You can set your browser to refuse all or some browser cookies, or to alert you when websites set or access cookies. If you disable or refuse cookies, please note that some parts of this Site may become inaccessible or not function properly. For more information about the cookies we use, please see our <a href="/cookie-policy">Cookie Policy</a>.</p>

<h2 id="how-we-use">3. How We Use Your Information</h2>
<p>We use the information we collect or receive for the following purposes:</p>
<ul>
  <li><strong>To provide and maintain our Services:</strong> Including to monitor the usage of our Services, detect, prevent, and address technical issues, and ensure the security and integrity of our platform.</li>
  <li><strong>To manage your account:</strong> To manage your registration as a user of the Services. The personal data you provide can give you access to different functionalities of the Services that are available to you as a registered user.</li>
  <li><strong>To contact you:</strong> To contact you by email, telephone calls, SMS, push notifications, or other equivalent forms of electronic communication regarding updates or informative communications related to the functionalities, products, or contracted services.</li>
  <li><strong>To provide you with news, special offers, and general information:</strong> About other goods, services, and events which we offer that are similar to those that you have already purchased or enquired about, unless you have opted not to receive such information.</li>
  <li><strong>To manage your requests:</strong> To attend and manage your requests and inquiries to us, including customer support interactions.</li>
  <li><strong>For business transfers:</strong> We may use your information to evaluate or conduct a merger, divestiture, restructuring, reorganization, dissolution, or other sale or transfer of some or all of our assets.</li>
  <li><strong>For analytics and research:</strong> To understand how our Services are used, identify trends, and improve our offerings. We may use aggregated and de-identified data for research, statistical analysis, and business intelligence purposes.</li>
  <li><strong>For compliance and legal obligations:</strong> To comply with applicable laws, regulations, legal processes, or enforceable governmental requests, and to protect our rights, privacy, safety, or property.</li>
  <li><strong>To enforce our terms, conditions, and policies:</strong> For business purposes, to verify accounts and activity, combat harmful or unauthorized conduct, and ensure compliance with our terms.</li>
</ul>

<h2 id="legal-basis">4. Legal Basis for Processing (GDPR)</h2>
<p>If you are located in the European Economic Area (EEA), the United Kingdom (UK), or Switzerland, we process your personal data under the following legal bases as defined by the General Data Protection Regulation:</p>
<ul>
  <li><strong>Consent (Article 6(1)(a)):</strong> You have given your consent for the processing of your personal data for one or more specific purposes, such as receiving marketing communications or allowing non-essential cookies.</li>
  <li><strong>Performance of a Contract (Article 6(1)(b)):</strong> Processing is necessary for the performance of a contract to which you are a party or in order to take steps at your request prior to entering into a contract.</li>
  <li><strong>Legal Obligation (Article 6(1)(c)):</strong> Processing is necessary for compliance with a legal obligation to which we are subject, such as tax reporting, fraud prevention, or responding to lawful requests from public authorities.</li>
  <li><strong>Legitimate Interests (Article 6(1)(f)):</strong> Processing is necessary for the purposes of the legitimate interests pursued by us or a third party, except where such interests are overridden by your fundamental rights and freedoms. Our legitimate interests include improving our Services, ensuring network and information security, preventing fraud, and direct marketing.</li>
</ul>
<p>Where we rely on consent as the legal basis for processing, you have the right to withdraw your consent at any time. This will not affect the lawfulness of processing based on consent before its withdrawal. To withdraw consent, you may use the cookie preference settings available on our Site or contact us using the details provided below.</p>

<h2 id="data-retention">5. Data Retention</h2>
<p>We will retain your personal data only for as long as is necessary for the purposes set out in this Privacy Policy. We will retain and use your personal data to the extent necessary to comply with our legal obligations (for example, if we are required to retain your data to comply with applicable laws), resolve disputes, and enforce our legal agreements and policies.</p>
<p>We will also retain usage data for internal analysis purposes. Usage data is generally retained for a shorter period of time, except when this data is used to strengthen the security or to improve the functionality of our Services, or we are legally obligated to retain this data for longer time periods. Typically, usage data is retained for up to 26 months.</p>
<p>When your personal data is no longer necessary for the purposes for which it was collected, we will securely delete or anonymize it. If deletion is not possible (for example, because your personal data has been stored in backup archives), we will securely store your personal data and isolate it from any further processing until deletion is possible.</p>

<h2 id="your-rights">6. Your Rights (GDPR)</h2>
<p>If you are a resident of the European Economic Area, the United Kingdom, or Switzerland, you have the following data protection rights under the GDPR. We aim to take reasonable steps to allow you to correct, amend, delete, or limit the use of your personal data:</p>
<ul>
  <li><strong>Right of Access (Article 15):</strong> You have the right to request copies of your personal data. We may charge a small fee for this service in certain circumstances.</li>
  <li><strong>Right to Rectification (Article 16):</strong> You have the right to request that we correct any information you believe is inaccurate. You also have the right to request that we complete information you believe is incomplete.</li>
  <li><strong>Right to Erasure (Article 17):</strong> You have the right to request that we erase your personal data, under certain conditions. This right is not absolute and applies only in certain circumstances, such as when the data is no longer necessary for the purpose it was collected.</li>
  <li><strong>Right to Restrict Processing (Article 18):</strong> You have the right to request that we restrict the processing of your personal data, under certain conditions, such as when you contest the accuracy of the data or when the processing is unlawful.</li>
  <li><strong>Right to Data Portability (Article 20):</strong> You have the right to request that we transfer the data that we have collected to another organization, or directly to you, under certain conditions and in a structured, commonly used, and machine-readable format.</li>
  <li><strong>Right to Object (Article 21):</strong> You have the right to object to our processing of your personal data, under certain conditions, including processing for direct marketing purposes and processing based on legitimate interests.</li>
  <li><strong>Right to Withdraw Consent:</strong> Where we rely on consent as the legal basis for processing, you have the right to withdraw your consent at any time without affecting the lawfulness of processing based on consent before its withdrawal.</li>
  <li><strong>Right to Lodge a Complaint:</strong> You have the right to lodge a complaint with a supervisory authority, in particular in the EU Member State of your habitual residence, place of work, or place of the alleged infringement, if you consider that the processing of personal data relating to you infringes the GDPR.</li>
</ul>
<p>To exercise any of these rights, please contact us using the information provided in the Contact Information section below. We will respond to your request within 30 days, as required by applicable law. We may need to verify your identity before processing your request.</p>

<h2 id="california-privacy">7. California Privacy Rights (CCPA)</h2>
<p>If you are a California resident, the California Consumer Privacy Act (CCPA), as amended by the California Privacy Rights Act (CPRA), grants you specific rights regarding your personal information. This section describes your CCPA rights and explains how to exercise those rights.</p>
<p>Under the CCPA, California consumers have the following rights:</p>
<ul>
  <li><strong>Right to Know:</strong> You have the right to request that we disclose the categories and specific pieces of personal information we have collected about you, the categories of sources from which personal information is collected, our business or commercial purpose for collecting or selling personal information, and the categories of third parties with whom we share personal information.</li>
  <li><strong>Right to Delete:</strong> You have the right to request the deletion of personal information we have collected from you, subject to certain exceptions provided by law.</li>
  <li><strong>Right to Correct:</strong> You have the right to request the correction of inaccurate personal information that we maintain about you.</li>
  <li><strong>Right to Opt-Out of Sale or Sharing:</strong> You have the right to opt out of the sale or sharing of your personal information for cross-context behavioral advertising purposes. We do not sell your personal information in the traditional sense. However, certain uses of cookies and tracking technologies may constitute "sharing" under the CCPA.</li>
  <li><strong>Right to Limit Use of Sensitive Personal Information:</strong> If we collect sensitive personal information, you have the right to limit our use and disclosure of that information to what is necessary.</li>
  <li><strong>Right to Non-Discrimination:</strong> You have the right not to receive discriminatory treatment for exercising any of your CCPA rights. We will not deny you goods or services, charge you different prices, or provide a different level of quality because you exercised your rights.</li>
</ul>
<p>In the preceding 12 months, we have collected the following categories of personal information: identifiers (name, email, IP address), internet or electronic network activity information, geolocation data, and inferences drawn from the above. We do not knowingly sell the personal information of consumers under 16 years of age.</p>
<p>To exercise your rights, you may submit a verifiable consumer request by contacting us at the information provided below. You may also designate an authorized agent to make a request on your behalf. We will verify your identity before processing any request, which may require you to provide additional information.</p>

<h2 id="international-transfers">8. International Transfers</h2>
<p>Your information, including personal data, may be transferred to and maintained on computers located outside of your state, province, country, or other governmental jurisdiction where the data protection laws may differ from those of your jurisdiction.</p>
<p>If you are located outside the United States and choose to provide information to us, please note that we transfer the data, including personal data, to the United States and process it there. Your consent to this Privacy Policy followed by your submission of such information represents your agreement to that transfer.</p>
<p>When transferring data from the EEA, UK, or Switzerland to the United States or other countries not deemed to provide an adequate level of data protection, we rely on appropriate safeguards, including:</p>
<ul>
  <li>Standard Contractual Clauses (SCCs) approved by the European Commission</li>
  <li>The UK International Data Transfer Agreement or Addendum, as applicable</li>
  <li>Adequacy decisions of the European Commission, where available</li>
  <li>The EU-U.S. Data Privacy Framework, the UK Extension to the EU-U.S. DPF, and the Swiss-U.S. Data Privacy Framework</li>
  <li>Binding Corporate Rules, where applicable</li>
</ul>
<p>We will take all steps reasonably necessary to ensure that your data is treated securely and in accordance with this Privacy Policy and no transfer of your personal data will take place to an organization or a country unless there are adequate controls in place including the security of your data and other personal information.</p>

<h2 id="data-security">9. Data Security</h2>
<p>The security of your personal data is important to us. We have implemented appropriate technical and organizational security measures designed to protect the security of any personal information we process. These measures include, but are not limited to:</p>
<ul>
  <li>Encryption of data in transit using TLS 1.2 or higher</li>
  <li>Encryption of data at rest using AES-256 encryption</li>
  <li>Regular security assessments and penetration testing</li>
  <li>Access controls and authentication mechanisms, including multi-factor authentication for administrative access</li>
  <li>Regular backups and disaster recovery procedures</li>
  <li>Employee training on data protection and security best practices</li>
  <li>Incident response procedures for security breaches</li>
  <li>Regular review and updates of our security policies and practices</li>
</ul>
<p>However, please be aware that despite our efforts, no method of transmission over the Internet or method of electronic storage is 100% secure. While we strive to use commercially acceptable means to protect your personal data, we cannot guarantee its absolute security. We encourage you to use strong, unique passwords and to be vigilant about phishing attempts and other security threats.</p>
<p>In the event of a data breach that is likely to result in a risk to your rights and freedoms, we will notify the appropriate supervisory authority within 72 hours of becoming aware of the breach, as required by the GDPR. Where the breach is likely to result in a high risk to your rights and freedoms, we will also notify you directly without undue delay.</p>

<h2 id="children">10. Children's Privacy</h2>
<p>Our Services are not intended for use by children under the age of 16 (or the applicable age of consent in your jurisdiction). We do not knowingly collect personally identifiable information from children under 16. If you are a parent or guardian and you are aware that your child has provided us with personal data, please contact us immediately. If we become aware that we have collected personal data from children without verification of parental consent, we take steps to remove that information from our servers promptly.</p>
<p>If we need to rely on consent as a legal basis for processing your information and your country requires consent from a parent, we may require your parent's consent before we collect and use that information. We will comply with the U.S. Children's Online Privacy Protection Act (COPPA) and other applicable legislation regarding the protection of children's personal information.</p>

<h2 id="changes">11. Changes to This Policy</h2>
<p>We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last updated" date at the top of this Privacy Policy. You are advised to review this Privacy Policy periodically for any changes. Changes to this Privacy Policy are effective when they are posted on this page.</p>
<p>If we make material changes to this Privacy Policy, we will notify you either through the email address you have provided us, through a prominent notice on our website, or through other appropriate communication channels. We will obtain your consent to any material changes if and where this is required by applicable data protection laws.</p>
<p>Your continued use of our Services after the posting of changes constitutes your binding acceptance of such changes. If you do not agree to the revised policy, you should discontinue your use of our Services and contact us to request deletion of your data.</p>

<h2 id="contact">12. Contact Information</h2>
<p>If you have any questions about this Privacy Policy, your personal data, or would like to exercise your data protection rights, you may contact us:</p>
<ul>
  <li><strong>Company:</strong> GlitchApp Inc.</li>
  <li><strong>Data Protection Officer:</strong> privacy@glitchapp.io</li>
  <li><strong>Email:</strong> legal@glitchapp.io</li>
  <li><strong>Address:</strong> 1337 Fault Line Drive, Suite 404, San Francisco, CA 94105, United States</li>
  <li><strong>Phone:</strong> +1 (555) 012-3456</li>
</ul>
<p>For EU/EEA residents, you may also contact our EU representative:</p>
<ul>
  <li><strong>EU Representative:</strong> GlitchApp EU Representative Services</li>
  <li><strong>Email:</strong> eu-representative@glitchapp.io</li>
  <li><strong>Address:</strong> Glitchstra&szlig;e 42, 10115 Berlin, Germany</li>
</ul>
<p>You have the right to make a complaint at any time to the relevant supervisory authority for data protection issues in your jurisdiction. We would, however, appreciate the chance to deal with your concerns before you approach the supervisory authority, so please contact us in the first instance.</p>

</div>
</body>
</html>`)
	return sb.String()
}

// ---------------------------------------------------------------------------
// Terms of service
// ---------------------------------------------------------------------------

func (h *Handler) serveTermsOfService(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, termsOfServiceHTML())
	return http.StatusOK
}

func termsOfServiceHTML() string {
	updated := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC).Format("January 2, 2006")
	effective := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC).Format("January 2, 2006")

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service - GlitchApp Inc.</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:Georgia,'Times New Roman',serif;background:#fff;color:#333;line-height:1.8;padding:40px 20px;}
  .container{max-width:800px;margin:0 auto;}
  h1{font-size:32px;margin-bottom:6px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  h2{font-size:22px;margin-top:36px;margin-bottom:12px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border-bottom:1px solid #e0e0e0;padding-bottom:6px;}
  p{margin-bottom:14px;font-size:15px;}
  ul,ol{margin:0 0 14px 28px;font-size:15px;}
  li{margin-bottom:6px;}
  .meta{color:#888;font-size:14px;margin-bottom:32px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  a{color:#0066cc;}
  .toc{background:#f8f9fa;padding:20px 28px;border-radius:6px;margin-bottom:32px;}
  .toc ol{margin-bottom:0;}
  .toc li{margin-bottom:4px;font-size:14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  .toc a{text-decoration:none;}
</style>
</head>
<body>
<div class="container">
<h1>Terms of Service</h1>
`)
	sb.WriteString(fmt.Sprintf(`<p class="meta">Last updated: %s | Effective date: %s</p>`, updated, effective))
	sb.WriteString(`
<div class="toc">
<p style="font-weight:600;margin-bottom:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">Table of Contents</p>
<ol>
  <li><a href="#acceptance">Acceptance of Terms</a></li>
  <li><a href="#description">Description of Service</a></li>
  <li><a href="#accounts">User Accounts</a></li>
  <li><a href="#ip">Intellectual Property</a></li>
  <li><a href="#user-content">User Content</a></li>
  <li><a href="#prohibited">Prohibited Activities</a></li>
  <li><a href="#disclaimer">Disclaimer of Warranties</a></li>
  <li><a href="#limitation">Limitation of Liability</a></li>
  <li><a href="#indemnification">Indemnification</a></li>
  <li><a href="#governing-law">Governing Law</a></li>
  <li><a href="#disputes">Dispute Resolution</a></li>
  <li><a href="#termination">Termination</a></li>
  <li><a href="#contact">Contact Information</a></li>
</ol>
</div>

<h2 id="acceptance">1. Acceptance of Terms</h2>
<p>By accessing or using the services provided by GlitchApp Inc. ("GlitchApp," "Company," "we," "us," or "our"), including our website, applications, APIs, and all associated services (collectively, the "Services"), you agree to be bound by these Terms of Service ("Terms"). These Terms constitute a legally binding agreement between you ("User," "you," or "your") and GlitchApp.</p>
<p>If you are using the Services on behalf of an organization, you represent and warrant that you have the authority to bind that organization to these Terms, and "you" refers to that organization. If you do not agree to these Terms, you must not access or use the Services.</p>
<p>We reserve the right to modify these Terms at any time. We will provide notice of material changes by posting the updated Terms on our website and updating the "Last updated" date. Your continued use of the Services after such modifications constitutes your acceptance of the revised Terms. It is your responsibility to review these Terms periodically.</p>
<p>These Terms apply to all visitors, users, and others who access or use the Services, including without limitation users who are browsers, vendors, customers, merchants, and contributors of content. You must be at least 16 years of age or the age of majority in your jurisdiction, whichever is greater, to use our Services.</p>

<h2 id="description">2. Description of Service</h2>
<p>GlitchApp provides a cloud-based platform for web application testing, monitoring, and reliability engineering. Our Services include, but are not limited to, website performance analysis, error simulation, load testing capabilities, API monitoring, and related developer tools and documentation.</p>
<p>We reserve the right to modify, suspend, or discontinue any aspect of the Services at any time, including the availability of any feature, database, or content, with or without notice. We may also impose limits on certain features and services or restrict your access to parts or all of the Services without notice or liability.</p>
<p>The Services are provided on an "as available" basis. We do not guarantee that the Services will be uninterrupted, timely, secure, or error-free. We make no warranty regarding the quality, accuracy, timeliness, truthfulness, completeness, or reliability of the Services or any content accessed through the Services.</p>

<h2 id="accounts">3. User Accounts</h2>
<p>To access certain features of the Services, you may be required to create a user account. When you create an account, you agree to provide accurate, current, and complete information and to update such information to keep it accurate, current, and complete. You are responsible for safeguarding the password that you use to access the Services and for any activities or actions under your password.</p>
<p>You agree not to disclose your password to any third party. You must notify us immediately upon becoming aware of any breach of security or unauthorized use of your account. You may not use as a username the name of another person or entity or that is not lawfully available for use, a name or trademark that is subject to any rights of another person or entity without appropriate authorization, or a name that is otherwise offensive, vulgar, or obscene.</p>
<p>We reserve the right to refuse registration of, or cancel, usernames at our sole discretion. You are solely responsible for all activity that occurs under your account, whether or not you authorized that activity. You acknowledge that we are not responsible for third-party access to your account that results from theft or misappropriation of your credentials.</p>

<h2 id="ip">4. Intellectual Property</h2>
<p>The Services and their original content (excluding content provided by users), features, and functionality are and will remain the exclusive property of GlitchApp Inc. and its licensors. The Services are protected by copyright, trademark, and other laws of both the United States and foreign countries. Our trademarks and trade dress may not be used in connection with any product or service without the prior written consent of GlitchApp Inc.</p>
<p>All text, graphics, user interfaces, visual interfaces, photographs, trademarks, logos, sounds, music, artwork, computer code, design, structure, selection, coordination, expression, and arrangement of the Services are owned, controlled, or licensed by or to GlitchApp and are protected by trade dress, copyright, patent, and trademark laws, and various other intellectual property rights and unfair competition laws.</p>
<p>You may not copy, reproduce, distribute, transmit, broadcast, display, sell, license, or otherwise exploit any content on our Services for any purposes without our prior written consent or the consent of our licensors. Nothing in these Terms grants you a right or license to use any trademark, design right, or copyright owned or controlled by GlitchApp or any other third party except as expressly provided in these Terms.</p>

<h2 id="user-content">5. User Content</h2>
<p>Our Services may allow you to post, upload, store, share, send, or display text, images, data, code, or other materials ("User Content"). You retain ownership of any intellectual property rights that you hold in that User Content. By posting User Content on or through the Services, you grant us a worldwide, non-exclusive, royalty-free, transferable license to use, reproduce, modify, adapt, publish, translate, create derivative works from, distribute, and display such User Content in connection with operating and providing the Services.</p>
<p>You represent and warrant that: (a) the User Content is yours (you own it) or you have the right to use it and grant us the rights and license as provided in these Terms; (b) the posting of your User Content on or through the Services does not violate the privacy rights, publicity rights, copyrights, contract rights, or any other rights of any person or entity; and (c) your User Content does not contain any viruses, malware, or other harmful code.</p>
<p>We reserve the right to remove any User Content at our sole discretion, for any reason, without notice. We are not responsible or liable to any third party for the content or accuracy of any User Content posted by you or any other user of the Services.</p>

<h2 id="prohibited">6. Prohibited Activities</h2>
<p>You agree not to engage in any of the following prohibited activities in connection with your use of the Services:</p>
<ul>
  <li>Using the Services for any unlawful purpose or in violation of any local, state, national, or international law or regulation</li>
  <li>Attempting to interfere with, compromise the system integrity or security of, or decipher any transmissions to or from the servers running the Services</li>
  <li>Transmitting any worms, viruses, spyware, malware, or any other type of harmful or destructive code</li>
  <li>Using any robot, spider, scraper, or other automated means to access the Services for any purpose without our express written permission</li>
  <li>Impersonating another person or entity, or falsely stating or otherwise misrepresenting your affiliation with a person or entity</li>
  <li>Harvesting or collecting email addresses or other contact information of other users from the Services by electronic or other means</li>
  <li>Interfering with or disrupting the Services or servers or networks connected to the Services, or disobeying any requirements, procedures, policies, or regulations of networks connected to the Services</li>
  <li>Reverse engineering, decompiling, disassembling, or otherwise attempting to discover the source code of the Services or any part thereof</li>
  <li>Using the Services to send unsolicited or unauthorized advertising, promotional materials, junk mail, spam, chain letters, pyramid schemes, or any other form of solicitation</li>
  <li>Engaging in any activity that could disable, overburden, damage, or impair the Services or interfere with any other party's use of the Services</li>
  <li>Using the Services to violate the security of any computer network, crack passwords or security encryption codes, or transfer or store illegal material</li>
  <li>Framing or mirroring any part of the Services without our express prior written consent</li>
</ul>

<h2 id="disclaimer">7. Disclaimer of Warranties</h2>
<p>THE SERVICES ARE PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS, WITHOUT ANY WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, OR COURSE OF PERFORMANCE.</p>
<p>GLITCHAPP INC., ITS SUBSIDIARIES, AFFILIATES, LICENSORS, OFFICERS, DIRECTORS, EMPLOYEES, AGENTS, SUPPLIERS, AND PARTNERS DO NOT WARRANT THAT: (A) THE SERVICES WILL FUNCTION UNINTERRUPTED, SECURELY, OR BE AVAILABLE AT ANY PARTICULAR TIME OR LOCATION; (B) ANY ERRORS OR DEFECTS WILL BE CORRECTED; (C) THE SERVICES ARE FREE OF VIRUSES OR OTHER HARMFUL COMPONENTS; (D) THE RESULTS OF USING THE SERVICES WILL MEET YOUR REQUIREMENTS; OR (E) ANY CONTENT OR DATA YOU ACCESS THROUGH THE SERVICES WILL BE ACCURATE, RELIABLE, OR COMPLETE.</p>
<p>SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OF CERTAIN WARRANTIES, SO SOME OF THE ABOVE LIMITATIONS MAY NOT APPLY TO YOU. IN SUCH CASES, OUR LIABILITY WILL BE LIMITED TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW.</p>

<h2 id="limitation">8. Limitation of Liability</h2>
<p>TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL GLITCHAPP INC., ITS SUBSIDIARIES, AFFILIATES, LICENSORS, OFFICERS, DIRECTORS, EMPLOYEES, AGENTS, SUPPLIERS, OR PARTNERS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE, OR EXEMPLARY DAMAGES, INCLUDING WITHOUT LIMITATION DAMAGES FOR LOSS OF PROFITS, GOODWILL, USE, DATA, OR OTHER INTANGIBLE LOSSES (EVEN IF GLITCHAPP HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES), ARISING OUT OF OR IN CONNECTION WITH:</p>
<ul>
  <li>Your access to or use of or inability to access or use the Services</li>
  <li>Any conduct or content of any third party on the Services</li>
  <li>Any content obtained from the Services</li>
  <li>Unauthorized access, use, or alteration of your transmissions or content</li>
</ul>
<p>IN NO EVENT SHALL OUR TOTAL LIABILITY TO YOU FOR ALL CLAIMS ARISING OUT OF OR RELATING TO THE USE OF OR INABILITY TO USE THE SERVICES EXCEED THE AMOUNT YOU HAVE PAID TO US IN THE TWELVE (12) MONTHS PRIOR TO THE EVENT GIVING RISE TO THE LIABILITY, OR ONE HUNDRED DOLLARS ($100), WHICHEVER IS GREATER.</p>
<p>THE LIMITATIONS OF THIS SECTION SHALL APPLY TO ANY THEORY OF LIABILITY, WHETHER BASED ON WARRANTY, CONTRACT, STATUTE, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE, AND WHETHER OR NOT GLITCHAPP HAS BEEN INFORMED OF THE POSSIBILITY OF ANY SUCH DAMAGE.</p>

<h2 id="indemnification">9. Indemnification</h2>
<p>You agree to defend, indemnify, and hold harmless GlitchApp Inc. and its licensees, licensors, employees, contractors, agents, officers, directors, suppliers, and partners from and against any and all claims, damages, obligations, losses, liabilities, costs, debt, and expenses (including but not limited to attorneys' fees) arising from:</p>
<ul>
  <li>Your use of and access to the Services, including any data or content transmitted or received by you</li>
  <li>Your violation of any term of these Terms, including without limitation your breach of any representations and warranties</li>
  <li>Your violation of any third-party right, including without limitation any right of privacy, intellectual property, or publicity</li>
  <li>Your violation of any applicable law, rule, or regulation</li>
  <li>Any User Content that is submitted through your account, including without limitation misleading, false, or inaccurate information</li>
  <li>Your willful misconduct</li>
  <li>Any other party's access to and use of the Services with your unique username, password, or other appropriate security code</li>
</ul>

<h2 id="governing-law">10. Governing Law</h2>
<p>These Terms shall be governed by and construed in accordance with the laws of the State of California, United States of America, without regard to its conflict of law provisions. Our failure to enforce any right or provision of these Terms will not be considered a waiver of those rights.</p>
<p>If any provision of these Terms is held to be invalid or unenforceable by a court, the remaining provisions of these Terms will remain in effect. These Terms constitute the entire agreement between us regarding our Services and supersede and replace any prior agreements we might have between us regarding the Services.</p>
<p>Any legal action or proceeding relating to your access to, or use of, the Services shall be instituted in a state or federal court in San Francisco County, California, and you agree to submit to the jurisdiction of, and agree that venue is proper in, these courts in any such legal action or proceeding.</p>

<h2 id="disputes">11. Dispute Resolution</h2>
<p>Any dispute arising out of or relating to these Terms or the Services shall first be attempted to be resolved through good-faith negotiation between the parties for a period of thirty (30) days from the date the dispute is raised in writing.</p>
<p>If the dispute cannot be resolved through negotiation, the parties agree to submit the dispute to binding arbitration administered by the American Arbitration Association ("AAA") in accordance with the AAA's Commercial Arbitration Rules. The arbitration shall be conducted in San Francisco, California, before a single arbitrator. The arbitrator's decision shall be final and binding on both parties and may be entered as a judgment in any court of competent jurisdiction.</p>
<p>Notwithstanding the foregoing, either party may seek injunctive or other equitable relief in any court of competent jurisdiction to protect its intellectual property rights or confidential information. You agree that any dispute resolution proceedings will be conducted only on an individual basis and not in a class, consolidated, or representative action.</p>
<p>YOU AGREE THAT, BY ENTERING INTO THESE TERMS, YOU AND GLITCHAPP ARE EACH WAIVING THE RIGHT TO A TRIAL BY JURY AND THE RIGHT TO PARTICIPATE IN A CLASS ACTION.</p>

<h2 id="termination">12. Termination</h2>
<p>We may terminate or suspend your account immediately, without prior notice or liability, for any reason whatsoever, including without limitation if you breach the Terms. Upon termination, your right to use the Services will immediately cease. If you wish to terminate your account, you may simply discontinue using the Services or contact us to request account deletion.</p>
<p>All provisions of the Terms which by their nature should survive termination shall survive termination, including, without limitation, ownership provisions, warranty disclaimers, indemnification, and limitations of liability. Upon termination, we may, but are not obligated to, delete your User Content and account information.</p>
<p>We will make reasonable efforts to provide you with notice of termination and, where commercially practicable, an opportunity to retrieve your data. However, we are not obligated to maintain or provide any data or content after termination, and we may delete any or all of your data and content at our discretion after a reasonable notice period following termination.</p>

<h2 id="contact">13. Contact Information</h2>
<p>If you have any questions about these Terms, please contact us:</p>
<ul>
  <li><strong>Company:</strong> GlitchApp Inc.</li>
  <li><strong>Email:</strong> legal@glitchapp.io</li>
  <li><strong>Address:</strong> 1337 Fault Line Drive, Suite 404, San Francisco, CA 94105, United States</li>
  <li><strong>Phone:</strong> +1 (555) 012-3456</li>
</ul>
<p>For legal notices, please send correspondence to our legal department at the address above, with a copy to legal@glitchapp.io. All legal notices must be in writing and will be deemed given when delivered personally, sent by certified or registered mail (return receipt requested), or sent by overnight courier to the address above.</p>

</div>
</body>
</html>`)
	return sb.String()
}

// ---------------------------------------------------------------------------
// Cookie policy
// ---------------------------------------------------------------------------

func (h *Handler) serveCookiePolicy(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, cookiePolicyHTML())
	return http.StatusOK
}

func cookiePolicyHTML() string {
	updated := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC).Format("January 2, 2006")

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cookie Policy - GlitchApp Inc.</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:Georgia,'Times New Roman',serif;background:#fff;color:#333;line-height:1.8;padding:40px 20px;}
  .container{max-width:800px;margin:0 auto;}
  h1{font-size:32px;margin-bottom:6px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  h2{font-size:22px;margin-top:36px;margin-bottom:12px;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border-bottom:1px solid #e0e0e0;padding-bottom:6px;}
  p{margin-bottom:14px;font-size:15px;}
  ul{margin:0 0 14px 28px;font-size:15px;}
  li{margin-bottom:6px;}
  .meta{color:#888;font-size:14px;margin-bottom:32px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  a{color:#0066cc;}
  table{width:100%;border-collapse:collapse;margin:16px 0 24px 0;font-size:14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
  th{background:#f4f5f7;text-align:left;padding:10px 14px;border:1px solid #e0e0e0;font-weight:600;}
  td{padding:10px 14px;border:1px solid #e0e0e0;vertical-align:top;}
  tr:nth-child(even){background:#fafafa;}
</style>
</head>
<body>
<div class="container">
<h1>Cookie Policy</h1>
`)
	sb.WriteString(fmt.Sprintf(`<p class="meta">Last updated: %s</p>`, updated))
	sb.WriteString(`
<h2>What Are Cookies</h2>
<p>Cookies are small text files that are placed on your computer or mobile device by websites that you visit. They are widely used in order to make websites work, or work more efficiently, as well as to provide information to the owners of the site. Cookies allow a website to recognize a user's device and remember information about your visit, such as your preferred language, font size, and other preferences.</p>
<p>This Cookie Policy explains what cookies are, how GlitchApp Inc. ("we," "us," or "our") uses cookies and similar technologies on our website, and what choices you have regarding their use.</p>

<h2>How We Use Cookies</h2>
<p>We use cookies and similar tracking technologies to track the activity on our website and hold certain information. We use both session cookies (which expire when you close your browser) and persistent cookies (which remain on your device until you delete them or they expire).</p>

<h2>Types of Cookies We Use</h2>

<h2>1. Necessary Cookies</h2>
<p>These cookies are essential for the website to function properly. They enable basic functions like page navigation, secure area access, and session management. The website cannot function properly without these cookies, and they cannot be disabled.</p>
<table>
  <tr><th>Cookie Name</th><th>Purpose</th><th>Duration</th><th>Type</th></tr>
  <tr><td>__session_id</td><td>Maintains user session state across pages</td><td>Session</td><td>First-party</td></tr>
  <tr><td>__csrf_token</td><td>Prevents cross-site request forgery attacks</td><td>Session</td><td>First-party</td></tr>
  <tr><td>CookieConsent</td><td>Stores your cookie consent preferences</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>__consent</td><td>Detailed consent category preferences</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>_gdpr_consent</td><td>GDPR consent status indicator</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>__cf_bm</td><td>Bot management and security verification</td><td>30 minutes</td><td>First-party</td></tr>
</table>

<h2>2. Analytics Cookies</h2>
<p>These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site. They help us know which pages are the most and least popular and see how visitors move around the site. All information these cookies collect is aggregated and therefore anonymous.</p>
<table>
  <tr><th>Cookie Name</th><th>Purpose</th><th>Duration</th><th>Type</th></tr>
  <tr><td>_ga</td><td>Distinguishes unique users by assigning a randomly generated number as a client identifier</td><td>2 years</td><td>Third-party (Google)</td></tr>
  <tr><td>_ga_*</td><td>Used to persist session state in Google Analytics 4</td><td>2 years</td><td>Third-party (Google)</td></tr>
  <tr><td>_gid</td><td>Distinguishes users for analytics purposes</td><td>24 hours</td><td>Third-party (Google)</td></tr>
  <tr><td>_gat</td><td>Used to throttle request rate to Google Analytics</td><td>1 minute</td><td>Third-party (Google)</td></tr>
  <tr><td>__hstc</td><td>Tracks visitor identity and session information</td><td>13 months</td><td>Third-party (HubSpot)</td></tr>
  <tr><td>__hssc</td><td>Keeps track of sessions for analytics</td><td>30 minutes</td><td>Third-party (HubSpot)</td></tr>
</table>

<h2>3. Marketing Cookies</h2>
<p>These cookies are used to track visitors across websites. The intention is to display ads that are relevant and engaging for the individual user and thereby more valuable for publishers and third-party advertisers.</p>
<table>
  <tr><th>Cookie Name</th><th>Purpose</th><th>Duration</th><th>Type</th></tr>
  <tr><td>_fbp</td><td>Used by Facebook to deliver advertisements</td><td>3 months</td><td>Third-party (Facebook)</td></tr>
  <tr><td>_gcl_au</td><td>Used by Google AdSense for ad targeting</td><td>3 months</td><td>Third-party (Google)</td></tr>
  <tr><td>IDE</td><td>Used by Google DoubleClick to register and report on ad interactions</td><td>1 year</td><td>Third-party (Google)</td></tr>
  <tr><td>__adroll</td><td>Used for retargeting ad campaigns</td><td>1 year</td><td>Third-party (AdRoll)</td></tr>
  <tr><td>_uetsid</td><td>Microsoft Bing Ads Universal Event Tracking</td><td>1 day</td><td>Third-party (Microsoft)</td></tr>
</table>

<h2>4. Preference Cookies</h2>
<p>Preference cookies enable a website to remember information that changes the way the website behaves or looks, like your preferred language, region, theme settings, or font size preferences.</p>
<table>
  <tr><th>Cookie Name</th><th>Purpose</th><th>Duration</th><th>Type</th></tr>
  <tr><td>__locale</td><td>Stores the user's preferred language setting</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>__theme</td><td>Remembers the user's preferred color theme (light/dark)</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>__tz</td><td>Stores the user's timezone preference</td><td>1 year</td><td>First-party</td></tr>
  <tr><td>__layout</td><td>Remembers the user's preferred page layout</td><td>6 months</td><td>First-party</td></tr>
</table>

<h2>Managing Cookies</h2>
<p>You can manage your cookie preferences at any time through our <a href="/consent/preferences">Cookie Preference Center</a>. Additionally, most web browsers allow you to control cookies through their settings preferences. However, if you limit the ability of websites to set cookies, you may impair your overall user experience.</p>
<p>To find out more about cookies, including how to see what cookies have been set, visit <a href="https://www.allaboutcookies.org" rel="nofollow">www.allaboutcookies.org</a>.</p>
<p>Below are links to the cookie management instructions for common browsers:</p>
<ul>
  <li><strong>Chrome:</strong> Settings &gt; Privacy and Security &gt; Cookies and other site data</li>
  <li><strong>Firefox:</strong> Settings &gt; Privacy &amp; Security &gt; Cookies and Site Data</li>
  <li><strong>Safari:</strong> Preferences &gt; Privacy &gt; Manage Website Data</li>
  <li><strong>Edge:</strong> Settings &gt; Cookies and site permissions &gt; Cookies and site data</li>
</ul>

<h2>Global Privacy Control</h2>
<p>We respect the Global Privacy Control (GPC) signal. If your browser sends a GPC signal, we will treat it as a valid opt-out of the sale or sharing of your personal information. You can learn more about GPC at <a href="https://globalprivacycontrol.org" rel="nofollow">globalprivacycontrol.org</a>. Our GPC support status is available at <a href="/.well-known/gpc">/.well-known/gpc</a>.</p>

<h2>Do Not Track</h2>
<p>We honor the Do Not Track (DNT) browser signal. When we detect a DNT signal, we respond with the tracking status header <code>Tk: N</code> indicating that we are not tracking the user. Note that DNT is a separate mechanism from GPC, and both are respected independently.</p>

<h2>Changes to This Policy</h2>
<p>We may update this Cookie Policy from time to time to reflect changes in technology, regulation, our business operations, or for other operational, legal, or regulatory reasons. We encourage you to periodically review this page for the latest information on our cookie practices.</p>

<h2>Contact Us</h2>
<p>If you have any questions about this Cookie Policy, please contact us:</p>
<ul>
  <li><strong>Email:</strong> privacy@glitchapp.io</li>
  <li><strong>Address:</strong> GlitchApp Inc., 1337 Fault Line Drive, Suite 404, San Francisco, CA 94105, United States</li>
</ul>

</div>
</body>
</html>`)
	return sb.String()
}
