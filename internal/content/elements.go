package content

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// NavItem represents a navigation link.
type NavItem struct {
	Label string
	Href  string
}

// Elements generates realistic HTML fragments for UI components.
type Elements struct {
	words *WordBank
}

// NewElements creates a new Elements instance backed by the given WordBank.
func NewElements(words *WordBank) *Elements {
	return &Elements{words: words}
}

// csrfToken generates a random hex token from the given rng.
func csrfToken(rng *rand.Rand) string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return fmt.Sprintf("%x", b)
}

// randHexColor returns a random hex color string like #a3c2f0.
func randHexColor(rng *rand.Rand) string {
	return fmt.Sprintf("#%02x%02x%02x", rng.Intn(200)+40, rng.Intn(200)+40, rng.Intn(200)+40)
}

// randDate returns a random date within the last year.
func randDate(rng *rand.Rand) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Duration(rng.Intn(365*24)) * time.Hour)
}

// --------------------------------------------------------------------------
// 1. SearchBar
// --------------------------------------------------------------------------

// SearchBar generates a search input with placeholder, button, and autocomplete container.
func (e *Elements) SearchBar(rng *rand.Rand) string {
	placeholders := []string{
		"Search articles, docs, and more...",
		"What are you looking for?",
		"Search the knowledge base...",
		"Type to search...",
		"Find products, guides, tutorials...",
	}
	placeholder := placeholders[rng.Intn(len(placeholders))]

	advancedLink := ""
	if rng.Intn(3) == 0 {
		advancedLink = `<a href="/search/advanced" class="search-advanced">Advanced Search</a>`
	}

	return fmt.Sprintf(`<div class="search-bar">
  <style>
    .search-bar { position: relative; max-width: 600px; margin: 0 auto; }
    .search-bar form { display: flex; gap: 8px; }
    .search-bar input[type="search"] {
      flex: 1; padding: 10px 16px; border: 1px solid #d1d5db; border-radius: 6px;
      font-size: 15px; outline: none; transition: border-color 0.2s;
    }
    .search-bar input[type="search"]:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
    .search-bar button[type="submit"] {
      padding: 10px 20px; background: #3b82f6; color: #fff; border: none; border-radius: 6px;
      font-size: 15px; cursor: pointer; transition: background 0.2s;
    }
    .search-bar button[type="submit"]:hover { background: #2563eb; }
    .search-autocomplete { position: absolute; top: 100%%; left: 0; right: 0; background: #fff; border: 1px solid #d1d5db; border-radius: 6px; margin-top: 4px; display: none; box-shadow: 0 4px 12px rgba(0,0,0,0.1); z-index: 100; }
    .search-advanced { display: inline-block; margin-top: 6px; font-size: 13px; color: #6b7280; text-decoration: none; }
    .search-advanced:hover { color: #3b82f6; }
  </style>
  <form action="/search" method="GET" role="search">
    <label for="search-input" class="sr-only" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);">Search</label>
    <input type="search" id="search-input" name="q" placeholder="%s" autocomplete="off" aria-label="Search">
    <button type="submit" aria-label="Submit search">Search</button>
  </form>
  <div class="search-autocomplete" id="search-autocomplete" role="listbox" aria-label="Search suggestions"></div>
  %s
</div>`, placeholder, advancedLink)
}

// --------------------------------------------------------------------------
// 2. LoginForm
// --------------------------------------------------------------------------

// LoginForm generates a username/password login form with CSRF token.
func (e *Elements) LoginForm(rng *rand.Rand) string {
	token := csrfToken(rng)

	return fmt.Sprintf(`<div class="login-form-container">
  <style>
    .login-form-container { max-width: 400px; margin: 40px auto; padding: 32px; background: #fff; border-radius: 10px; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }
    .login-form-container h2 { margin: 0 0 24px; font-size: 22px; color: #111827; text-align: center; }
    .login-form-container .form-group { margin-bottom: 18px; }
    .login-form-container label { display: block; margin-bottom: 6px; font-size: 14px; font-weight: 500; color: #374151; }
    .login-form-container input[type="text"],
    .login-form-container input[type="password"] {
      width: 100%%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px;
      font-size: 15px; box-sizing: border-box; outline: none;
    }
    .login-form-container input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
    .login-form-container .form-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; font-size: 13px; }
    .login-form-container .form-row a { color: #3b82f6; text-decoration: none; }
    .login-form-container .form-row a:hover { text-decoration: underline; }
    .login-form-container button[type="submit"] {
      width: 100%%; padding: 12px; background: #3b82f6; color: #fff; border: none; border-radius: 6px;
      font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .login-form-container button[type="submit"]:hover { background: #2563eb; }
  </style>
  <h2>Sign In</h2>
  <form action="/api/auth/login" method="POST" id="login-form">
    <input type="hidden" name="_csrf" value="%s">
    <div class="form-group">
      <label for="login-username">Username</label>
      <input type="text" id="login-username" name="username" placeholder="Enter your username" required autocomplete="username">
    </div>
    <div class="form-group">
      <label for="login-password">Password</label>
      <input type="password" id="login-password" name="password" placeholder="Enter your password" required autocomplete="current-password">
    </div>
    <div class="form-row">
      <label style="display:inline;font-weight:normal;"><input type="checkbox" id="login-remember" name="remember" value="1"> Remember me</label>
      <a href="/auth/forgot-password">Forgot password?</a>
    </div>
    <button type="submit">Sign In</button>
  </form>
</div>`, token)
}

// --------------------------------------------------------------------------
// 3. RegisterForm
// --------------------------------------------------------------------------

// RegisterForm generates a registration form with name, email, password, confirm, terms.
func (e *Elements) RegisterForm(rng *rand.Rand) string {
	token := csrfToken(rng)

	return fmt.Sprintf(`<div class="register-form-container">
  <style>
    .register-form-container { max-width: 440px; margin: 40px auto; padding: 32px; background: #fff; border-radius: 10px; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }
    .register-form-container h2 { margin: 0 0 24px; font-size: 22px; color: #111827; text-align: center; }
    .register-form-container .form-group { margin-bottom: 16px; }
    .register-form-container label { display: block; margin-bottom: 5px; font-size: 14px; font-weight: 500; color: #374151; }
    .register-form-container input[type="text"],
    .register-form-container input[type="email"],
    .register-form-container input[type="password"] {
      width: 100%%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px;
      font-size: 15px; box-sizing: border-box; outline: none;
    }
    .register-form-container input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
    .register-form-container .terms-group { margin: 18px 0; font-size: 13px; color: #6b7280; }
    .register-form-container .terms-group a { color: #3b82f6; text-decoration: none; }
    .register-form-container button[type="submit"] {
      width: 100%%; padding: 12px; background: #10b981; color: #fff; border: none; border-radius: 6px;
      font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .register-form-container button[type="submit"]:hover { background: #059669; }
  </style>
  <h2>Create Account</h2>
  <form action="/api/auth/register" method="POST" id="register-form">
    <input type="hidden" name="_csrf" value="%s">
    <div class="form-group">
      <label for="register-name">Full Name</label>
      <input type="text" id="register-name" name="name" placeholder="Your full name" required autocomplete="name">
    </div>
    <div class="form-group">
      <label for="register-email">Email Address</label>
      <input type="email" id="register-email" name="email" placeholder="you@example.com" required autocomplete="email">
    </div>
    <div class="form-group">
      <label for="register-password">Password</label>
      <input type="password" id="register-password" name="password" placeholder="Create a password" required minlength="8" autocomplete="new-password">
    </div>
    <div class="form-group">
      <label for="register-confirm-password">Confirm Password</label>
      <input type="password" id="register-confirm-password" name="confirm_password" placeholder="Confirm your password" required minlength="8" autocomplete="new-password">
    </div>
    <div class="terms-group">
      <label><input type="checkbox" id="register-terms" name="terms" value="1" required> I agree to the <a href="/terms">Terms of Service</a> and <a href="/privacy-policy">Privacy Policy</a></label>
    </div>
    <button type="submit">Create Account</button>
  </form>
</div>`, token)
}

// --------------------------------------------------------------------------
// 4. ContactForm
// --------------------------------------------------------------------------

// ContactForm generates a contact form with name, email, subject, message, captcha placeholder.
func (e *Elements) ContactForm(rng *rand.Rand) string {
	token := csrfToken(rng)

	subjects := []string{
		"General Inquiry", "Technical Support", "Sales Question", "Bug Report",
		"Feature Request", "Partnership Opportunity", "Billing Issue", "Press Inquiry",
	}

	var optionsHTML strings.Builder
	optionsHTML.WriteString(`<option value="" disabled selected>Select a subject</option>`)
	for _, s := range subjects {
		val := strings.ToLower(strings.ReplaceAll(s, " ", "_"))
		optionsHTML.WriteString(fmt.Sprintf("\n        <option value=\"%s\">%s</option>", val, s))
	}

	return fmt.Sprintf(`<div class="contact-form-container">
  <style>
    .contact-form-container { max-width: 520px; margin: 40px auto; padding: 32px; background: #fff; border-radius: 10px; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }
    .contact-form-container h2 { margin: 0 0 8px; font-size: 22px; color: #111827; }
    .contact-form-container .subtitle { margin: 0 0 24px; font-size: 14px; color: #6b7280; }
    .contact-form-container .form-group { margin-bottom: 16px; }
    .contact-form-container label { display: block; margin-bottom: 5px; font-size: 14px; font-weight: 500; color: #374151; }
    .contact-form-container input[type="text"],
    .contact-form-container input[type="email"],
    .contact-form-container select,
    .contact-form-container textarea {
      width: 100%%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px;
      font-size: 15px; box-sizing: border-box; outline: none; font-family: inherit;
    }
    .contact-form-container input:focus,
    .contact-form-container select:focus,
    .contact-form-container textarea:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
    .contact-form-container textarea { resize: vertical; min-height: 120px; }
    .contact-form-container .captcha-placeholder {
      padding: 16px; background: #f3f4f6; border: 1px dashed #9ca3af; border-radius: 6px;
      text-align: center; color: #6b7280; font-size: 13px; margin-bottom: 16px;
    }
    .contact-form-container button[type="submit"] {
      width: 100%%; padding: 12px; background: #3b82f6; color: #fff; border: none; border-radius: 6px;
      font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .contact-form-container button[type="submit"]:hover { background: #2563eb; }
  </style>
  <h2>Contact Us</h2>
  <p class="subtitle">We'd love to hear from you. Fill out the form below and we'll get back to you shortly.</p>
  <form action="/api/contact" method="POST" id="contact-form">
    <input type="hidden" name="_csrf" value="%s">
    <div class="form-group">
      <label for="contact-name">Your Name</label>
      <input type="text" id="contact-name" name="name" placeholder="Full name" required>
    </div>
    <div class="form-group">
      <label for="contact-email">Email Address</label>
      <input type="email" id="contact-email" name="email" placeholder="you@example.com" required>
    </div>
    <div class="form-group">
      <label for="contact-subject">Subject</label>
      <select id="contact-subject" name="subject" required>
        %s
      </select>
    </div>
    <div class="form-group">
      <label for="contact-message">Message</label>
      <textarea id="contact-message" name="message" placeholder="Tell us how we can help..." required></textarea>
    </div>
    <div class="captcha-placeholder" id="captcha-container">
      CAPTCHA verification will appear here
    </div>
    <button type="submit">Send Message</button>
  </form>
</div>`, token, optionsHTML.String())
}

// --------------------------------------------------------------------------
// 5. NewsletterSignup
// --------------------------------------------------------------------------

// NewsletterSignup generates a newsletter subscription form with email, frequency, categories.
func (e *Elements) NewsletterSignup(rng *rand.Rand) string {
	token := csrfToken(rng)

	categories := []string{
		"Engineering", "Product Updates", "Industry News", "Tutorials",
		"Case Studies", "Security Alerts", "Community", "Events",
	}

	// Pick a random subset of categories
	numCats := rng.Intn(4) + 4
	shuffled := make([]string, len(categories))
	copy(shuffled, categories)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	selected := shuffled[:numCats]

	var catsHTML strings.Builder
	for _, cat := range selected {
		val := strings.ToLower(strings.ReplaceAll(cat, " ", "_"))
		checked := ""
		if rng.Intn(3) == 0 {
			checked = " checked"
		}
		catsHTML.WriteString(fmt.Sprintf(`
        <label class="checkbox-label"><input type="checkbox" name="categories" value="%s"%s> %s</label>`, val, checked, cat))
	}

	bgColor := randHexColor(rng)

	return fmt.Sprintf(`<div class="newsletter-signup" style="background:linear-gradient(135deg, %s, %s); padding:32px; border-radius:12px; color:#fff; max-width:600px; margin:24px auto;">
  <style>
    .newsletter-signup h3 { margin: 0 0 8px; font-size: 20px; }
    .newsletter-signup .nl-subtitle { margin: 0 0 20px; font-size: 14px; opacity: 0.9; }
    .newsletter-signup .form-group { margin-bottom: 16px; }
    .newsletter-signup label.field-label { display: block; margin-bottom: 5px; font-size: 13px; font-weight: 500; }
    .newsletter-signup input[type="email"] {
      width: 100%%; padding: 10px 12px; border: 2px solid rgba(255,255,255,0.3); border-radius: 6px;
      background: rgba(255,255,255,0.15); color: #fff; font-size: 15px; box-sizing: border-box; outline: none;
    }
    .newsletter-signup input[type="email"]::placeholder { color: rgba(255,255,255,0.7); }
    .newsletter-signup input[type="email"]:focus { border-color: #fff; background: rgba(255,255,255,0.25); }
    .newsletter-signup .radio-group, .newsletter-signup .checkbox-group { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
    .newsletter-signup .radio-label, .newsletter-signup .checkbox-label { font-size: 14px; cursor: pointer; display: flex; align-items: center; gap: 4px; }
    .newsletter-signup button[type="submit"] {
      padding: 12px 28px; background: #fff; color: #111827; border: none; border-radius: 6px;
      font-size: 15px; font-weight: 600; cursor: pointer; transition: transform 0.15s, box-shadow 0.15s;
    }
    .newsletter-signup button[type="submit"]:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.2); }
  </style>
  <h3>Stay in the Loop</h3>
  <p class="nl-subtitle">Get the latest updates delivered straight to your inbox.</p>
  <form action="/api/newsletter/subscribe" method="POST" id="newsletter-form">
    <input type="hidden" name="_csrf" value="%s">
    <div class="form-group">
      <label class="field-label" for="newsletter-email">Email Address</label>
      <input type="email" id="newsletter-email" name="email" placeholder="you@example.com" required>
    </div>
    <div class="form-group">
      <label class="field-label">Frequency</label>
      <div class="radio-group">
        <label class="radio-label"><input type="radio" name="frequency" value="daily"> Daily</label>
        <label class="radio-label"><input type="radio" name="frequency" value="weekly" checked> Weekly</label>
        <label class="radio-label"><input type="radio" name="frequency" value="monthly"> Monthly</label>
      </div>
    </div>
    <div class="form-group">
      <label class="field-label">Categories</label>
      <div class="checkbox-group">%s
      </div>
    </div>
    <button type="submit">Subscribe</button>
  </form>
</div>`, bgColor, randHexColor(rng), token, catsHTML.String())
}

// --------------------------------------------------------------------------
// 6. CookieConsent
// --------------------------------------------------------------------------

// CookieConsent generates a fixed-position cookie consent banner.
func (e *Elements) CookieConsent(rng *rand.Rand) string {
	messages := []string{
		"We use cookies to enhance your browsing experience, serve personalized content, and analyze our traffic.",
		"This website uses cookies to ensure you get the best experience on our website.",
		"We use cookies and similar technologies to provide the best experience on our site.",
		"By continuing to browse this site, you agree to our use of cookies as described in our Cookie Policy.",
	}
	msg := messages[rng.Intn(len(messages))]

	return fmt.Sprintf(`<div class="cookie-consent" id="cookie-consent">
  <style>
    .cookie-consent {
      position: fixed; bottom: 0; left: 0; right: 0; z-index: 9999;
      background: #1f2937; color: #e5e7eb; padding: 16px 24px;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
      box-shadow: 0 -2px 16px rgba(0,0,0,0.15); font-size: 14px;
    }
    .cookie-consent .cookie-text { flex: 1; min-width: 300px; line-height: 1.5; }
    .cookie-consent .cookie-text a { color: #60a5fa; text-decoration: underline; }
    .cookie-consent .cookie-buttons { display: flex; gap: 10px; flex-shrink: 0; }
    .cookie-consent button {
      padding: 8px 18px; border: none; border-radius: 5px; font-size: 14px;
      font-weight: 500; cursor: pointer; transition: opacity 0.2s;
    }
    .cookie-consent button:hover { opacity: 0.85; }
    .cookie-consent .btn-accept { background: #10b981; color: #fff; }
    .cookie-consent .btn-reject { background: #4b5563; color: #e5e7eb; }
    .cookie-consent .btn-customize { background: transparent; color: #60a5fa; border: 1px solid #60a5fa; }
  </style>
  <div class="cookie-text">
    %s Read our <a href="/privacy-policy">Privacy Policy</a> for more information.
  </div>
  <div class="cookie-buttons">
    <button class="btn-reject" id="cookie-reject" type="button">Reject All</button>
    <button class="btn-customize" id="cookie-customize" type="button">Customize</button>
    <button class="btn-accept" id="cookie-accept" type="button">Accept All</button>
  </div>
</div>`, msg)
}

// --------------------------------------------------------------------------
// 7. NavHeader
// --------------------------------------------------------------------------

// NavHeader generates a full header with logo, navigation links, search icon, and user menu.
func (e *Elements) NavHeader(rng *rand.Rand, navItems []NavItem) string {
	logoText := e.words.Companies[rng.Intn(len(e.words.Companies))]

	var navHTML strings.Builder
	for _, item := range navItems {
		navHTML.WriteString(fmt.Sprintf(`
        <a href="%s" class="nav-link">%s</a>`, item.Href, item.Label))
	}

	userName := e.words.RandName(rng)
	initials := string(userName[0]) + string([]rune(userName)[strings.Index(userName, " ")+1])

	return fmt.Sprintf(`<header class="site-header" id="site-header">
  <style>
    .site-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px; height: 64px; background: #fff; border-bottom: 1px solid #e5e7eb;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .site-header .logo { font-size: 20px; font-weight: 700; color: #111827; text-decoration: none; }
    .site-header nav { display: flex; align-items: center; gap: 4px; }
    .site-header .nav-link {
      padding: 8px 14px; font-size: 15px; color: #374151; text-decoration: none;
      border-radius: 6px; transition: background 0.15s, color 0.15s;
    }
    .site-header .nav-link:hover { background: #f3f4f6; color: #111827; }
    .site-header .header-actions { display: flex; align-items: center; gap: 12px; }
    .site-header .search-icon {
      width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;
      border-radius: 50%%; cursor: pointer; transition: background 0.15s;
    }
    .site-header .search-icon:hover { background: #f3f4f6; }
    .site-header .user-menu { position: relative; }
    .site-header .user-avatar {
      width: 36px; height: 36px; border-radius: 50%%; background: #3b82f6; color: #fff;
      display: flex; align-items: center; justify-content: center; font-size: 14px;
      font-weight: 600; cursor: pointer;
    }
    .site-header .user-dropdown {
      display: none; position: absolute; top: 44px; right: 0; background: #fff;
      border: 1px solid #e5e7eb; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.1);
      min-width: 180px; z-index: 500; padding: 6px 0;
    }
    .site-header .user-dropdown a {
      display: block; padding: 8px 16px; font-size: 14px; color: #374151; text-decoration: none;
    }
    .site-header .user-dropdown a:hover { background: #f3f4f6; }
  </style>
  <a href="/" class="logo">%s</a>
  <nav>%s
  </nav>
  <div class="header-actions">
    <div class="search-icon" role="button" aria-label="Search" tabindex="0">
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#6b7280" stroke-width="2">
        <circle cx="8.5" cy="8.5" r="6"/>
        <line x1="13" y1="13" x2="18" y2="18"/>
      </svg>
    </div>
    <div class="user-menu">
      <div class="user-avatar" role="button" aria-label="User menu" tabindex="0">%s</div>
      <div class="user-dropdown" id="user-dropdown">
        <a href="/profile">Profile</a>
        <a href="/settings">Settings</a>
        <a href="/billing">Billing</a>
        <a href="/auth/logout">Sign Out</a>
      </div>
    </div>
  </div>
</header>`, logoText, navHTML.String(), initials)
}

// --------------------------------------------------------------------------
// 8. Footer
// --------------------------------------------------------------------------

// Footer generates a multi-column footer with about, links, resources, contact, and legal.
func (e *Elements) Footer(rng *rand.Rand, companyName string) string {
	year := time.Now().Year()

	quickLinks := []NavItem{
		{Label: "Home", Href: "/"},
		{Label: "Products", Href: "/products"},
		{Label: "Pricing", Href: "/pricing"},
		{Label: "Blog", Href: "/blog"},
		{Label: "Careers", Href: "/careers"},
	}
	// Occasionally add vuln endpoint links that look like real app pages
	if rng.Intn(3) == 0 {
		quickLinks = append(quickLinks, NavItem{Label: "Administration", Href: "/vuln/dashboard/"})
	}
	if rng.Intn(3) == 0 {
		quickLinks = append(quickLinks, NavItem{Label: "Manage Users", Href: "/vuln/a01/"})
	}
	resources := []NavItem{
		{Label: "Documentation", Href: "/docs"},
		{Label: "API Reference", Href: "/api"},
		{Label: "Tutorials", Href: "/tutorials"},
		{Label: "Status Page", Href: "/status"},
		{Label: "Support", Href: "/support"},
	}
	if rng.Intn(3) == 0 {
		resources = append(resources, NavItem{Label: "System Config", Href: "/vuln/settings/"})
	}

	var qlHTML, resHTML strings.Builder
	for _, l := range quickLinks {
		qlHTML.WriteString(fmt.Sprintf("\n          <li><a href=\"%s\">%s</a></li>", l.Href, l.Label))
	}
	for _, l := range resources {
		resHTML.WriteString(fmt.Sprintf("\n          <li><a href=\"%s\">%s</a></li>", l.Href, l.Label))
	}

	email := fmt.Sprintf("contact@%s.com", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(companyName, " ", ""), "&", "")))
	phone := fmt.Sprintf("+1 (%d) %d-%04d", rng.Intn(800)+200, rng.Intn(900)+100, rng.Intn(10000))
	address := fmt.Sprintf("%d %s Street, Suite %d", rng.Intn(9000)+100, e.words.LastNames[rng.Intn(len(e.words.LastNames))], rng.Intn(500)+100)

	aboutText := fmt.Sprintf("%s builds %s %s for teams that demand %s performance and %s reliability.",
		companyName,
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		e.words.Nouns[rng.Intn(len(e.words.Nouns))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
	)

	// Social media SVG icon placeholders (simple colored circles)
	socials := []struct{ Name, Color string }{
		{"Twitter", "#1da1f2"},
		{"Facebook", "#1877f2"},
		{"LinkedIn", "#0a66c2"},
		{"GitHub", "#333"},
		{"YouTube", "#ff0000"},
	}
	var socialHTML strings.Builder
	for _, s := range socials {
		socialHTML.WriteString(fmt.Sprintf(`
          <a href="https://%s.com/%s" aria-label="%s" title="%s" style="display:inline-block;margin-right:10px;">
            <svg width="28" height="28" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="%s"/><text x="14" y="18" text-anchor="middle" fill="#fff" font-size="11" font-weight="600">%s</text></svg>
          </a>`,
			strings.ToLower(s.Name), strings.ToLower(strings.ReplaceAll(companyName, " ", "")),
			s.Name, s.Name, s.Color, strings.ToUpper(s.Name[:1])))
	}

	return fmt.Sprintf(`<footer class="site-footer">
  <style>
    .site-footer { background: #111827; color: #d1d5db; padding: 48px 24px 24px; font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .site-footer .footer-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 32px; max-width: 1200px; margin: 0 auto; }
    .site-footer .footer-col h4 { color: #fff; font-size: 15px; margin: 0 0 14px; text-transform: uppercase; letter-spacing: 0.05em; }
    .site-footer .footer-col p { line-height: 1.6; margin: 0 0 12px; }
    .site-footer .footer-col ul { list-style: none; padding: 0; margin: 0; }
    .site-footer .footer-col ul li { margin-bottom: 8px; }
    .site-footer .footer-col a { color: #9ca3af; text-decoration: none; transition: color 0.15s; }
    .site-footer .footer-col a:hover { color: #fff; }
    .site-footer .footer-bottom {
      max-width: 1200px; margin: 32px auto 0; padding-top: 24px; border-top: 1px solid #374151;
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    }
    .site-footer .legal-links { display: flex; gap: 16px; }
    .site-footer .legal-links a { color: #9ca3af; text-decoration: none; font-size: 13px; }
    .site-footer .legal-links a:hover { color: #fff; }
  </style>
  <div class="footer-grid">
    <div class="footer-col">
      <h4>About</h4>
      <p>%s</p>
      <div class="social-icons">%s
      </div>
    </div>
    <div class="footer-col">
      <h4>Quick Links</h4>
      <ul>%s
      </ul>
    </div>
    <div class="footer-col">
      <h4>Resources</h4>
      <ul>%s
      </ul>
    </div>
    <div class="footer-col">
      <h4>Contact</h4>
      <p>%s</p>
      <p><a href="mailto:%s">%s</a></p>
      <p>%s</p>
    </div>
  </div>
  <div class="footer-bottom">
    <span>&copy; %d %s. All rights reserved.</span>
    <div class="legal-links">
      <a href="/privacy-policy">Privacy Policy</a>
      <a href="/terms">Terms of Service</a>
      <a href="/cookie-policy">Cookie Policy</a>
    </div>
  </div>
</footer>`, aboutText, socialHTML.String(), qlHTML.String(), resHTML.String(), address, email, email, phone, year, companyName)
}

// --------------------------------------------------------------------------
// 9. CommentSection
// --------------------------------------------------------------------------

// CommentSection generates a list of comments with avatars, voting, and a reply form.
func (e *Elements) CommentSection(rng *rand.Rand, count int) string {
	var commentsHTML strings.Builder

	for i := 0; i < count; i++ {
		name := e.words.RandName(rng)
		avatarColor := randHexColor(rng)
		initials := string(name[0]) + string([]rune(name)[strings.Index(name, " ")+1])
		ts := randDate(rng).Format("Jan 2, 2006 at 3:04 PM")
		text := e.words.Paragraph(rng, rng.Intn(3)+1)
		upvotes := rng.Intn(150)
		downvotes := rng.Intn(20)
		commentID := fmt.Sprintf("comment-%d-%d", i, rng.Intn(10000))

		commentsHTML.WriteString(fmt.Sprintf(`
    <div class="comment" id="%s">
      <div class="comment-avatar">
        <svg width="40" height="40" viewBox="0 0 40 40"><circle cx="20" cy="20" r="20" fill="%s"/><text x="20" y="25" text-anchor="middle" fill="#fff" font-size="15" font-weight="600">%s</text></svg>
      </div>
      <div class="comment-body">
        <div class="comment-meta">
          <span class="comment-author">%s</span>
          <span class="comment-time">%s</span>
        </div>
        <p class="comment-text">%s</p>
        <div class="comment-actions">
          <button type="button" class="vote-btn" aria-label="Upvote">&#9650; %d</button>
          <button type="button" class="vote-btn" aria-label="Downvote">&#9660; %d</button>
          <a href="#%s" class="reply-link">Reply</a>
        </div>
      </div>
    </div>`, commentID, avatarColor, initials, name, ts, text, upvotes, downvotes, commentID))
	}

	token := csrfToken(rng)

	return fmt.Sprintf(`<div class="comment-section" id="comments">
  <style>
    .comment-section { max-width: 700px; margin: 32px auto; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .comment-section h3 { font-size: 20px; color: #111827; margin-bottom: 20px; }
    .comment { display: flex; gap: 12px; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #e5e7eb; }
    .comment-avatar { flex-shrink: 0; }
    .comment-body { flex: 1; }
    .comment-meta { margin-bottom: 6px; }
    .comment-author { font-weight: 600; color: #111827; font-size: 14px; margin-right: 8px; }
    .comment-time { font-size: 12px; color: #9ca3af; }
    .comment-text { font-size: 14px; color: #374151; line-height: 1.6; margin: 0; }
    .comment-actions { margin-top: 8px; display: flex; align-items: center; gap: 12px; }
    .vote-btn {
      background: none; border: 1px solid #e5e7eb; border-radius: 4px; padding: 2px 8px;
      font-size: 13px; color: #6b7280; cursor: pointer; transition: background 0.15s;
    }
    .vote-btn:hover { background: #f3f4f6; }
    .reply-link { font-size: 13px; color: #3b82f6; text-decoration: none; }
    .reply-link:hover { text-decoration: underline; }
    .add-comment-form { margin-top: 24px; padding-top: 24px; border-top: 2px solid #e5e7eb; }
    .add-comment-form h4 { font-size: 16px; color: #111827; margin: 0 0 12px; }
    .add-comment-form textarea {
      width: 100%%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px;
      font-size: 14px; box-sizing: border-box; resize: vertical; min-height: 80px;
      outline: none; font-family: inherit;
    }
    .add-comment-form textarea:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
    .add-comment-form button[type="submit"] {
      margin-top: 10px; padding: 10px 24px; background: #3b82f6; color: #fff; border: none;
      border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer;
    }
    .add-comment-form button[type="submit"]:hover { background: #2563eb; }
  </style>
  <h3>Comments (%d)</h3>
  %s
  <div class="add-comment-form">
    <h4>Add a Comment</h4>
    <form action="/api/comments" method="POST" id="add-comment-form">
      <input type="hidden" name="_csrf" value="%s">
      <div>
        <label for="comment-author-name" style="display:block;margin-bottom:5px;font-size:14px;font-weight:500;color:#374151;">Name</label>
        <input type="text" id="comment-author-name" name="author" placeholder="Your name" required style="width:100%%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;box-sizing:border-box;margin-bottom:10px;">
      </div>
      <div>
        <label for="comment-text-input" style="display:block;margin-bottom:5px;font-size:14px;font-weight:500;color:#374151;">Comment</label>
        <textarea id="comment-text-input" name="body" placeholder="Share your thoughts..." required></textarea>
      </div>
      <button type="submit">Post Comment</button>
    </form>
  </div>
</div>`, count, commentsHTML.String(), token)
}

// --------------------------------------------------------------------------
// 10. ProductCard
// --------------------------------------------------------------------------

// ProductCard generates a product card with SVG placeholder, name, price, rating, description.
func (e *Elements) ProductCard(rng *rand.Rand) string {
	products := []string{
		"CloudSync Pro", "DataVault Enterprise", "NetGuard Shield", "CodeForge IDE",
		"PixelCraft Studio", "ServerMesh Gateway", "LogStream Analyzer", "TaskFlow Manager",
		"CryptoKey Vault", "APIBridge Connector", "MetricsPulse Dashboard", "FormBuilder Pro",
	}
	product := products[rng.Intn(len(products))]

	price := float64(rng.Intn(49900)+100) / 100.0
	rating := rng.Intn(3) + 3 // 3-5 stars
	reviewCount := rng.Intn(500) + 1
	desc := fmt.Sprintf("A %s %s designed for %s teams. Features %s %s with %s integration.",
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		e.words.Nouns[rng.Intn(len(e.words.Nouns))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		e.words.Nouns[rng.Intn(len(e.words.Nouns))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
	)

	bgColor := randHexColor(rng)
	iconColor := randHexColor(rng)

	var stars strings.Builder
	for i := 0; i < 5; i++ {
		if i < rating {
			stars.WriteString("&#9733;")
		} else {
			stars.WriteString("&#9734;")
		}
	}

	return fmt.Sprintf(`<div class="product-card">
  <style>
    .product-card {
      width: 280px; background: #fff; border-radius: 10px; overflow: hidden;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .product-card:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.12); }
    .product-card .product-image { position: relative; }
    .product-card .product-body { padding: 16px; }
    .product-card .product-name { font-size: 16px; font-weight: 600; color: #111827; margin: 0 0 6px; }
    .product-card .product-price { font-size: 20px; font-weight: 700; color: #059669; margin: 0 0 8px; }
    .product-card .product-rating { font-size: 16px; color: #f59e0b; margin-bottom: 8px; }
    .product-card .product-rating .review-count { font-size: 13px; color: #9ca3af; margin-left: 4px; }
    .product-card .product-desc { font-size: 13px; color: #6b7280; line-height: 1.5; margin: 0 0 14px; }
    .product-card .add-to-cart {
      width: 100%%; padding: 10px; background: #3b82f6; color: #fff; border: none; border-radius: 6px;
      font-size: 14px; font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .product-card .add-to-cart:hover { background: #2563eb; }
  </style>
  <div class="product-image">
    <svg width="280" height="200" viewBox="0 0 280 200">
      <rect width="280" height="200" fill="%s"/>
      <rect x="110" y="60" width="60" height="80" rx="8" fill="%s" opacity="0.8"/>
      <circle cx="140" cy="90" r="15" fill="#fff" opacity="0.6"/>
      <rect x="125" y="110" width="30" height="4" rx="2" fill="#fff" opacity="0.6"/>
    </svg>
  </div>
  <div class="product-body">
    <h3 class="product-name">%s</h3>
    <p class="product-price">$%.2f</p>
    <div class="product-rating">
      %s<span class="review-count">(%d reviews)</span>
    </div>
    <p class="product-desc">%s</p>
    <button class="add-to-cart" type="button">Add to Cart</button>
  </div>
</div>`, bgColor, iconColor, product, price, stars.String(), reviewCount, desc)
}

// --------------------------------------------------------------------------
// 11. PricingTable
// --------------------------------------------------------------------------

// PricingTable generates a 3-tier pricing table with features and CTA buttons.
func (e *Elements) PricingTable(rng *rand.Rand) string {
	basicPrice := rng.Intn(20) + 5
	proPrice := basicPrice*3 + rng.Intn(10)
	enterprisePrice := proPrice*2 + rng.Intn(30)

	features := []struct {
		Name                         string
		Basic, Pro, Enterprise       bool
	}{
		{"Up to 5 users", true, true, true},
		{"10 GB storage", true, true, true},
		{"Email support", true, true, true},
		{"API access", false, true, true},
		{"Custom integrations", false, true, true},
		{"Advanced analytics", false, true, true},
		{"Unlimited users", false, false, true},
		{"Unlimited storage", false, false, true},
		{"Priority support", false, false, true},
		{"SLA guarantee", false, false, true},
		{"Dedicated account manager", false, false, true},
		{"Custom deployment", false, false, true},
	}

	check := "&#10003;"
	dash := "&#8212;"

	renderFeatures := func(tier int) string {
		var sb strings.Builder
		for _, f := range features {
			var has bool
			switch tier {
			case 0:
				has = f.Basic
			case 1:
				has = f.Pro
			case 2:
				has = f.Enterprise
			}
			if has {
				sb.WriteString(fmt.Sprintf(`
            <li class="feature-yes"><span class="check">%s</span> %s</li>`, check, f.Name))
			} else {
				sb.WriteString(fmt.Sprintf(`
            <li class="feature-no"><span class="dash">%s</span> %s</li>`, dash, f.Name))
			}
		}
		return sb.String()
	}

	return fmt.Sprintf(`<div class="pricing-table" id="pricing">
  <style>
    .pricing-table { max-width: 960px; margin: 40px auto; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .pricing-table .pricing-header { text-align: center; margin-bottom: 32px; }
    .pricing-table .pricing-header h2 { font-size: 28px; color: #111827; margin: 0 0 8px; }
    .pricing-table .pricing-header p { color: #6b7280; font-size: 16px; margin: 0 0 16px; }
    .pricing-table .toggle-group {
      display: inline-flex; background: #f3f4f6; border-radius: 8px; padding: 4px;
    }
    .pricing-table .toggle-btn {
      padding: 8px 20px; border: none; background: transparent; border-radius: 6px;
      font-size: 14px; cursor: pointer; color: #6b7280; font-weight: 500;
    }
    .pricing-table .toggle-btn.active { background: #fff; color: #111827; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
    .pricing-card {
      background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 32px 24px;
      display: flex; flex-direction: column; text-align: center;
    }
    .pricing-card.featured { border-color: #3b82f6; box-shadow: 0 0 0 2px #3b82f6; position: relative; }
    .pricing-card.featured::before {
      content: "Most Popular"; position: absolute; top: -13px; left: 50%%; transform: translateX(-50%%);
      background: #3b82f6; color: #fff; font-size: 12px; font-weight: 600; padding: 4px 14px;
      border-radius: 50px;
    }
    .pricing-card .plan-name { font-size: 18px; font-weight: 600; color: #111827; margin: 0 0 8px; }
    .pricing-card .plan-price { font-size: 40px; font-weight: 700; color: #111827; margin: 0 0 4px; }
    .pricing-card .plan-price span { font-size: 16px; font-weight: 400; color: #6b7280; }
    .pricing-card .plan-desc { font-size: 14px; color: #6b7280; margin: 0 0 24px; }
    .pricing-card ul { list-style: none; padding: 0; margin: 0 0 24px; text-align: left; }
    .pricing-card ul li { padding: 8px 0; font-size: 14px; color: #374151; border-bottom: 1px solid #f3f4f6; }
    .pricing-card .feature-no { color: #d1d5db; }
    .pricing-card .check { color: #10b981; font-weight: bold; margin-right: 6px; }
    .pricing-card .dash { color: #d1d5db; margin-right: 6px; }
    .pricing-card .cta-btn {
      margin-top: auto; padding: 12px; border-radius: 8px; font-size: 15px; font-weight: 600;
      cursor: pointer; transition: background 0.2s; text-decoration: none; display: block;
    }
    .pricing-card .cta-btn.primary { background: #3b82f6; color: #fff; border: none; }
    .pricing-card .cta-btn.primary:hover { background: #2563eb; }
    .pricing-card .cta-btn.secondary { background: #fff; color: #3b82f6; border: 2px solid #3b82f6; }
    .pricing-card .cta-btn.secondary:hover { background: #eff6ff; }
  </style>
  <div class="pricing-header">
    <h2>Simple, Transparent Pricing</h2>
    <p>Choose the plan that works best for your team</p>
    <div class="toggle-group">
      <button class="toggle-btn active" type="button" id="toggle-monthly">Monthly</button>
      <button class="toggle-btn" type="button" id="toggle-annual">Annual (Save 20%%)</button>
    </div>
  </div>
  <div class="pricing-grid">
    <div class="pricing-card">
      <h3 class="plan-name">Basic</h3>
      <div class="plan-price">$%d<span>/mo</span></div>
      <p class="plan-desc">For individuals and small projects</p>
      <ul>%s
      </ul>
      <a href="/signup?plan=basic" class="cta-btn secondary">Get Started</a>
    </div>
    <div class="pricing-card featured">
      <h3 class="plan-name">Pro</h3>
      <div class="plan-price">$%d<span>/mo</span></div>
      <p class="plan-desc">For growing teams and businesses</p>
      <ul>%s
      </ul>
      <a href="/signup?plan=pro" class="cta-btn primary">Start Free Trial</a>
    </div>
    <div class="pricing-card">
      <h3 class="plan-name">Enterprise</h3>
      <div class="plan-price">$%d<span>/mo</span></div>
      <p class="plan-desc">For large organizations at scale</p>
      <ul>%s
      </ul>
      <a href="/contact?plan=enterprise" class="cta-btn secondary">Contact Sales</a>
    </div>
  </div>
</div>`, basicPrice, renderFeatures(0), proPrice, renderFeatures(1), enterprisePrice, renderFeatures(2))
}

// --------------------------------------------------------------------------
// 12. Testimonial
// --------------------------------------------------------------------------

// Testimonial generates a styled quote block with person info and avatar placeholder.
func (e *Elements) Testimonial(rng *rand.Rand) string {
	quotes := []string{
		"This %s has completely transformed how our team approaches %s. The %s features alone saved us hundreds of hours.",
		"We evaluated several %s options before choosing this one. The %s capabilities and %s support made it an easy decision.",
		"After switching to this %s, our %s metrics improved by over 40%%. The %s integration was seamless.",
		"I've been in the %s industry for over a decade. This is the most %s tool I've ever used for %s.",
		"Our entire engineering team relies on this %s daily. The %s and %s features are simply unmatched.",
	}

	quote := quotes[rng.Intn(len(quotes))]
	for strings.Contains(quote, "%s") {
		pool := []string{
			e.words.Nouns[rng.Intn(len(e.words.Nouns))],
			e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
		}
		quote = strings.Replace(quote, "%s", pool[rng.Intn(len(pool))], 1)
	}

	name := e.words.RandName(rng)
	title := e.words.JobTitles[rng.Intn(len(e.words.JobTitles))]
	company := e.words.Companies[rng.Intn(len(e.words.Companies))]
	avatarColor := randHexColor(rng)
	initials := string(name[0]) + string([]rune(name)[strings.Index(name, " ")+1])

	return fmt.Sprintf(`<blockquote class="testimonial">
  <style>
    .testimonial {
      max-width: 600px; margin: 32px auto; padding: 28px 32px; background: #f9fafb;
      border-left: 4px solid #3b82f6; border-radius: 0 10px 10px 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .testimonial .quote-text { font-size: 16px; color: #374151; line-height: 1.7; margin: 0 0 20px; font-style: italic; }
    .testimonial .quote-text::before { content: "\201C"; font-size: 28px; color: #3b82f6; vertical-align: -4px; margin-right: 2px; }
    .testimonial .quote-text::after { content: "\201D"; font-size: 28px; color: #3b82f6; vertical-align: -4px; margin-left: 2px; }
    .testimonial .quote-author { display: flex; align-items: center; gap: 12px; }
    .testimonial .quote-avatar svg { display: block; }
    .testimonial .quote-info .name { font-weight: 600; color: #111827; font-size: 15px; }
    .testimonial .quote-info .role { color: #6b7280; font-size: 13px; }
  </style>
  <p class="quote-text">%s</p>
  <div class="quote-author">
    <div class="quote-avatar">
      <svg width="44" height="44" viewBox="0 0 44 44"><circle cx="22" cy="22" r="22" fill="%s"/><text x="22" y="27" text-anchor="middle" fill="#fff" font-size="16" font-weight="600">%s</text></svg>
    </div>
    <div class="quote-info">
      <div class="name">%s</div>
      <div class="role">%s at %s</div>
    </div>
  </div>
</blockquote>`, quote, avatarColor, initials, name, title, company)
}

// --------------------------------------------------------------------------
// 13. HeroSection
// --------------------------------------------------------------------------

// HeroSection generates a large hero banner with heading, subtitle, CTA, and optional SVG pattern.
func (e *Elements) HeroSection(rng *rand.Rand, title, subtitle string) string {
	bgColor1 := randHexColor(rng)
	bgColor2 := randHexColor(rng)

	ctaLabels := []string{
		"Get Started Free", "Start Your Trial", "Learn More", "Book a Demo",
		"Explore Features", "Sign Up Now", "Try It Free",
	}
	ctaLabel := ctaLabels[rng.Intn(len(ctaLabels))]

	ctaHrefs := []string{"/signup", "/demo", "/features", "/pricing", "/trial"}
	ctaHref := ctaHrefs[rng.Intn(len(ctaHrefs))]

	// Generate random geometric SVG background pattern
	var patternShapes strings.Builder
	numShapes := rng.Intn(12) + 6
	for i := 0; i < numShapes; i++ {
		x := rng.Intn(1200)
		y := rng.Intn(500)
		opacity := float64(rng.Intn(15)+5) / 100.0
		size := rng.Intn(80) + 20
		switch rng.Intn(3) {
		case 0:
			patternShapes.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="%d" fill="#fff" opacity="%.2f"/>`, x, y, size, opacity))
		case 1:
			patternShapes.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="#fff" opacity="%.2f" transform="rotate(%d %d %d)"/>`, x, y, size, size, opacity, rng.Intn(45), x+size/2, y+size/2))
		case 2:
			x2 := x + rng.Intn(80) - 40
			y2 := y + rng.Intn(80) - 40
			x3 := x + rng.Intn(80) - 40
			y3 := y + rng.Intn(80) - 40
			patternShapes.WriteString(fmt.Sprintf(`<polygon points="%d,%d %d,%d %d,%d" fill="#fff" opacity="%.2f"/>`, x, y, x2, y2, x3, y3, opacity))
		}
	}

	return fmt.Sprintf(`<section class="hero-section">
  <style>
    .hero-section {
      position: relative; overflow: hidden;
      background: linear-gradient(135deg, %s, %s);
      padding: 80px 24px; text-align: center; color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .hero-section .hero-bg {
      position: absolute; top: 0; left: 0; width: 100%%; height: 100%%;
      pointer-events: none;
    }
    .hero-section .hero-content { position: relative; z-index: 1; max-width: 700px; margin: 0 auto; }
    .hero-section h1 { font-size: 42px; font-weight: 800; margin: 0 0 16px; line-height: 1.2; }
    .hero-section .hero-subtitle { font-size: 18px; opacity: 0.9; margin: 0 0 32px; line-height: 1.5; }
    .hero-section .hero-cta {
      display: inline-block; padding: 14px 36px; background: #fff; color: %s;
      font-size: 16px; font-weight: 600; border-radius: 8px; text-decoration: none;
      transition: transform 0.15s, box-shadow 0.15s;
    }
    .hero-section .hero-cta:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.2); }
  </style>
  <svg class="hero-bg" viewBox="0 0 1200 500" preserveAspectRatio="none">
    %s
  </svg>
  <div class="hero-content">
    <h1>%s</h1>
    <p class="hero-subtitle">%s</p>
    <a href="%s" class="hero-cta">%s</a>
  </div>
</section>`, bgColor1, bgColor2, bgColor1, patternShapes.String(), title, subtitle, ctaHref, ctaLabel)
}

// --------------------------------------------------------------------------
// 14. DataTable
// --------------------------------------------------------------------------

// DataTable generates an HTML table with headers, sortable indicators, and pagination.
func (e *Elements) DataTable(rng *rand.Rand, cols int, rows int) string {
	headerPool := []string{
		"ID", "Name", "Status", "Date", "Amount", "Category", "Priority",
		"Assignee", "Progress", "Region", "Score", "Type", "Version",
		"Duration", "Source", "Level", "Count", "Rate",
	}
	if cols > len(headerPool) {
		cols = len(headerPool)
	}

	// Shuffle and pick headers
	shuffled := make([]string, len(headerPool))
	copy(shuffled, headerPool)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	headers := shuffled[:cols]

	var headHTML strings.Builder
	sortCol := rng.Intn(cols)
	sortDir := "asc"
	if rng.Intn(2) == 0 {
		sortDir = "desc"
	}
	for i, h := range headers {
		indicator := " &#9650;&#9660;"
		activeClass := ""
		if i == sortCol {
			activeClass = " class=\"sorted\""
			if sortDir == "asc" {
				indicator = " &#9650;"
			} else {
				indicator = " &#9660;"
			}
		}
		headHTML.WriteString(fmt.Sprintf("\n        <th%s>%s<span class=\"sort-indicator\">%s</span></th>", activeClass, h, indicator))
	}

	statuses := []string{"Active", "Pending", "Inactive", "Completed", "Failed", "Processing"}
	categories := []string{"Alpha", "Beta", "Gamma", "Delta", "Sigma"}
	priorities := []string{"Low", "Medium", "High", "Critical"}

	var bodyHTML strings.Builder
	for r := 0; r < rows; r++ {
		bodyHTML.WriteString("\n        <tr>")
		for c := 0; c < cols; c++ {
			var val string
			switch headers[c] {
			case "ID":
				val = fmt.Sprintf("%d", rng.Intn(90000)+10000)
			case "Name":
				val = e.words.RandName(rng)
			case "Status":
				val = statuses[rng.Intn(len(statuses))]
			case "Date":
				val = randDate(rng).Format("2006-01-02")
			case "Amount":
				val = fmt.Sprintf("$%.2f", float64(rng.Intn(100000))/100.0)
			case "Category":
				val = categories[rng.Intn(len(categories))]
			case "Priority":
				val = priorities[rng.Intn(len(priorities))]
			case "Assignee":
				val = e.words.RandName(rng)
			case "Progress":
				val = fmt.Sprintf("%d%%", rng.Intn(101))
			case "Region":
				regions := []string{"North", "South", "East", "West", "Central", "EU", "APAC"}
				val = regions[rng.Intn(len(regions))]
			case "Score":
				val = fmt.Sprintf("%.1f", float64(rng.Intn(1000))/10.0)
			case "Type":
				types := []string{"Standard", "Premium", "Custom", "Trial", "Enterprise"}
				val = types[rng.Intn(len(types))]
			case "Version":
				val = fmt.Sprintf("v%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100))
			case "Duration":
				val = fmt.Sprintf("%dm %ds", rng.Intn(60), rng.Intn(60))
			case "Source":
				sources := []string{"Web", "API", "Mobile", "Import", "Sync"}
				val = sources[rng.Intn(len(sources))]
			case "Level":
				val = fmt.Sprintf("%d", rng.Intn(100)+1)
			case "Count":
				val = fmt.Sprintf("%d", rng.Intn(10000))
			case "Rate":
				val = fmt.Sprintf("%.2f%%", float64(rng.Intn(10000))/100.0)
			default:
				val = fmt.Sprintf("%d", rng.Intn(1000))
			}
			bodyHTML.WriteString(fmt.Sprintf("<td>%s</td>", val))
		}
		bodyHTML.WriteString("</tr>")
	}

	totalPages := rng.Intn(20) + 2
	currentPage := rng.Intn(totalPages) + 1

	var pagesHTML strings.Builder
	pagesHTML.WriteString(`<button class="page-btn" type="button" aria-label="Previous page">&laquo;</button>`)
	start := currentPage - 2
	if start < 1 {
		start = 1
	}
	end := start + 4
	if end > totalPages {
		end = totalPages
	}
	for p := start; p <= end; p++ {
		active := ""
		if p == currentPage {
			active = " active"
		}
		pagesHTML.WriteString(fmt.Sprintf(`<button class="page-btn%s" type="button">%d</button>`, active, p))
	}
	pagesHTML.WriteString(`<button class="page-btn" type="button" aria-label="Next page">&raquo;</button>`)

	return fmt.Sprintf(`<div class="data-table-container">
  <style>
    .data-table-container { max-width: 100%%; overflow-x: auto; margin: 24px 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .data-table-container table { width: 100%%; border-collapse: collapse; font-size: 14px; }
    .data-table-container th {
      background: #f9fafb; padding: 10px 14px; text-align: left; font-weight: 600;
      color: #374151; border-bottom: 2px solid #e5e7eb; white-space: nowrap; cursor: pointer;
      user-select: none;
    }
    .data-table-container th:hover { background: #f3f4f6; }
    .data-table-container th.sorted { color: #3b82f6; }
    .data-table-container .sort-indicator { font-size: 11px; margin-left: 4px; color: #9ca3af; }
    .data-table-container th.sorted .sort-indicator { color: #3b82f6; }
    .data-table-container td { padding: 10px 14px; border-bottom: 1px solid #f3f4f6; color: #374151; }
    .data-table-container tr:hover td { background: #f9fafb; }
    .data-table-container .pagination { display: flex; align-items: center; justify-content: space-between; margin-top: 16px; font-size: 14px; color: #6b7280; }
    .data-table-container .page-buttons { display: flex; gap: 4px; }
    .data-table-container .page-btn {
      padding: 6px 12px; border: 1px solid #e5e7eb; background: #fff; border-radius: 4px;
      font-size: 13px; cursor: pointer; color: #374151;
    }
    .data-table-container .page-btn:hover { background: #f3f4f6; }
    .data-table-container .page-btn.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }
  </style>
  <table>
    <thead>
      <tr>%s
      </tr>
    </thead>
    <tbody>%s
    </tbody>
  </table>
  <div class="pagination">
    <span>Showing %d-%d of %d results</span>
    <div class="page-buttons">
      %s
    </div>
  </div>
</div>`, headHTML.String(), bodyHTML.String(), (currentPage-1)*rows+1, currentPage*rows, totalPages*rows, pagesHTML.String())
}

// --------------------------------------------------------------------------
// 15. NotificationBanner
// --------------------------------------------------------------------------

// NotificationBanner generates an alert banner of a random type with close button.
func (e *Elements) NotificationBanner(rng *rand.Rand) string {
	types := []struct {
		Name, BgColor, BorderColor, TextColor, IconColor, Icon string
	}{
		{"info", "#eff6ff", "#bfdbfe", "#1e40af", "#3b82f6", "&#9432;"},
		{"success", "#f0fdf4", "#bbf7d0", "#166534", "#22c55e", "&#10003;"},
		{"warning", "#fffbeb", "#fde68a", "#92400e", "#f59e0b", "&#9888;"},
		{"error", "#fef2f2", "#fecaca", "#991b1b", "#ef4444", "&#10007;"},
	}
	t := types[rng.Intn(len(types))]

	messages := map[string][]string{
		"info": {
			"A new version is available. Please update to get the latest features and security patches.",
			"Scheduled maintenance is planned for this weekend. Service may be briefly interrupted.",
			"Your trial period will expire in 7 days. Upgrade now to keep full access.",
		},
		"success": {
			"Your changes have been saved successfully.",
			"Account verification complete. Welcome aboard!",
			"Payment processed. Your receipt has been sent to your email.",
		},
		"warning": {
			"Your API usage is approaching the monthly limit. Consider upgrading your plan.",
			"Some features may not work as expected in your current browser version.",
			"Your password has not been changed in over 90 days. Consider updating it.",
		},
		"error": {
			"Unable to connect to the server. Please check your internet connection and try again.",
			"An error occurred while processing your request. Our team has been notified.",
			"Your session has expired. Please log in again to continue.",
		},
	}
	msgList := messages[t.Name]
	msg := msgList[rng.Intn(len(msgList))]
	bannerID := fmt.Sprintf("notification-%d", rng.Intn(100000))

	return fmt.Sprintf(`<div class="notification-banner notification-%s" id="%s" role="alert">
  <style>
    .notification-banner {
      display: flex; align-items: flex-start; gap: 12px; padding: 14px 18px;
      border-radius: 8px; border: 1px solid; margin: 16px 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px; line-height: 1.5;
    }
    .notification-info { background: %s; border-color: %s; color: %s; }
    .notification-success { background: %s; border-color: %s; color: %s; }
    .notification-warning { background: %s; border-color: %s; color: %s; }
    .notification-error { background: %s; border-color: %s; color: %s; }
    .notification-banner .notif-icon { font-size: 18px; flex-shrink: 0; line-height: 1; margin-top: 1px; }
    .notification-banner .notif-message { flex: 1; }
    .notification-banner .notif-close {
      background: none; border: none; font-size: 18px; cursor: pointer; padding: 0; line-height: 1;
      color: inherit; opacity: 0.5; flex-shrink: 0;
    }
    .notification-banner .notif-close:hover { opacity: 1; }
  </style>
  <span class="notif-icon" style="color:%s;">%s</span>
  <span class="notif-message">%s</span>
  <button class="notif-close" type="button" aria-label="Close notification">&times;</button>
</div>`,
		t.Name, bannerID,
		types[0].BgColor, types[0].BorderColor, types[0].TextColor,
		types[1].BgColor, types[1].BorderColor, types[1].TextColor,
		types[2].BgColor, types[2].BorderColor, types[2].TextColor,
		types[3].BgColor, types[3].BorderColor, types[3].TextColor,
		t.IconColor, t.Icon, msg)
}

// --------------------------------------------------------------------------
// 16. Breadcrumbs
// --------------------------------------------------------------------------

// Breadcrumbs generates navigation breadcrumbs from a URL path.
func (e *Elements) Breadcrumbs(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")

	var crumbsHTML strings.Builder
	crumbsHTML.WriteString(`<a href="/" class="crumb">Home</a>`)

	accumulated := ""
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		accumulated += "/" + seg
		label := strings.ReplaceAll(seg, "-", " ")
		label = strings.ReplaceAll(label, "_", " ")
		// Title-case each word
		words := strings.Fields(label)
		for j, w := range words {
			if len(w) > 0 {
				words[j] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		label = strings.Join(words, " ")

		crumbsHTML.WriteString(`<span class="crumb-sep">&#8250;</span>`)
		if i == len(segments)-1 {
			// Last segment: not a link
			crumbsHTML.WriteString(fmt.Sprintf(`<span class="crumb current">%s</span>`, label))
		} else {
			crumbsHTML.WriteString(fmt.Sprintf(`<a href="%s" class="crumb">%s</a>`, accumulated, label))
		}
	}

	return fmt.Sprintf(`<nav class="breadcrumbs" aria-label="Breadcrumb">
  <style>
    .breadcrumbs {
      display: flex; align-items: center; gap: 6px; padding: 12px 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
    }
    .breadcrumbs .crumb { color: #6b7280; text-decoration: none; }
    .breadcrumbs .crumb:hover { color: #3b82f6; text-decoration: underline; }
    .breadcrumbs .crumb.current { color: #111827; font-weight: 500; cursor: default; }
    .breadcrumbs .crumb.current:hover { text-decoration: none; color: #111827; }
    .breadcrumbs .crumb-sep { color: #d1d5db; font-size: 16px; }
  </style>
  %s
</nav>`, crumbsHTML.String())
}

// --------------------------------------------------------------------------
// 17. ImagePlaceholder
// --------------------------------------------------------------------------

// ImagePlaceholder generates an SVG placeholder with random gradient and dimensions text.
func (e *Elements) ImagePlaceholder(rng *rand.Rand, width, height int) string {
	color1 := randHexColor(rng)
	color2 := randHexColor(rng)
	gradID := fmt.Sprintf("grad-%d", rng.Intn(100000))

	dimText := fmt.Sprintf("%d x %d", width, height)

	return fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="%s" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
      <stop offset="0%%" stop-color="%s"/>
      <stop offset="100%%" stop-color="%s"/>
    </linearGradient>
  </defs>
  <rect width="%d" height="%d" fill="url(#%s)"/>
  <text x="%d" y="%d" text-anchor="middle" dominant-baseline="central" fill="#fff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="%d" font-weight="600" opacity="0.7">%s</text>
</svg>`, width, height, width, height, gradID, color1, color2, width, height, gradID, width/2, height/2, width/20+10, dimText)
}

// --------------------------------------------------------------------------
// 18. SocialShareButtons
// --------------------------------------------------------------------------

// SocialShareButtons generates share buttons for major social platforms and email.
func (e *Elements) SocialShareButtons() string {
	return `<div class="social-share" aria-label="Share this page">
  <style>
    .social-share { display: flex; align-items: center; gap: 10px; padding: 12px 0; }
    .social-share .share-label { font-size: 14px; color: #6b7280; font-weight: 500; margin-right: 4px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .social-share a {
      display: inline-flex; align-items: center; justify-content: center;
      width: 36px; height: 36px; border-radius: 50%; text-decoration: none;
      transition: transform 0.15s, opacity 0.15s;
    }
    .social-share a:hover { transform: scale(1.1); opacity: 0.85; }
  </style>
  <span class="share-label">Share:</span>
  <a href="https://twitter.com/intent/tweet?url=" aria-label="Share on Twitter" title="Share on Twitter" style="background:#1da1f2;">
    <svg width="18" height="18" viewBox="0 0 18 18"><path d="M16 4.5c-.5.2-1.1.4-1.7.5.6-.4 1.1-.9 1.3-1.6-.6.3-1.2.6-1.9.7C13.1 3.4 12.2 3 11.2 3c-2 0-3.5 1.6-3.5 3.5 0 .3 0 .5.1.8C5.2 7.1 3 5.7 1.5 3.7c-.3.5-.5 1-.5 1.6 0 1.2.6 2.3 1.6 2.9-.6 0-1.1-.2-1.6-.4v0c0 1.7 1.2 3.1 2.8 3.4-.3.1-.6.1-.9.1-.2 0-.4 0-.6-.1.4 1.3 1.6 2.3 3.1 2.3-1.1.9-2.5 1.4-4.1 1.4-.3 0-.5 0-.8 0 1.5.9 3.2 1.5 5 1.5 6 0 9.3-5 9.3-9.3v-.4c.7-.5 1.2-1 1.7-1.7z" fill="#fff"/></svg>
  </a>
  <a href="https://www.facebook.com/sharer/sharer.php?u=" aria-label="Share on Facebook" title="Share on Facebook" style="background:#1877f2;">
    <svg width="18" height="18" viewBox="0 0 18 18"><path d="M10 18V9.8h2.8l.4-3.2H10V4.5c0-.9.3-1.6 1.6-1.6h1.7V.1C13 .1 12 0 10.8 0 8.4 0 6.8 1.5 6.8 4.1v2.4H4v3.2h2.8V18H10z" fill="#fff"/></svg>
  </a>
  <a href="https://www.linkedin.com/shareArticle?mini=true&url=" aria-label="Share on LinkedIn" title="Share on LinkedIn" style="background:#0a66c2;">
    <svg width="18" height="18" viewBox="0 0 18 18"><path d="M4.2 6.2H1V17h3.2V6.2zM2.6 1C1.5 1 .7 1.8.7 2.8S1.5 4.6 2.6 4.6c1.1 0 1.9-.8 1.9-1.8S3.7 1 2.6 1zM17.3 17h-3.2v-5.3c0-1.3 0-2.9-1.8-2.9-1.8 0-2 1.4-2 2.8V17H7.1V6.2h3.1v1.5c.4-.8 1.5-1.8 3-1.8 3.2 0 3.8 2.1 3.8 4.9V17h.3z" fill="#fff"/></svg>
  </a>
  <a href="https://www.reddit.com/submit?url=" aria-label="Share on Reddit" title="Share on Reddit" style="background:#ff4500;">
    <svg width="18" height="18" viewBox="0 0 18 18"><circle cx="9" cy="9" r="8" fill="none"/><path d="M15 9c0-.8-.7-1.5-1.5-1.5-.4 0-.8.2-1 .4-1-.7-2.4-1.2-3.9-1.2l.7-3.1 2.2.5c0 .7.5 1.2 1.2 1.2.7 0 1.2-.6 1.2-1.2 0-.7-.5-1.2-1.2-1.2-.5 0-.9.3-1.1.7L9.2 3c-.1 0-.2 0-.2.1 0 .1 0 .1-.1.2l-.8 3.5c-1.6.1-3 .5-4.1 1.2-.3-.3-.6-.4-1-.4C2.2 7.5 1.5 8.2 1.5 9c0 .5.3 1 .7 1.3 0 .2 0 .4 0 .6 0 2.7 3.1 4.9 7 4.9s7-2.2 7-4.9c0-.2 0-.4 0-.6.3-.3.6-.7.7-1.3h.1z" fill="#fff"/></svg>
  </a>
  <a href="mailto:?subject=Check%20this%20out&body=" aria-label="Share via Email" title="Share via Email" style="background:#6b7280;">
    <svg width="18" height="18" viewBox="0 0 18 18"><rect x="2" y="4" width="14" height="10" rx="2" fill="none" stroke="#fff" stroke-width="1.5"/><polyline points="2,4 9,10 16,4" fill="none" stroke="#fff" stroke-width="1.5"/></svg>
  </a>
</div>`
}

// --------------------------------------------------------------------------
// 19. Sidebar
// --------------------------------------------------------------------------

// Sidebar generates a sidebar with popular articles, categories, tags, and an ad placeholder.
func (e *Elements) Sidebar(rng *rand.Rand, links []NavItem) string {
	// Occasionally inject vuln endpoint links that look like real app pages
	if rng.Intn(3) == 0 {
		links = append(links, NavItem{Label: "Admin Panel", Href: "/vuln/dashboard/"})
	}
	if rng.Intn(3) == 0 {
		links = append(links, NavItem{Label: "System Settings", Href: "/vuln/settings/"})
	}
	if rng.Intn(4) == 0 {
		links = append(links, NavItem{Label: "User Management", Href: "/vuln/a01/"})
	}

	var articlesHTML strings.Builder
	for _, l := range links {
		articlesHTML.WriteString(fmt.Sprintf(`
      <li><a href="%s">%s</a></li>`, l.Href, l.Label))
	}

	categories := []string{
		"Engineering", "Product", "Design", "Security", "DevOps",
		"Data Science", "Machine Learning", "Infrastructure", "Open Source", "Culture",
	}
	rng.Shuffle(len(categories), func(i, j int) { categories[i], categories[j] = categories[j], categories[i] })
	numCats := rng.Intn(5) + 4
	if numCats > len(categories) {
		numCats = len(categories)
	}
	var catsHTML strings.Builder
	for _, cat := range categories[:numCats] {
		count := rng.Intn(50) + 1
		catsHTML.WriteString(fmt.Sprintf(`
      <li><a href="/category/%s">%s</a> <span class="cat-count">(%d)</span></li>`,
			strings.ToLower(strings.ReplaceAll(cat, " ", "-")), cat, count))
	}

	tags := []string{
		"go", "python", "kubernetes", "docker", "aws", "terraform",
		"ci/cd", "api", "graphql", "rest", "grpc", "testing",
		"monitoring", "logging", "security", "performance", "architecture",
		"microservices", "serverless", "edge", "wasm", "sql",
	}
	rng.Shuffle(len(tags), func(i, j int) { tags[i], tags[j] = tags[j], tags[i] })
	numTags := rng.Intn(8) + 6
	if numTags > len(tags) {
		numTags = len(tags)
	}
	var tagsHTML strings.Builder
	for _, tag := range tags[:numTags] {
		tagsHTML.WriteString(fmt.Sprintf(`
      <a href="/tag/%s" class="tag">%s</a>`, strings.ToLower(tag), tag))
	}

	adColor := randHexColor(rng)
	adText := fmt.Sprintf("%s %s - %s",
		e.words.Buzzwords[rng.Intn(len(e.words.Buzzwords))],
		e.words.Nouns[rng.Intn(len(e.words.Nouns))],
		e.words.Adjectives[rng.Intn(len(e.words.Adjectives))],
	)

	return fmt.Sprintf(`<aside class="sidebar">
  <style>
    .sidebar { width: 280px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 14px; }
    .sidebar .sidebar-section { margin-bottom: 28px; }
    .sidebar .sidebar-section h4 {
      font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;
      color: #6b7280; margin: 0 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb;
    }
    .sidebar .sidebar-section ul { list-style: none; padding: 0; margin: 0; }
    .sidebar .sidebar-section ul li { margin-bottom: 8px; }
    .sidebar .sidebar-section a { color: #374151; text-decoration: none; transition: color 0.15s; }
    .sidebar .sidebar-section a:hover { color: #3b82f6; }
    .sidebar .cat-count { color: #9ca3af; font-size: 12px; }
    .sidebar .tags-cloud { display: flex; flex-wrap: wrap; gap: 6px; }
    .sidebar .tag {
      display: inline-block; padding: 4px 10px; background: #f3f4f6; border-radius: 50px;
      font-size: 12px; color: #374151; text-decoration: none; transition: background 0.15s;
    }
    .sidebar .tag:hover { background: #e5e7eb; color: #111827; }
    .sidebar .ad-placeholder {
      padding: 20px; border-radius: 8px; text-align: center; color: #fff;
      font-size: 13px; font-weight: 500;
    }
  </style>
  <div class="sidebar-section">
    <h4>Popular Articles</h4>
    <ul>%s
    </ul>
  </div>
  <div class="sidebar-section">
    <h4>Categories</h4>
    <ul>%s
    </ul>
  </div>
  <div class="sidebar-section">
    <h4>Tags</h4>
    <div class="tags-cloud">%s
    </div>
  </div>
  <div class="sidebar-section">
    <div class="ad-placeholder" style="background:%s;">
      <p style="margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;opacity:0.7;">Advertisement</p>
      <p style="margin:0;font-size:15px;">%s</p>
      <a href="/sponsor" style="display:inline-block;margin-top:10px;padding:6px 16px;background:rgba(255,255,255,0.2);color:#fff;border-radius:4px;text-decoration:none;font-size:13px;">Learn More</a>
    </div>
  </div>
</aside>`, articlesHTML.String(), catsHTML.String(), tagsHTML.String(), adColor, adText)
}

// --------------------------------------------------------------------------
// 20. ArticleMetadata
// --------------------------------------------------------------------------

// ArticleMetadata generates author, date, read time, category, and share count info.
func (e *Elements) ArticleMetadata(rng *rand.Rand) string {
	author := e.words.RandName(rng)
	avatarColor := randHexColor(rng)
	initials := string(author[0]) + string([]rune(author)[strings.Index(author, " ")+1])
	pubDate := randDate(rng)
	readTime := rng.Intn(20) + 2
	category := e.words.Topics[rng.Intn(len(e.words.Topics))]
	shares := rng.Intn(5000)

	return fmt.Sprintf(`<div class="article-metadata">
  <style>
    .article-metadata {
      display: flex; align-items: center; flex-wrap: wrap; gap: 16px; padding: 14px 0;
      border-top: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb; margin: 16px 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px; color: #6b7280;
    }
    .article-metadata .meta-author { display: flex; align-items: center; gap: 8px; }
    .article-metadata .meta-author .author-name { color: #111827; font-weight: 500; }
    .article-metadata .meta-divider { width: 1px; height: 16px; background: #d1d5db; }
    .article-metadata .meta-category {
      display: inline-block; padding: 3px 10px; background: #eff6ff; color: #3b82f6;
      border-radius: 50px; font-size: 12px; font-weight: 500;
    }
    .article-metadata .meta-shares { display: flex; align-items: center; gap: 4px; }
  </style>
  <div class="meta-author">
    <svg width="32" height="32" viewBox="0 0 32 32"><circle cx="16" cy="16" r="16" fill="%s"/><text x="16" y="20" text-anchor="middle" fill="#fff" font-size="12" font-weight="600">%s</text></svg>
    <span class="author-name">%s</span>
  </div>
  <span class="meta-divider"></span>
  <span class="meta-date">%s</span>
  <span class="meta-divider"></span>
  <span class="meta-readtime">%d min read</span>
  <span class="meta-divider"></span>
  <span class="meta-category">%s</span>
  <span class="meta-divider"></span>
  <span class="meta-shares">
    <svg width="14" height="14" viewBox="0 0 14 14"><path d="M11 5c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2c0 .2 0 .3.1.5L5.5 5.7C5.1 5.3 4.6 5 4 5c-1.1 0-2 .9-2 2s.9 2 2 2c.6 0 1.1-.3 1.5-.7l3.6 2.2c0 .2-.1.3-.1.5 0 1.1.9 2 2 2s2-.9 2-2-.9-2-2-2c-.6 0-1.1.3-1.5.7L5.9 7.5c0-.2.1-.3.1-.5s0-.3-.1-.5l3.6-2.2c.4.4.9.7 1.5.7z" fill="#9ca3af"/></svg>
    %d shares
  </span>
</div>`, avatarColor, initials, author, pubDate.Format("January 2, 2006"), readTime, category, shares)
}
