package content

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
)

// ThemeType identifies a visual theme.
type ThemeType string

const (
	ThemeSaaS       ThemeType = "saas"
	ThemeEcommerce  ThemeType = "ecommerce"
	ThemeSocial     ThemeType = "social"
	ThemeNews       ThemeType = "news"
	ThemeDocs       ThemeType = "docs"
	ThemeCorporate  ThemeType = "corporate"
	ThemeStartup    ThemeType = "startup"
	ThemeGovt       ThemeType = "govt"
	ThemeUniversity ThemeType = "university"
	ThemeBanking    ThemeType = "banking"
)

// AllThemes contains all available theme types.
var AllThemes = []ThemeType{
	ThemeSaaS,
	ThemeEcommerce,
	ThemeSocial,
	ThemeNews,
	ThemeDocs,
	ThemeCorporate,
	ThemeStartup,
	ThemeGovt,
	ThemeUniversity,
	ThemeBanking,
}

// ThemeForPath returns a deterministic theme based on the path using SHA-256.
func ThemeForPath(path string) ThemeType {
	h := sha256.Sum256([]byte(path))
	idx := binary.BigEndian.Uint64(h[:8]) % uint64(len(AllThemes))
	return AllThemes[idx]
}

// ThemeCSS returns a complete <style> block for the given theme.
func ThemeCSS(theme ThemeType) string {
	switch theme {
	case ThemeSaaS:
		return `<style>
  :root { --primary: #2563eb; --accent: #3b82f6; --bg: #f8fafc; --text: #1e293b; --nav-bg: #ffffff; --nav-text: #1e293b; --footer-bg: #f1f5f9; }
  body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1140px; margin: 0 auto; padding: 0 24px; }
  nav { background: var(--nav-bg); border-bottom: 1px solid #e2e8f0; padding: 14px 0; }
  nav a { color: var(--nav-text); margin-right: 20px; font-weight: 500; font-size: 0.95em; }
  .brand { font-weight: 700; font-size: 1.15em; color: var(--primary); }
  footer { background: var(--footer-bg); padding: 32px 0; margin-top: 48px; font-size: 0.9em; color: #64748b; }
  h1, h2, h3 { color: var(--text); }
  .btn { background: var(--primary); color: #fff; padding: 10px 22px; border-radius: 6px; display: inline-block; border: none; cursor: pointer; }
  .btn:hover { background: #1d4ed8; }
  .card { background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 16px; }
  .tag { background: #eff6ff; color: var(--primary); padding: 2px 10px; border-radius: 12px; font-size: 0.85em; display: inline-block; }
</style>`

	case ThemeEcommerce:
		return `<style>
  :root { --primary: #ea580c; --accent: #f97316; --bg: #fffbf5; --text: #292524; --nav-bg: #1c1917; --nav-text: #fafaf9; --footer-bg: #1c1917; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
  nav { background: var(--nav-bg); padding: 12px 0; }
  nav a { color: var(--nav-text); margin-right: 18px; font-size: 0.95em; }
  .brand { font-weight: 800; font-size: 1.2em; color: var(--accent); }
  footer { background: var(--footer-bg); color: #a8a29e; padding: 36px 0; margin-top: 40px; font-size: 0.9em; }
  h1, h2, h3 { color: var(--text); }
  .btn { background: var(--primary); color: #fff; padding: 10px 24px; border-radius: 4px; display: inline-block; border: none; cursor: pointer; font-weight: 600; }
  .btn:hover { background: #c2410c; }
  .card { background: #fff; border: 1px solid #fed7aa; border-radius: 6px; padding: 20px; margin-bottom: 16px; }
  .price { font-size: 1.5em; font-weight: 700; color: var(--primary); }
  .cart-icon { font-size: 1.2em; }
</style>`

	case ThemeSocial:
		return `<style>
  :root { --primary: #7c3aed; --accent: #a855f7; --bg: #faf5ff; --text: #1e1b4b; --nav-bg: linear-gradient(135deg, #7c3aed, #3b82f6); --nav-text: #ffffff; --footer-bg: #f5f3ff; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 960px; margin: 0 auto; padding: 0 20px; }
  nav { background: var(--nav-bg); padding: 14px 0; }
  nav a { color: var(--nav-text); margin-right: 18px; font-size: 0.95em; font-weight: 500; }
  .brand { font-weight: 800; font-size: 1.25em; color: #fff; letter-spacing: -0.5px; }
  footer { background: var(--footer-bg); padding: 30px 0; margin-top: 40px; font-size: 0.9em; color: #6b7280; }
  h1, h2, h3 { color: var(--text); }
  .btn { background: var(--primary); color: #fff; padding: 10px 22px; border-radius: 20px; display: inline-block; border: none; cursor: pointer; font-weight: 600; }
  .btn:hover { background: #6d28d9; }
  .card { background: #fff; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(124,58,237,0.08); margin-bottom: 16px; }
  .avatar { width: 40px; height: 40px; border-radius: 50%; background: var(--accent); display: inline-block; }
</style>`

	case ThemeNews:
		return `<style>
  :root { --primary: #b91c1c; --accent: #dc2626; --bg: #fff; --text: #1a1a1a; --nav-bg: #111827; --nav-text: #f9fafb; --footer-bg: #111827; }
  body { font-family: Georgia, 'Times New Roman', Times, serif; background: var(--bg); color: var(--text); line-height: 1.7; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1100px; margin: 0 auto; padding: 0 20px; }
  nav { background: var(--nav-bg); padding: 10px 0; border-bottom: 3px solid var(--accent); }
  nav a { color: var(--nav-text); margin-right: 20px; font-family: Arial, Helvetica, sans-serif; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px; }
  .brand { font-weight: 900; font-size: 1.6em; color: #fff; font-family: Georgia, serif; letter-spacing: -0.5px; }
  footer { background: var(--footer-bg); color: #9ca3af; padding: 32px 0; margin-top: 48px; font-size: 0.85em; font-family: Arial, Helvetica, sans-serif; }
  h1 { font-size: 2.4em; line-height: 1.2; } h2 { font-size: 1.5em; } h3 { font-size: 1.2em; }
  .byline { font-family: Arial, Helvetica, sans-serif; font-size: 0.9em; color: #6b7280; margin-bottom: 16px; }
  .card { background: #fff; border-bottom: 1px solid #e5e7eb; padding: 20px 0; margin-bottom: 8px; }
  .section-label { text-transform: uppercase; font-family: Arial, Helvetica, sans-serif; font-size: 0.75em; font-weight: 700; color: var(--accent); letter-spacing: 1px; border-bottom: 2px solid var(--accent); display: inline-block; margin-bottom: 12px; }
</style>`

	case ThemeDocs:
		return `<style>
  :root { --primary: #0284c7; --accent: #0ea5e9; --bg: #ffffff; --text: #334155; --nav-bg: #f8fafc; --nav-text: #334155; --footer-bg: #f8fafc; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.7; margin: 0; font-size: 15px; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1080px; margin: 0 auto; padding: 0 24px; }
  nav { background: var(--nav-bg); border-bottom: 1px solid #e2e8f0; padding: 10px 0; }
  nav a { color: var(--nav-text); margin-right: 20px; font-size: 0.9em; }
  .brand { font-weight: 700; font-size: 1.1em; color: var(--primary); font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; }
  footer { background: var(--footer-bg); padding: 24px 0; margin-top: 40px; font-size: 0.85em; color: #94a3b8; border-top: 1px solid #e2e8f0; }
  h1 { font-size: 1.8em; margin-bottom: 0.4em; } h2 { font-size: 1.4em; margin-top: 1.8em; } h3 { font-size: 1.15em; }
  code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; font-family: 'SF Mono', 'Fira Code', Consolas, monospace; }
  pre { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 20px; margin-bottom: 16px; }
  .sidebar-nav { font-size: 0.9em; } .sidebar-nav a { display: block; padding: 6px 0; color: var(--text); }
</style>`

	case ThemeCorporate:
		return `<style>
  :root { --primary: #1e40af; --accent: #2563eb; --bg: #f9fafb; --text: #1f2937; --nav-bg: #1e3a5f; --nav-text: #f0f4f8; --footer-bg: #1e3a5f; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
  nav { background: var(--nav-bg); padding: 14px 0; }
  nav a { color: var(--nav-text); margin-right: 22px; font-size: 0.9em; }
  .brand { font-weight: 700; font-size: 1.15em; color: #fff; letter-spacing: 0.3px; }
  footer { background: var(--footer-bg); color: #94a3b8; padding: 36px 0; margin-top: 48px; font-size: 0.85em; }
  h1, h2, h3 { color: #111827; }
  .btn { background: var(--primary); color: #fff; padding: 12px 28px; border-radius: 4px; display: inline-block; border: none; cursor: pointer; font-weight: 500; text-transform: uppercase; font-size: 0.9em; letter-spacing: 0.5px; }
  .btn:hover { background: #1e3a8a; }
  .card { background: #fff; border: 1px solid #d1d5db; border-radius: 4px; padding: 24px; margin-bottom: 16px; }
  hr { border: none; border-top: 1px solid #d1d5db; margin: 24px 0; }
</style>`

	case ThemeStartup:
		return `<style>
  :root { --primary: #8b5cf6; --accent: #ec4899; --bg: #fefce8; --text: #1c1917; --nav-bg: linear-gradient(135deg, #8b5cf6, #ec4899); --nav-text: #ffffff; --footer-bg: #18181b; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { opacity: 0.8; }
  .container { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
  nav { background: var(--nav-bg); padding: 14px 0; }
  nav a { color: var(--nav-text); margin-right: 20px; font-size: 0.95em; font-weight: 500; }
  .brand { font-weight: 800; font-size: 1.3em; color: #fff; }
  footer { background: var(--footer-bg); color: #a1a1aa; padding: 36px 0; margin-top: 48px; font-size: 0.9em; }
  h1 { font-size: 2.5em; line-height: 1.15; } h2 { font-size: 1.6em; } h3 { font-size: 1.2em; }
  .btn { background: linear-gradient(135deg, var(--primary), var(--accent)); color: #fff; padding: 12px 28px; border-radius: 24px; display: inline-block; border: none; cursor: pointer; font-weight: 600; font-size: 1em; }
  .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(139,92,246,0.3); }
  .card { background: #fff; border-radius: 16px; padding: 28px; box-shadow: 0 4px 16px rgba(0,0,0,0.06); margin-bottom: 20px; }
  .gradient-text { background: linear-gradient(135deg, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
</style>`

	case ThemeGovt:
		return `<style>
  :root { --primary: #1a4480; --accent: #005ea2; --bg: #f0f0f0; --text: #1b1b1b; --nav-bg: #1b1b1b; --nav-text: #f0f0f0; --footer-bg: #1b1b1b; }
  body { font-family: 'Source Sans Pro', 'Helvetica Neue', Helvetica, Roboto, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; font-size: 16px; }
  a { color: var(--accent); text-decoration: underline; } a:hover { color: var(--primary); }
  .container { max-width: 1040px; margin: 0 auto; padding: 0 20px; }
  nav { background: var(--nav-bg); padding: 8px 0; border-bottom: none; }
  nav a { color: var(--nav-text); margin-right: 16px; font-size: 0.9em; text-decoration: none; }
  .brand { font-weight: 700; font-size: 1.05em; color: #fff; }
  .usa-banner { background: #f0f0f0; font-size: 0.8em; padding: 4px 0; color: #1b1b1b; border-bottom: 1px solid #dfe1e2; }
  footer { background: var(--footer-bg); color: #a9aeb1; padding: 32px 0; margin-top: 40px; font-size: 0.85em; }
  h1, h2, h3 { color: var(--primary); }
  .btn { background: var(--accent); color: #fff; padding: 10px 20px; border-radius: 2px; display: inline-block; border: none; cursor: pointer; font-weight: 600; }
  .btn:hover { background: var(--primary); }
  .card { background: #fff; border: 1px solid #dfe1e2; border-radius: 0; padding: 20px; margin-bottom: 16px; }
  .alert { background: #faf3d1; border-left: 4px solid #ffbe2e; padding: 12px 16px; margin-bottom: 16px; }
</style>`

	case ThemeUniversity:
		return `<style>
  :root { --primary: #14532d; --accent: #7f1d1d; --bg: #fafaf9; --text: #292524; --nav-bg: #14532d; --nav-text: #ecfdf5; --footer-bg: #14532d; }
  body { font-family: 'Palatino Linotype', Palatino, 'Book Antiqua', Georgia, serif; background: var(--bg); color: var(--text); line-height: 1.7; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 1060px; margin: 0 auto; padding: 0 24px; }
  nav { background: var(--nav-bg); padding: 12px 0; }
  nav a { color: var(--nav-text); margin-right: 20px; font-size: 0.9em; font-family: Arial, Helvetica, sans-serif; }
  .brand { font-weight: 700; font-size: 1.15em; color: #fff; }
  .sub-brand { font-size: 0.8em; color: #bbf7d0; display: block; font-family: Arial, sans-serif; }
  footer { background: var(--footer-bg); color: #86efac; padding: 32px 0; margin-top: 48px; font-size: 0.85em; font-family: Arial, Helvetica, sans-serif; }
  h1 { font-size: 2em; color: var(--primary); } h2 { font-size: 1.5em; color: var(--accent); } h3 { font-size: 1.15em; }
  .btn { background: var(--accent); color: #fff; padding: 10px 24px; border-radius: 4px; display: inline-block; border: none; cursor: pointer; font-family: Arial, sans-serif; font-weight: 600; }
  .btn:hover { background: #991b1b; }
  .card { background: #fff; border: 1px solid #d6d3d1; border-radius: 4px; padding: 24px; margin-bottom: 16px; }
  .crest { font-size: 0.75em; text-transform: uppercase; letter-spacing: 1.5px; color: var(--accent); font-family: Arial, sans-serif; }
</style>`

	case ThemeBanking:
		return `<style>
  :root { --primary: #1e3a5f; --accent: #b8860b; --bg: #f5f5f0; --text: #1a1a2e; --nav-bg: #0c1b33; --nav-text: #e8e6e1; --footer-bg: #0c1b33; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; }
  a { color: var(--primary); text-decoration: none; } a:hover { color: var(--accent); }
  .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
  nav { background: var(--nav-bg); padding: 14px 0; border-bottom: 2px solid var(--accent); }
  nav a { color: var(--nav-text); margin-right: 22px; font-size: 0.9em; }
  .brand { font-weight: 700; font-size: 1.15em; color: var(--accent); letter-spacing: 0.5px; }
  footer { background: var(--footer-bg); color: #8896a7; padding: 36px 0; margin-top: 48px; font-size: 0.85em; border-top: 2px solid var(--accent); }
  h1, h2, h3 { color: var(--primary); }
  .btn { background: var(--primary); color: #fff; padding: 12px 28px; border-radius: 3px; display: inline-block; border: none; cursor: pointer; font-weight: 500; letter-spacing: 0.3px; }
  .btn:hover { background: #15304f; }
  .btn-gold { background: var(--accent); color: #fff; } .btn-gold:hover { background: #996f00; }
  .card { background: #fff; border: 1px solid #d1d5db; border-radius: 4px; padding: 24px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .secure-badge { font-size: 0.8em; color: var(--primary); font-weight: 600; }
  .notice { background: #fefce8; border-left: 3px solid var(--accent); padding: 10px 14px; font-size: 0.9em; margin-bottom: 16px; }
</style>`

	default:
		// Fallback to SaaS theme for unknown types.
		return ThemeCSS(ThemeSaaS)
	}
}

// ThemeHeader returns the theme-appropriate HTML header/nav bar.
func ThemeHeader(theme ThemeType, rng *rand.Rand) string {
	navLinks := themeNavLinks(theme, rng)

	switch theme {
	case ThemeSaaS:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">Acme Cloud</span>
    <div>%s</div>
    <div><a href="/login" class="btn" style="font-size:0.9em;padding:6px 16px;">Sign In</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeEcommerce:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">MegaShop</span>
    <div>%s</div>
    <div><a href="/cart" style="color:#fafaf9;"><span class="cart-icon">&#128722;</span> Cart (0)</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeSocial:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">ConnectHub</span>
    <div>%s</div>
    <div><a href="/profile" class="btn" style="font-size:0.85em;padding:6px 18px;">My Profile</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeNews:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">Daily Chronicle</span>
    <div>%s</div>
    <div><a href="/subscribe" style="color:#fafaf9;font-size:0.9em;font-family:Arial,sans-serif;">Subscribe</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeDocs:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">&gt;_ DevDocs</span>
    <div>%s</div>
    <div><input type="search" placeholder="Search docs..." style="padding:5px 10px;border:1px solid #e2e8f0;border-radius:4px;font-size:0.85em;"></div>
  </div></nav>
</header>`, navLinks)

	case ThemeCorporate:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">Meridian Corp</span>
    <div>%s</div>
    <div><a href="/contact" class="btn" style="font-size:0.85em;padding:8px 18px;">Contact Us</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeStartup:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">LaunchPad &#127640;</span>
    <div>%s</div>
    <div><a href="/signup" class="btn" style="font-size:0.85em;padding:8px 20px;">Get Started Free</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeGovt:
		return fmt.Sprintf(`<div class="usa-banner"><div class="container">An official website of the United States government</div></div>
<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">Federal Services Portal</span>
    <div>%s</div>
  </div></nav>
</header>`, navLinks)

	case ThemeUniversity:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <div><span class="brand">Westfield University</span><span class="sub-brand">Est. 1847</span></div>
    <div>%s</div>
    <div><a href="/apply" class="btn" style="font-size:0.85em;padding:8px 18px;">Apply Now</a></div>
  </div></nav>
</header>`, navLinks)

	case ThemeBanking:
		return fmt.Sprintf(`<header>
  <nav><div class="container" style="display:flex;align-items:center;justify-content:space-between;">
    <span class="brand">&#128274; SecureBank</span>
    <div>%s</div>
    <div><a href="/login" class="btn btn-gold" style="font-size:0.85em;padding:8px 20px;">Online Banking</a></div>
  </div></nav>
</header>`, navLinks)

	default:
		return ThemeHeader(ThemeSaaS, rng)
	}
}

// ThemeFooter returns the theme-appropriate HTML footer.
func ThemeFooter(theme ThemeType) string {
	switch theme {
	case ThemeSaaS:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 Acme Cloud, Inc. All rights reserved.</div>
    <div><a href="/privacy" style="color:#94a3b8;margin-right:16px;">Privacy</a><a href="/terms" style="color:#94a3b8;margin-right:16px;">Terms</a><a href="/status" style="color:#94a3b8;">Status</a></div>
  </div>
</footer>`

	case ThemeEcommerce:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 MegaShop. All rights reserved.</div>
    <div><a href="/returns" style="color:#a8a29e;margin-right:16px;">Returns</a><a href="/shipping" style="color:#a8a29e;margin-right:16px;">Shipping</a><a href="/privacy" style="color:#a8a29e;">Privacy Policy</a></div>
  </div>
</footer>`

	case ThemeSocial:
		return `<footer>
  <div class="container" style="text-align:center;">
    <div>&copy; 2025 ConnectHub. Connecting people everywhere.</div>
    <div style="margin-top:8px;"><a href="/privacy" style="color:#6b7280;margin-right:14px;">Privacy</a><a href="/terms" style="color:#6b7280;margin-right:14px;">Terms</a><a href="/community" style="color:#6b7280;">Community Guidelines</a></div>
  </div>
</footer>`

	case ThemeNews:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 Daily Chronicle Media Group</div>
    <div><a href="/about" style="color:#9ca3af;margin-right:14px;">About</a><a href="/ethics" style="color:#9ca3af;margin-right:14px;">Ethics Policy</a><a href="/corrections" style="color:#9ca3af;margin-right:14px;">Corrections</a><a href="/privacy" style="color:#9ca3af;">Privacy</a></div>
  </div>
</footer>`

	case ThemeDocs:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 DevDocs. Built for developers.</div>
    <div><a href="/changelog" style="color:#94a3b8;margin-right:14px;">Changelog</a><a href="/api" style="color:#94a3b8;margin-right:14px;">API Reference</a><a href="/privacy" style="color:#94a3b8;margin-right:14px;">Privacy</a><a href="/github" style="color:#94a3b8;">GitHub</a></div>
  </div>
</footer>`

	case ThemeCorporate:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 Meridian Corporation. All rights reserved.</div>
    <div><a href="/privacy" style="color:#94a3b8;margin-right:14px;">Privacy Policy</a><a href="/terms" style="color:#94a3b8;margin-right:14px;">Terms of Use</a><a href="/compliance" style="color:#94a3b8;">Compliance</a></div>
  </div>
</footer>`

	case ThemeStartup:
		return `<footer>
  <div class="container" style="text-align:center;">
    <div>&copy; 2025 LaunchPad, Inc. Built with passion.</div>
    <div style="margin-top:8px;"><a href="/privacy" style="color:#a1a1aa;margin-right:14px;">Privacy</a><a href="/terms" style="color:#a1a1aa;margin-right:14px;">Terms</a><a href="/blog" style="color:#a1a1aa;">Blog</a></div>
  </div>
</footer>`

	case ThemeGovt:
		return `<footer>
  <div class="container">
    <div style="margin-bottom:12px;font-weight:600;color:#d1d5db;">Federal Services Portal</div>
    <div><a href="/accessibility" style="color:#a9aeb1;margin-right:14px;">Accessibility</a><a href="/foia" style="color:#a9aeb1;margin-right:14px;">FOIA</a><a href="/privacy" style="color:#a9aeb1;margin-right:14px;">Privacy Policy</a><a href="/inspector-general" style="color:#a9aeb1;">Inspector General</a></div>
    <div style="margin-top:12px;font-size:0.8em;">&copy; 2025 Federal Services Portal. An official website of the United States government.</div>
  </div>
</footer>`

	case ThemeUniversity:
		return `<footer>
  <div class="container" style="display:flex;justify-content:space-between;flex-wrap:wrap;">
    <div>&copy; 2025 Westfield University. All rights reserved.</div>
    <div><a href="/admissions" style="color:#86efac;margin-right:14px;">Admissions</a><a href="/privacy" style="color:#86efac;margin-right:14px;">Privacy</a><a href="/accessibility" style="color:#86efac;margin-right:14px;">Accessibility</a><a href="/accreditation" style="color:#86efac;">Accreditation</a></div>
  </div>
</footer>`

	case ThemeBanking:
		return `<footer>
  <div class="container">
    <div style="margin-bottom:10px;">&copy; 2025 SecureBank, N.A. Member FDIC. Equal Housing Lender.</div>
    <div><a href="/privacy" style="color:#8896a7;margin-right:14px;">Privacy Policy</a><a href="/security" style="color:#8896a7;margin-right:14px;">Security</a><a href="/disclosures" style="color:#8896a7;margin-right:14px;">Disclosures</a><a href="/accessibility" style="color:#8896a7;">Accessibility</a></div>
    <div class="notice" style="margin-top:14px;background:transparent;border-left-color:#8896a7;color:#8896a7;padding:0;">FDIC-insured. Deposits are backed by the full faith and credit of the U.S. government.</div>
  </div>
</footer>`

	default:
		return ThemeFooter(ThemeSaaS)
	}
}

// ThemeMeta returns theme-appropriate meta tags.
func ThemeMeta(theme ThemeType, title string) string {
	safeTitle := escHTML(title)

	switch theme {
	case ThemeSaaS:
		return fmt.Sprintf(`<meta property="og:site_name" content="Acme Cloud">
  <meta name="application-name" content="Acme Cloud">
  <meta name="theme-color" content="#2563eb">
  <meta property="og:title" content="%s - Acme Cloud">
  <meta name="description" content="Acme Cloud - Modern cloud platform for teams of all sizes.">`, safeTitle)

	case ThemeEcommerce:
		return fmt.Sprintf(`<meta property="og:site_name" content="MegaShop">
  <meta name="application-name" content="MegaShop">
  <meta name="theme-color" content="#ea580c">
  <meta property="og:title" content="%s - MegaShop">
  <meta name="description" content="MegaShop - Your one-stop destination for everything you need.">`, safeTitle)

	case ThemeSocial:
		return fmt.Sprintf(`<meta property="og:site_name" content="ConnectHub">
  <meta name="application-name" content="ConnectHub">
  <meta name="theme-color" content="#7c3aed">
  <meta property="og:title" content="%s - ConnectHub">
  <meta name="description" content="ConnectHub - Connect with friends, share moments, build communities.">`, safeTitle)

	case ThemeNews:
		return fmt.Sprintf(`<meta property="og:site_name" content="Daily Chronicle">
  <meta name="application-name" content="Daily Chronicle">
  <meta name="theme-color" content="#111827">
  <meta property="og:title" content="%s - Daily Chronicle">
  <meta name="description" content="Daily Chronicle - Breaking news, in-depth reporting, and analysis.">`, safeTitle)

	case ThemeDocs:
		return fmt.Sprintf(`<meta property="og:site_name" content="DevDocs">
  <meta name="application-name" content="DevDocs">
  <meta name="theme-color" content="#0284c7">
  <meta property="og:title" content="%s - DevDocs">
  <meta name="description" content="DevDocs - Comprehensive developer documentation and API references.">`, safeTitle)

	case ThemeCorporate:
		return fmt.Sprintf(`<meta property="og:site_name" content="Meridian Corp">
  <meta name="application-name" content="Meridian Corp">
  <meta name="theme-color" content="#1e3a5f">
  <meta property="og:title" content="%s - Meridian Corp">
  <meta name="description" content="Meridian Corporation - Trusted solutions for enterprise and government.">`, safeTitle)

	case ThemeStartup:
		return fmt.Sprintf(`<meta property="og:site_name" content="LaunchPad">
  <meta name="application-name" content="LaunchPad">
  <meta name="theme-color" content="#8b5cf6">
  <meta property="og:title" content="%s - LaunchPad">
  <meta name="description" content="LaunchPad - The fastest way to build and ship your next big idea.">`, safeTitle)

	case ThemeGovt:
		return fmt.Sprintf(`<meta property="og:site_name" content="Federal Services Portal">
  <meta name="application-name" content="Federal Services Portal">
  <meta name="theme-color" content="#1b1b1b">
  <meta property="og:title" content="%s - Federal Services Portal">
  <meta name="description" content="Federal Services Portal - Official U.S. government services and information.">`, safeTitle)

	case ThemeUniversity:
		return fmt.Sprintf(`<meta property="og:site_name" content="Westfield University">
  <meta name="application-name" content="Westfield University">
  <meta name="theme-color" content="#14532d">
  <meta property="og:title" content="%s - Westfield University">
  <meta name="description" content="Westfield University - Excellence in education since 1847.">`, safeTitle)

	case ThemeBanking:
		return fmt.Sprintf(`<meta property="og:site_name" content="SecureBank">
  <meta name="application-name" content="SecureBank">
  <meta name="theme-color" content="#0c1b33">
  <meta property="og:title" content="%s - SecureBank">
  <meta name="description" content="SecureBank - Secure, reliable banking for individuals and businesses.">`, safeTitle)

	default:
		return ThemeMeta(ThemeSaaS, title)
	}
}

// themeNavLinks generates navigation link HTML for the given theme.
func themeNavLinks(theme ThemeType, rng *rand.Rand) string {
	var labels []string

	switch theme {
	case ThemeSaaS:
		labels = []string{"Products", "Solutions", "Pricing", "Docs", "Blog"}
	case ThemeEcommerce:
		labels = []string{"Shop", "Deals", "Categories", "Brands", "New Arrivals"}
	case ThemeSocial:
		labels = []string{"Feed", "Explore", "Messages", "Groups", "Events"}
	case ThemeNews:
		labels = []string{"World", "Politics", "Business", "Tech", "Opinion"}
	case ThemeDocs:
		labels = []string{"Guides", "API", "CLI", "SDKs", "Examples"}
	case ThemeCorporate:
		labels = []string{"About", "Services", "Industries", "Insights", "Careers"}
	case ThemeStartup:
		labels = []string{"Product", "Features", "Pricing", "About", "Blog"}
	case ThemeGovt:
		labels = []string{"Services", "Forms", "Agency Info", "Help", "Contact"}
	case ThemeUniversity:
		labels = []string{"Academics", "Admissions", "Research", "Campus Life", "Athletics"}
	case ThemeBanking:
		labels = []string{"Personal", "Business", "Wealth", "Loans", "Locations"}
	default:
		labels = []string{"Home", "About", "Services", "Blog", "Contact"}
	}

	// Optionally shuffle to add variety based on rng.
	if rng.Intn(3) == 0 {
		rng.Shuffle(len(labels), func(i, j int) {
			labels[i], labels[j] = labels[j], labels[i]
		})
	}

	var result string
	for _, label := range labels {
		href := "/" + slugify(label)
		result += fmt.Sprintf(`<a href="%s">%s</a>`, href, label)
	}
	return result
}
