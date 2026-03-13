# LinkedIn Post: Cloudflare Browser Rendering vs Adversarial Pages

I pointed Cloudflare's Browser Rendering API at an adversarial server. It didn't go well.

We're building Glitch — an open-source HTTP chaos testing framework that simulates broken, hostile, and deceptive web services. One of our newest modules targets headless Chrome crawlers specifically.

I wanted to see how Cloudflare's Browser Rendering API handles a website that fights back. Here's what happened:

**85 page renders turned into 7,345 requests.** That's an 86x amplification ratio. CF's headless Chrome executed every embedded `fetch()` call, loaded every hidden iframe, followed every generated link. One page = dozens of backend requests, with no server-side budget cap.

**The crawler went 19 levels deep into an infinite labyrinth.** Glitch generates procedural page graphs — deterministic, infinite, realistic-looking content with internal links. CF Chrome followed 3,838 labyrinth pages without any depth limit or loop detection kicking in.

**Network idle detection was defeated.** A small JS payload fires a fetch every 200–450ms, preventing Puppeteer's `networkidle2` from ever resolving. The crawler made 973 "heartbeat" requests trying to reach idle state. It never did.

**JS-based API discovery worked perfectly — against the crawler.** CF Chrome executed JavaScript and discovered 22 API endpoints that existed only in `fetch()` calls, not in HTML links. Routes like `/api/auth/status` and `/api/csrf-token` were all hit. Great for scraping. Also great for traps.

**Budget traps activated at scale.** 972 fake vulnerability breadcrumb hits. 208 tarpit connections (slow-drip responses holding connections open). The crawler followed every honey trail.

**ServiceWorker registration succeeded.** The chaos engine registered a SW via a real URL endpoint. Headless Chrome loaded and activated it. Once active, the SW intercepts all navigation and injects additional requests per page load.

**The takeaway:** If you're using browser-based crawling at scale — whether CF Browser Rendering, Puppeteer, or Playwright — the target website has significant leverage over your infrastructure. A single adversarial page can spiral your crawl budget, exhaust connections, and waste compute. The browser is doing exactly what it's designed to do: execute everything the page asks for.

This isn't a Cloudflare vulnerability — it's a fundamental challenge with browser-based crawling. But it means crawl orchestration needs its own defense layer: request budgets per page, depth limits, idle timeout overrides, and domain-level circuit breakers. The browser runtime won't protect you.

Glitch is open source. The browser chaos engine has 4 severity levels and targets every headless Chrome detection gap we could find — network idle stall, ServiceWorker poisoning, CSS rendering bombs, iframe amplification, memory pressure, and more.

#websecurity #crawling #cloudflare #headlesschrome #chaosengineering #appsec
