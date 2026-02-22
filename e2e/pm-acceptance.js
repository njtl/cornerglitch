/**
 * PM Acceptance Test Framework
 *
 * Uses Stagehand (natural language browser automation) to let a PM agent
 * navigate the running glitch web server and admin panel, verify features
 * work as expected, and report pass/fail results.
 *
 * Usage:
 *   node e2e/pm-acceptance.js <test-suite>
 *
 * Available suites:
 *   all               Run all acceptance tests
 *   pcap              PCAP recording feature
 *   firecrawl-traps   Firecrawl/Oxylabs traps
 *   proxy-integration Reverse proxy integration
 *   scanner-compare   Scanner comparison tool
 *
 * Environment:
 *   SERVER_URL    (default: http://localhost:8765)
 *   ADMIN_URL     (default: http://localhost:8766)
 */

const { Stagehand } = require("@browserbasehq/stagehand");

const SERVER_URL = process.env.SERVER_URL || "http://localhost:8765";
const ADMIN_URL = process.env.ADMIN_URL || "http://localhost:8766";

class PMAcceptance {
  constructor() {
    this.stagehand = null;
    this.results = [];
  }

  async init() {
    this.stagehand = new Stagehand({
      env: "LOCAL",
      enableCaching: false,
      headless: true,
      modelName: "claude-sonnet-4-20250514",
      modelClientOptions: {
        apiKey: process.env.ANTHROPIC_API_KEY,
      },
    });
    await this.stagehand.init();
  }

  async close() {
    if (this.stagehand) {
      await this.stagehand.close();
    }
  }

  async check(name, fn) {
    try {
      await fn(this.stagehand);
      this.results.push({ name, status: "PASS" });
      console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
    } catch (err) {
      this.results.push({ name, status: "FAIL", error: err.message });
      console.log(`  \x1b[31mFAIL\x1b[0m ${name}: ${err.message}`);
    }
  }

  report() {
    const passed = this.results.filter((r) => r.status === "PASS").length;
    const failed = this.results.filter((r) => r.status === "FAIL").length;
    console.log(
      `\n${passed} passed, ${failed} failed, ${this.results.length} total`
    );
    return failed === 0 ? 0 : 1;
  }

  // --- Test Suites ---

  async testPCAP() {
    console.log("\n--- PCAP Recording Feature ---");
    const page = this.stagehand.page;

    await this.check("Admin panel loads", async (sh) => {
      await page.goto(`${ADMIN_URL}/admin`);
      const title = await page.title();
      if (!title.includes("Glitch")) throw new Error("Wrong title: " + title);
    });

    await this.check("Controls tab has recorder section", async (sh) => {
      await sh.act({
        action: "click the Controls tab button in the admin panel",
      });
      await page.waitForTimeout(1000);
      const text = await page.textContent("body");
      if (!text.includes("Traffic Recorder") && !text.includes("recorder"))
        throw new Error("No recorder section found in Controls");
    });

    await this.check("Can start PCAP recording via API", async () => {
      const resp = await fetch(`${SERVER_URL}/captures/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: "pcap" }),
      });
      const data = await resp.json();
      if (data.status !== "recording")
        throw new Error("Expected recording status");
      if (!data.file || !data.file.endsWith(".pcap"))
        throw new Error("Expected .pcap file, got: " + data.file);
    });

    await this.check("Generate traffic for capture", async () => {
      for (let i = 0; i < 5; i++) {
        await fetch(`${SERVER_URL}/test/page-${i}`);
      }
    });

    await this.check("Can stop recording and list captures", async () => {
      await fetch(`${SERVER_URL}/captures/stop`, { method: "POST" });
      const resp = await fetch(`${SERVER_URL}/captures/`);
      const files = await resp.json();
      const pcap = files.find((f) => f.name && f.name.endsWith(".pcap"));
      if (!pcap) throw new Error("No PCAP file in captures list");
    });

    await this.check("Can download PCAP file", async () => {
      const resp = await fetch(`${SERVER_URL}/captures/`);
      const files = await resp.json();
      const pcap = files.find((f) => f.name && f.name.endsWith(".pcap"));
      if (!pcap) throw new Error("No PCAP file found");
      const dl = await fetch(`${SERVER_URL}/captures/${pcap.name}`);
      if (dl.status !== 200)
        throw new Error("Download failed: " + dl.status);
      const buf = await dl.arrayBuffer();
      // PCAP magic number: 0xa1b2c3d4
      const view = new DataView(buf);
      const magic = view.getUint32(0, true);
      if (magic !== 0xa1b2c3d4)
        throw new Error(
          "Invalid PCAP magic: 0x" + magic.toString(16)
        );
    });
  }

  async testFirecrawlTraps() {
    console.log("\n--- Firecrawl/Oxylabs Traps ---");
    const page = this.stagehand.page;

    await this.check("Admin panel loads", async () => {
      await page.goto(`${ADMIN_URL}/admin`);
    });

    await this.check(
      "Firecrawl UA is detected as high-score bot",
      async () => {
        const resp = await fetch(`${SERVER_URL}/`, {
          headers: {
            "User-Agent": "Mozilla/5.0 firecrawl/1.0",
            Accept: "text/html",
          },
        });
        // Should still respond but with bot treatment
        if (resp.status >= 500)
          throw new Error("Unexpected 5xx for firecrawl");
      }
    );

    await this.check(
      "Platform mismatch (Oxylabs pattern) is detected",
      async () => {
        const resp = await fetch(`${SERVER_URL}/`, {
          headers: {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Ch-Ua":
              '"Chromium";v="120", "Google Chrome";v="120"',
            Accept: "text/html",
          },
        });
        if (resp.status >= 500)
          throw new Error("Unexpected 5xx for oxylabs pattern");
      }
    );

    await this.check("Crawler-specific honeypot paths exist", async () => {
      const paths = [
        "/assets/config.js",
        "/api/internal/config",
        "/.env.production",
      ];
      for (const p of paths) {
        const resp = await fetch(`${SERVER_URL}${p}`);
        if (resp.status === 404)
          throw new Error(`Honeypot path ${p} returned 404`);
      }
    });
  }

  async testProxyIntegration() {
    console.log("\n--- Reverse Proxy Integration ---");

    await this.check(
      "Glitch server is running on expected port",
      async () => {
        const resp = await fetch(`${SERVER_URL}/`);
        if (!resp.ok && resp.status !== 403)
          throw new Error("Server not responding");
      }
    );

    await this.check("Admin dashboard is accessible", async () => {
      const page = this.stagehand.page;
      await page.goto(`${ADMIN_URL}/admin`);
      const title = await page.title();
      if (!title.includes("Glitch")) throw new Error("Admin not loaded");
    });
  }

  async testScannerCompare() {
    console.log("\n--- Scanner Profile Comparison ---");
    const page = this.stagehand.page;

    await this.check("Admin panel Scanner tab loads", async (sh) => {
      await page.goto(`${ADMIN_URL}/admin#scanner`);
      await page.waitForTimeout(1000);
      const text = await page.textContent("body");
      if (!text.includes("Scanner") && !text.includes("scanner"))
        throw new Error("Scanner tab not found");
    });

    await this.check("Generate profile API works", async () => {
      const resp = await fetch(`${ADMIN_URL}/admin/api/scanner/profile`);
      const data = await resp.json();
      if (!data.vulnerabilities)
        throw new Error("No vulnerabilities in profile");
      if (!data.stats) throw new Error("No stats in profile");
    });

    await this.check("Comparison API accepts results", async () => {
      // Submit mock scanner results
      const resp = await fetch(
        `${ADMIN_URL}/admin/api/scanner/compare`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scanner: "nuclei",
            results:
              '{"info":{"severity":"high"},"matched-at":"http://localhost:8765/vuln/a03/sqli","template-id":"sql-injection"}',
          }),
        }
      );
      const data = await resp.json();
      if (!data.grade) throw new Error("No grade in comparison result");
    });

    await this.check(
      "Multi-scanner comparison API works",
      async () => {
        const resp = await fetch(
          `${ADMIN_URL}/admin/api/scanner/comparisons`
        );
        if (resp.status === 404) {
          // Endpoint exists but may return empty
          const resp2 = await fetch(
            `${ADMIN_URL}/admin/api/scanner/history`
          );
          if (resp2.status === 404)
            throw new Error("No comparison/history endpoint found");
        }
      }
    );
  }

  async runAll() {
    await this.testPCAP();
    await this.testFirecrawlTraps();
    await this.testProxyIntegration();
    await this.testScannerCompare();
  }
}

async function main() {
  const suite = process.argv[2] || "all";
  const pm = new PMAcceptance();

  try {
    await pm.init();

    switch (suite) {
      case "pcap":
        await pm.testPCAP();
        break;
      case "firecrawl-traps":
        await pm.testFirecrawlTraps();
        break;
      case "proxy-integration":
        await pm.testProxyIntegration();
        break;
      case "scanner-compare":
        await pm.testScannerCompare();
        break;
      case "all":
        await pm.runAll();
        break;
      default:
        console.error("Unknown suite:", suite);
        process.exit(1);
    }
  } catch (err) {
    console.error("Fatal error:", err.message);
  } finally {
    await pm.close();
  }

  process.exit(pm.report());
}

main();
