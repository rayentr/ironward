import { test } from "node:test";
import assert from "node:assert/strict";
import { scanUrl, type FetchLike } from "../src/engines/url-scanner.ts";

interface FakeResponse {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
}

function makeFetch(responses: Record<string, FakeResponse>): { fetch: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url) => {
    calls.push(url);
    const r = responses[url] ?? responses["*"] ?? { status: 404, body: "Not Found" };
    return {
      ok: (r.status ?? 200) < 400,
      status: r.status ?? 200,
      url,
      headers: r.headers ?? {},
      text: async () => r.body ?? "",
    };
  };
  return { fetch: fetchImpl, calls };
}

test("flags missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": { status: 200, headers: {}, body: "hi" },
    "*": { status: 404, body: "" },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  const ids = out.findings.map((f) => f.id).sort();
  assert.ok(ids.includes("missing-csp"));
  assert.ok(ids.includes("missing-hsts"));
  assert.ok(ids.includes("missing-frame-protection"));
  assert.ok(ids.includes("missing-nosniff"));
});

test("does not flag headers when present and strong", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
      },
      body: "hi",
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  const ids = out.findings.map((f) => f.id);
  assert.ok(!ids.includes("missing-csp"));
  assert.ok(!ids.includes("missing-hsts"));
  assert.ok(!ids.includes("missing-frame-protection"));
});

test("flags unsafe-inline / unsafe-eval in CSP", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: { "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" },
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  assert.ok(out.findings.some((f) => f.id === "weak-csp"));
});

test("flags session cookie without HttpOnly", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: { "set-cookie": "sessionId=abc; Path=/; Secure" },
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  assert.ok(out.findings.some((f) => f.id.startsWith("cookie-missing-httponly")));
});

test("flags cookie missing Secure and SameSite", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: { "set-cookie": "cart=1; Path=/" },
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  const ids = out.findings.map((f) => f.id);
  assert.ok(ids.some((id) => id.startsWith("cookie-missing-secure")));
  assert.ok(ids.some((id) => id.startsWith("cookie-missing-samesite")));
});

test("flags CORS wildcard combined with credentials as critical", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      },
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  const cors = out.findings.find((f) => f.id === "cors-wildcard-with-credentials");
  assert.ok(cors, "expected cors-wildcard-with-credentials finding");
  assert.equal(cors!.severity, "critical");
});

test("flags CORS null origin", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: { "access-control-allow-origin": "null" },
    },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  assert.ok(out.findings.some((f) => f.id === "cors-null-origin"));
});

test("flags plain HTTP as high severity", async () => {
  const { fetch } = makeFetch({
    "http://example.test/": { status: 200, headers: {} },
  });
  const out = await scanUrl("http://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: false,
  });
  assert.ok(out.findings.some((f) => f.id === "plaintext-http"));
});

test("probes exposed files and flags .env as critical", async () => {
  const { fetch, calls } = makeFetch({
    "https://example.test/": { status: 200, headers: {} },
    "https://example.test/.env": { status: 200, body: "DATABASE_URL=postgres://u:p@h/db" },
    "*": { status: 404, body: "" },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: true,
    probeErrors: false,
  });
  const env = out.findings.find((f) => f.id === "exposed:/.env");
  assert.ok(env, "expected exposed .env finding");
  assert.equal(env!.severity, "critical");
  assert.ok(calls.some((u) => u.endsWith("/.env")));
});

test("detects stack trace leakage on a random 404 probe", async () => {
  const trace = "Error: boom\n    at Object.<anonymous> (/var/www/app/server.js:42:10)\n";
  const { fetch } = makeFetch({
    "https://example.test/": { status: 200, headers: {} },
    "*": { status: 500, body: trace },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: false,
    probeErrors: true,
  });
  assert.ok(out.findings.some((f) => f.category === "error-leakage"));
});

test("clean site with probes enabled produces no critical/high exposed-file findings", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": {
      status: 200,
      headers: {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin",
        "x-frame-options": "DENY",
        "set-cookie": "sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
      },
    },
    "*": { status: 404, body: "Not Found" },
  });
  const out = await scanUrl("https://example.test/", fetch, {
    probeExposedFiles: true,
    probeErrors: true,
  });
  assert.ok(!out.findings.some((f) => f.category === "exposed-file"));
  assert.ok(!out.findings.some((f) => f.severity === "critical"));
});

test("throws on invalid URL and unsupported protocol", async () => {
  const { fetch } = makeFetch({});
  await assert.rejects(scanUrl("not-a-url", fetch), /Invalid URL/);
  await assert.rejects(scanUrl("ftp://example.test/", fetch), /Unsupported protocol/);
});

// ──────────────────────────────────────────────────────────────
// New probes: source maps, admin panels, API docs,
// embedded secrets, version disclosure, TLS expiry
// ──────────────────────────────────────────────────────────────
import { probeSourceMaps, probeAdminPanels, probeApiDocs, findEmbeddedSecrets, probeTlsExpiry, analyzeVersionDisclosure, type TlsProber } from "../src/engines/url-scanner.ts";

test("probeSourceMaps flags exposed .js.map as critical", async () => {
  const { fetch } = makeFetch({
    "https://example.test/static/main.js.map": {
      status: 200,
      body: '{"version":3,"sources":["src/index.ts"]}',
    },
    "*": { status: 404, body: "" },
  });
  const findings = await probeSourceMaps("https://example.test", fetch);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].category, "source-map");
});

test("probeSourceMaps does NOT flag when body is a 404 HTML page", async () => {
  const { fetch } = makeFetch({
    "*": { status: 200, body: "<html>Not Found</html>" },
  });
  const findings = await probeSourceMaps("https://example.test", fetch);
  assert.equal(findings.length, 0);
});

test("probeAdminPanels flags /admin returning 200 with login form", async () => {
  const { fetch } = makeFetch({
    "https://example.test/admin": { status: 200, body: "<html><form><input type=password></form></html>" },
    "*": { status: 404, body: "" },
  });
  const findings = await probeAdminPanels("https://example.test", fetch);
  assert.ok(findings.some((f) => f.id.startsWith("admin-panel:")));
});

test("probeAdminPanels flags /admin redirecting to login (3xx)", async () => {
  const { fetch } = makeFetch({
    "https://example.test/admin": { status: 302, body: "" },
    "*": { status: 404, body: "" },
  });
  const findings = await probeAdminPanels("https://example.test", fetch);
  assert.ok(findings.some((f) => f.id === "admin-panel:/admin"));
});

test("probeApiDocs flags /swagger with OpenAPI signature", async () => {
  const { fetch } = makeFetch({
    "https://example.test/swagger": { status: 200, body: '{"openapi":"3.0.0","info":{}}' },
    "*": { status: 404, body: "" },
  });
  const findings = await probeApiDocs("https://example.test", fetch);
  assert.ok(findings.some((f) => f.id === "api-docs:/swagger"));
});

test("probeApiDocs flags /__graphql with GraphQL signature", async () => {
  const { fetch } = makeFetch({
    "https://example.test/__graphql": { status: 200, body: "<html>GraphQL Playground</html>" },
    "*": { status: 404, body: "" },
  });
  const findings = await probeApiDocs("https://example.test", fetch);
  assert.ok(findings.some((f) => f.id === "api-docs:/__graphql"));
});

test("probeApiDocs ignores unrelated 200 responses", async () => {
  const { fetch } = makeFetch({
    "*": { status: 200, body: "<html>Home page</html>" },
  });
  const findings = await probeApiDocs("https://example.test", fetch);
  assert.equal(findings.length, 0);
});

test("findEmbeddedSecrets flags Supabase anon key in HTML", () => {
  const html = `<script>
    import { createClient } from '@supabase/supabase-js';
    const supabase = supabase.createClient("https://abc.supabase.co",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbm9uIjoidHJ1ZSIsImlhdCI6MX0.abcdefghijklmnop")
  </script>`;
  const findings = findEmbeddedSecrets(html, "https://example.test");
  assert.ok(findings.some((f) => f.id === "supabase-anon-key-in-html"));
});

test("findEmbeddedSecrets flags Firebase config in HTML", () => {
  const html = `<script>
    var firebaseConfig = { apiKey: "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ", authDomain: "x" };
    firebase.initializeApp(firebaseConfig);
  </script>`;
  const findings = findEmbeddedSecrets(html, "https://example.test");
  assert.ok(findings.some((f) => f.id === "firebase-config-in-html"));
});

test("findEmbeddedSecrets does NOT flag plain HTML", () => {
  const findings = findEmbeddedSecrets("<html><body>Hello</body></html>", "https://example.test");
  assert.equal(findings.length, 0);
});

test("analyzeVersionDisclosure flags X-AspNet-Version header", () => {
  const headers = {
    get: (n: string) => (n.toLowerCase() === "x-aspnet-version" ? "4.0.30319" : undefined),
    entries: () => [] as Array<[string, string]>,
  };
  const findings = analyzeVersionDisclosure(headers as any);
  assert.ok(findings.some((f) => f.id === "version-disclosure:x-aspnet-version"));
});

test("probeTlsExpiry flags expired cert as critical", async () => {
  const prober: TlsProber = { async check() { return { validTo: new Date("2020-01-01") }; } };
  const findings = await probeTlsExpiry("example.test", prober, new Date("2026-04-22"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].id, "tls-expired");
});

test("probeTlsExpiry flags cert expiring in 5 days as critical", async () => {
  const now = new Date("2026-04-22");
  const soon = new Date("2026-04-26");
  const prober: TlsProber = { async check() { return { validTo: soon }; } };
  const findings = await probeTlsExpiry("example.test", prober, now);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].id, "tls-expiring-soon");
});

test("probeTlsExpiry flags cert expiring in 20 days as medium", async () => {
  const now = new Date("2026-04-22");
  const soon = new Date("2026-05-10");
  const prober: TlsProber = { async check() { return { validTo: soon }; } };
  const findings = await probeTlsExpiry("example.test", prober, now);
  assert.equal(findings[0].severity, "medium");
  assert.equal(findings[0].id, "tls-expiring");
});

test("probeTlsExpiry silent when cert has plenty of life", async () => {
  const now = new Date("2026-04-22");
  const later = new Date("2027-04-22");
  const prober: TlsProber = { async check() { return { validTo: later }; } };
  const findings = await probeTlsExpiry("example.test", prober, now);
  assert.equal(findings.length, 0);
});

test("probeTlsExpiry silent when prober returns null", async () => {
  const prober: TlsProber = { async check() { return null; } };
  const findings = await probeTlsExpiry("example.test", prober);
  assert.equal(findings.length, 0);
});

test("scanUrl runs all new probes without crashing on empty responses", async () => {
  const { fetch } = makeFetch({
    "https://example.test/": { status: 200, headers: {}, body: "hi" },
    "*": { status: 404, body: "" },
  });
  const prober: TlsProber = { async check() { return null; } };
  const out = await scanUrl("https://example.test/", fetch, { probeTls: true, tlsProber: prober });
  // Should have baseline findings (missing CSP etc) but no new-probe noise
  assert.ok(!out.findings.some((f) => f.category === "source-map"));
  assert.ok(!out.findings.some((f) => f.category === "api-docs"));
  assert.ok(!out.findings.some((f) => f.category === "embedded-secret"));
});
