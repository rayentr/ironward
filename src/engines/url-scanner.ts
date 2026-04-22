export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface UrlFinding {
  category:
    | "headers"
    | "cookies"
    | "cors"
    | "exposed-file"
    | "error-leakage"
    | "tls"
    | "source-map"
    | "admin-panel"
    | "api-docs"
    | "embedded-secret"
    | "version-disclosure"
    | "info";
  id: string;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
}

export interface UrlScanResult {
  target: string;
  fetchedAt: string;
  status: number;
  durationMs: number;
  findings: UrlFinding[];
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  summary: string;
}

export function scoreAndGrade(findings: UrlFinding[]): { score: number; grade: UrlScanResult["grade"] } {
  let penalty = 0;
  for (const f of findings) {
    if (f.severity === "critical") penalty += 25;
    else if (f.severity === "high") penalty += 12;
    else if (f.severity === "medium") penalty += 5;
    else if (f.severity === "low") penalty += 2;
  }
  const score = Math.max(0, 100 - penalty);
  let grade: UrlScanResult["grade"];
  if (score >= 95 && findings.every((f) => f.severity === "info" || f.severity === "low")) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 70) grade = "B";
  else if (score >= 55) grade = "C";
  else if (score >= 35) grade = "D";
  else grade = "F";
  return { score, grade };
}

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; redirect?: "manual" | "follow" },
) => Promise<{
  ok: boolean;
  status: number;
  url: string;
  headers: Headers | Map<string, string> | Record<string, string>;
  text: () => Promise<string>;
}>;

const DEFAULT_EXPOSED_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/config",
  "/.git/HEAD",
  "/.DS_Store",
  "/.vscode/settings.json",
  "/firebase.json",
  "/config.json",
  "/.npmrc",
];

interface NormalizedHeaders {
  get(name: string): string | undefined;
  entries(): IterableIterator<[string, string]> | Array<[string, string]>;
}

function normalizeHeaders(h: Headers | Map<string, string> | Record<string, string>): NormalizedHeaders {
  if (h && typeof (h as Headers).get === "function") {
    const headers = h as Headers;
    return {
      get: (name: string) => headers.get(name) ?? undefined,
      entries: () => headers.entries(),
    };
  }
  const record: Record<string, string> =
    h instanceof Map ? Object.fromEntries(h) : { ...(h as Record<string, string>) };
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(record)) lower[k.toLowerCase()] = v;
  return {
    get: (name: string) => lower[name.toLowerCase()],
    entries: () => Object.entries(record),
  };
}

export function analyzeSecurityHeaders(headers: NormalizedHeaders): UrlFinding[] {
  const findings: UrlFinding[] = [];
  const csp = headers.get("content-security-policy");
  if (!csp) {
    findings.push({
      category: "headers",
      id: "missing-csp",
      severity: "high",
      title: "Content-Security-Policy header is missing",
      evidence: "No Content-Security-Policy in response headers.",
      recommendation:
        "Set a CSP header that restricts script sources (e.g. `default-src 'self'; script-src 'self'`) to mitigate XSS impact.",
    });
  } else if (/'unsafe-inline'/.test(csp) || /'unsafe-eval'/.test(csp)) {
    findings.push({
      category: "headers",
      id: "weak-csp",
      severity: "medium",
      title: "Content-Security-Policy allows unsafe-inline or unsafe-eval",
      evidence: `CSP: ${csp}`,
      recommendation:
        "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for the few inline scripts you truly need.",
    });
  }

  if (!headers.get("strict-transport-security")) {
    findings.push({
      category: "headers",
      id: "missing-hsts",
      severity: "medium",
      title: "Strict-Transport-Security header is missing",
      evidence: "No HSTS header.",
      recommendation: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
    });
  }

  const xfo = headers.get("x-frame-options");
  const cspFrameAncestors = csp && /frame-ancestors/.test(csp);
  if (!xfo && !cspFrameAncestors) {
    findings.push({
      category: "headers",
      id: "missing-frame-protection",
      severity: "medium",
      title: "Clickjacking protection missing",
      evidence: "No X-Frame-Options or CSP frame-ancestors directive.",
      recommendation: "Set `X-Frame-Options: DENY` or add `frame-ancestors 'none'` to your CSP.",
    });
  }

  if (!headers.get("x-content-type-options")) {
    findings.push({
      category: "headers",
      id: "missing-nosniff",
      severity: "low",
      title: "X-Content-Type-Options header is missing",
      evidence: "No X-Content-Type-Options header.",
      recommendation: "Set `X-Content-Type-Options: nosniff`.",
    });
  }

  if (!headers.get("referrer-policy")) {
    findings.push({
      category: "headers",
      id: "missing-referrer-policy",
      severity: "low",
      title: "Referrer-Policy header is missing",
      evidence: "No Referrer-Policy header.",
      recommendation:
        "Set `Referrer-Policy: strict-origin-when-cross-origin` to limit data leakage in Referer headers.",
    });
  }

  const server = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  if (server && /[0-9]/.test(server)) {
    findings.push({
      category: "headers",
      id: "server-version-disclosure",
      severity: "low",
      title: "Server header discloses version",
      evidence: `Server: ${server}`,
      recommendation: "Remove or redact the Server header at the reverse proxy.",
    });
  }
  if (poweredBy) {
    findings.push({
      category: "headers",
      id: "x-powered-by-disclosure",
      severity: "low",
      title: "X-Powered-By header discloses framework",
      evidence: `X-Powered-By: ${poweredBy}`,
      recommendation:
        "Disable the X-Powered-By header (e.g. `app.disable('x-powered-by')` in Express).",
    });
  }

  return findings;
}

export function analyzeCookies(headers: NormalizedHeaders): UrlFinding[] {
  const findings: UrlFinding[] = [];
  const setCookieValues: string[] = [];
  for (const [k, v] of headers.entries()) {
    if (k.toLowerCase() === "set-cookie") setCookieValues.push(v);
  }
  if (setCookieValues.length === 0) return findings;

  for (const raw of setCookieValues) {
    for (const cookie of raw.split(/,(?=\s*[A-Za-z0-9_\-]+=)/)) {
      const name = cookie.split("=", 1)[0].trim();
      const flags = cookie.toLowerCase();
      const hasSecure = /;\s*secure\b/.test(flags);
      const hasHttpOnly = /;\s*httponly\b/.test(flags);
      const hasSameSite = /;\s*samesite=/.test(flags);
      if (!hasSecure) {
        findings.push({
          category: "cookies",
          id: `cookie-missing-secure:${name}`,
          severity: "medium",
          title: `Cookie "${name}" missing Secure flag`,
          evidence: cookie.split(";")[0] + "; …",
          recommendation: "Add the Secure flag so the cookie is only sent over HTTPS.",
        });
      }
      if (!hasHttpOnly && /session|sid|auth|token/i.test(name)) {
        findings.push({
          category: "cookies",
          id: `cookie-missing-httponly:${name}`,
          severity: "high",
          title: `Session-like cookie "${name}" missing HttpOnly flag`,
          evidence: cookie.split(";")[0] + "; …",
          recommendation:
            "Add the HttpOnly flag to prevent JavaScript access; only servers should read session cookies.",
        });
      }
      if (!hasSameSite) {
        findings.push({
          category: "cookies",
          id: `cookie-missing-samesite:${name}`,
          severity: "low",
          title: `Cookie "${name}" missing SameSite attribute`,
          evidence: cookie.split(";")[0] + "; …",
          recommendation:
            "Add `SameSite=Lax` (or `Strict` for auth cookies) to reduce CSRF risk.",
        });
      }
    }
  }
  return findings;
}

export function analyzeCors(headers: NormalizedHeaders): UrlFinding[] {
  const findings: UrlFinding[] = [];
  const origin = headers.get("access-control-allow-origin");
  const credentials = headers.get("access-control-allow-credentials");
  if (origin === "*" && credentials && credentials.toLowerCase() === "true") {
    findings.push({
      category: "cors",
      id: "cors-wildcard-with-credentials",
      severity: "critical",
      title: "CORS: Access-Control-Allow-Origin '*' combined with Allow-Credentials: true",
      evidence: `ACAO: *  ·  ACAC: ${credentials}`,
      recommendation:
        "Never combine `*` with credentials: true. Echo the request Origin against an allowlist or drop the wildcard.",
    });
  } else if (origin === "*") {
    findings.push({
      category: "cors",
      id: "cors-wildcard",
      severity: "low",
      title: "CORS: Access-Control-Allow-Origin is '*'",
      evidence: "ACAO: *",
      recommendation:
        "For APIs that return non-public data, restrict ACAO to an explicit list of trusted origins.",
    });
  }
  const null_origin = origin && origin.toLowerCase() === "null";
  if (null_origin) {
    findings.push({
      category: "cors",
      id: "cors-null-origin",
      severity: "high",
      title: "CORS: Access-Control-Allow-Origin allows 'null'",
      evidence: `ACAO: ${origin}`,
      recommendation:
        "Do not allow 'null' — sandboxed iframes and malicious pages can send a null origin.",
    });
  }
  return findings;
}

function looksLikeSecret(body: string): string | null {
  const tests: Array<[RegExp, string]> = [
    [/AKIA[0-9A-Z]{16}/, "AWS access key ID"],
    [/sk_live_[A-Za-z0-9]{24,}/, "Stripe live secret key"],
    [/ghp_[A-Za-z0-9]{36}/, "GitHub personal access token"],
    [/sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{60,}/, "Anthropic API key"],
    [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/, "Private key PEM"],
    [/postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@/, "Postgres connection string with credentials"],
  ];
  for (const [re, label] of tests) if (re.test(body)) return label;
  return null;
}

export async function probeExposedPaths(
  origin: string,
  fetchImpl: FetchLike,
  paths: string[] = DEFAULT_EXPOSED_PATHS,
): Promise<UrlFinding[]> {
  const findings: UrlFinding[] = [];
  for (const p of paths) {
    const url = origin.replace(/\/$/, "") + p;
    let res;
    try {
      res = await fetchImpl(url, { method: "GET", redirect: "manual" });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    const body = (await res.text().catch(() => "")).slice(0, 4096);
    const secretLabel = looksLikeSecret(body);
    findings.push({
      category: "exposed-file",
      id: `exposed:${p}`,
      severity: secretLabel ? "critical" : p.includes(".env") || p.includes(".git") ? "critical" : "high",
      title: `Dev/build file accessible at ${p}`,
      evidence: secretLabel
        ? `HTTP 200; body contains ${secretLabel}.`
        : `HTTP 200; body length ${body.length}.`,
      recommendation:
        "Block this path at the edge (nginx / Vercel / Cloudflare). Never ship .env / .git to production.",
    });
  }
  return findings;
}

const DEFAULT_SOURCE_MAP_PATHS = [
  "/static/main.js.map",
  "/static/js/main.js.map",
  "/assets/index.js.map",
  "/assets/main.js.map",
  "/dist/main.js.map",
  "/build/main.js.map",
  "/bundle.js.map",
  "/app.js.map",
];

export async function probeSourceMaps(
  origin: string,
  fetchImpl: FetchLike,
  paths: string[] = DEFAULT_SOURCE_MAP_PATHS,
): Promise<UrlFinding[]> {
  const findings: UrlFinding[] = [];
  for (const p of paths) {
    const url = origin.replace(/\/$/, "") + p;
    let res;
    try {
      res = await fetchImpl(url, { method: "GET", redirect: "manual" });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    const body = (await res.text().catch(() => "")).slice(0, 2048);
    // A valid source map starts with `{"version":3` or similar
    if (!/"version"\s*:\s*3/.test(body) && !/"sources"\s*:/.test(body)) continue;
    findings.push({
      category: "source-map",
      id: `source-map:${p}`,
      severity: "critical",
      title: `JavaScript source map exposed at ${p}`,
      evidence: `HTTP 200, body begins with valid source map JSON.`,
      recommendation:
        "Do not ship .js.map files to production. They give attackers your un-minified source code. Strip them from your build output or block them at the edge.",
    });
  }
  return findings;
}

const DEFAULT_ADMIN_PATHS = [
  "/admin",
  "/administrator",
  "/wp-admin",
  "/phpmyadmin",
  "/cpanel",
  "/dashboard",
  "/manage",
  "/control",
  "/backend",
  "/staff",
];

export async function probeAdminPanels(
  origin: string,
  fetchImpl: FetchLike,
  paths: string[] = DEFAULT_ADMIN_PATHS,
): Promise<UrlFinding[]> {
  const findings: UrlFinding[] = [];
  for (const p of paths) {
    const url = origin.replace(/\/$/, "") + p;
    let res;
    try {
      res = await fetchImpl(url, { method: "GET", redirect: "manual" });
    } catch {
      continue;
    }
    // 200 or 3xx (redirect to login) = discoverable panel
    if (res.status !== 200 && !(res.status >= 300 && res.status < 400)) continue;
    const body = (await res.text().catch(() => "")).slice(0, 2048);
    const looksLikeApp = /<html|login|password|admin|<form/i.test(body);
    if (!looksLikeApp && res.status === 200) continue;
    findings.push({
      category: "admin-panel",
      id: `admin-panel:${p}`,
      severity: "low",
      title: `Admin panel discoverable at ${p}`,
      evidence: `HTTP ${res.status} at ${p}.`,
      recommendation:
        "Gate admin panels behind VPN, IP allowlist, or SSO. At minimum, add a WAF rule to rate-limit or block by default.",
    });
  }
  return findings;
}

const DEFAULT_API_DOC_PATHS = [
  "/swagger",
  "/swagger-ui",
  "/swagger-ui.html",
  "/api-docs",
  "/api/docs",
  "/docs",
  "/redoc",
  "/openapi.json",
  "/schema",
  "/__graphql",
  "/playground",
];

export async function probeApiDocs(
  origin: string,
  fetchImpl: FetchLike,
  paths: string[] = DEFAULT_API_DOC_PATHS,
): Promise<UrlFinding[]> {
  const findings: UrlFinding[] = [];
  for (const p of paths) {
    const url = origin.replace(/\/$/, "") + p;
    let res;
    try {
      res = await fetchImpl(url, { method: "GET", redirect: "manual" });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    const body = (await res.text().catch(() => "")).slice(0, 4096);
    const isOpenApi = /"openapi"\s*:|"swagger"\s*:/.test(body);
    const isGraphQL = /graphql|GraphQLPlayground/i.test(body);
    const isRedoc = /redoc/i.test(body);
    if (!isOpenApi && !isGraphQL && !isRedoc) continue;
    findings.push({
      category: "api-docs",
      id: `api-docs:${p}`,
      severity: "medium",
      title: `API documentation publicly accessible at ${p}`,
      evidence: `HTTP 200 at ${p}; body signature: ${isOpenApi ? "OpenAPI/Swagger" : isGraphQL ? "GraphQL" : "ReDoc"}.`,
      recommendation:
        "Gate API docs behind auth, or only enable them in non-production environments. Public API docs accelerate reconnaissance.",
    });
  }
  return findings;
}

export function findEmbeddedSecrets(html: string, sourceUrl: string): UrlFinding[] {
  const findings: UrlFinding[] = [];

  const supabaseAnon = html.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/);
  const supabaseCall = /supabase\s*\.createClient\s*\(|NEXT_PUBLIC_SUPABASE|createClient\s*\(\s*["'`]https:\/\/[a-z0-9]{20}\.supabase\.co/i.test(html);
  if (supabaseCall && supabaseAnon) {
    findings.push({
      category: "embedded-secret",
      id: "supabase-anon-key-in-html",
      severity: "medium",
      title: "Supabase anon key embedded in page HTML",
      evidence: `Found Supabase client init + JWT-shaped key in ${sourceUrl}.`,
      recommendation:
        "Anon keys are designed for client-side use, but verify Row-Level Security is on for every table. Anyone with this key can query your database subject to RLS policies.",
    });
  }

  const firebaseInit = /firebase\s*\.initializeApp\s*\(|firebaseConfig\s*=\s*\{[^}]*apiKey\s*:/i.test(html);
  const firebaseKey = html.match(/apiKey\s*:\s*["']AIza[0-9A-Za-z_-]{20,}["']/);
  if (firebaseInit && firebaseKey) {
    findings.push({
      category: "embedded-secret",
      id: "firebase-config-in-html",
      severity: "low",
      title: "Firebase config embedded in page HTML",
      evidence: `Found firebase.initializeApp with apiKey in ${sourceUrl}.`,
      recommendation:
        "Firebase API keys are not secrets, but you must lock down Firestore/RTDB security rules and set App Check. Anyone with this config can hit your Firebase project.",
    });
  }

  return findings;
}

export async function probePageForSecrets(
  target: string,
  fetchImpl: FetchLike,
): Promise<UrlFinding[]> {
  let res;
  try {
    res = await fetchImpl(target, { method: "GET", redirect: "follow" });
  } catch {
    return [];
  }
  const body = (await res.text().catch(() => "")).slice(0, 512 * 1024);
  return findEmbeddedSecrets(body, target);
}

export function analyzeVersionDisclosure(headers: NormalizedHeaders): UrlFinding[] {
  const findings: UrlFinding[] = [];
  const versionRe = /\d+\.\d+(?:\.\d+)?/;
  const candidates: Array<[string, string]> = [
    ["x-aspnet-version", "X-AspNet-Version"],
    ["x-aspnetmvc-version", "X-AspNetMvc-Version"],
    ["x-drupal-cache", "X-Drupal-Cache"],
    ["x-generator", "X-Generator"],
  ];
  for (const [lower, canonical] of candidates) {
    const v = headers.get(lower);
    if (!v) continue;
    if (!versionRe.test(v) && !/\d/.test(v)) continue;
    findings.push({
      category: "version-disclosure",
      id: `version-disclosure:${lower}`,
      severity: "low",
      title: `${canonical} header discloses software details`,
      evidence: `${canonical}: ${v}`,
      recommendation: `Strip or redact ${canonical} at the proxy — it helps attackers match your stack to known exploits.`,
    });
  }
  return findings;
}

export interface TlsProber {
  check(hostname: string, port?: number): Promise<{ validTo: Date } | null>;
}

export class NodeTlsProber implements TlsProber {
  async check(hostname: string, port = 443): Promise<{ validTo: Date } | null> {
    const tls = await import("node:tls");
    return new Promise((resolve) => {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 5000 },
        () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (!cert || !cert.valid_to) return resolve(null);
          resolve({ validTo: new Date(cert.valid_to) });
        },
      );
      socket.on("error", () => { try { socket.destroy(); } catch {} resolve(null); });
      socket.on("timeout", () => { try { socket.destroy(); } catch {} resolve(null); });
    });
  }
}

export async function probeTlsExpiry(
  hostname: string,
  prober: TlsProber = new NodeTlsProber(),
  now: Date = new Date(),
): Promise<UrlFinding[]> {
  const result = await prober.check(hostname);
  if (!result) return [];
  const daysLeft = Math.floor((result.validTo.getTime() - now.getTime()) / 86400000);
  if (daysLeft <= 0) {
    return [{
      category: "tls",
      id: "tls-expired",
      severity: "critical",
      title: "TLS certificate is expired",
      evidence: `Certificate valid_to: ${result.validTo.toISOString()}`,
      recommendation: "Renew your TLS certificate immediately. Browsers will refuse to connect.",
    }];
  }
  if (daysLeft <= 7) {
    return [{
      category: "tls",
      id: "tls-expiring-soon",
      severity: "critical",
      title: `TLS certificate expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`,
      evidence: `Certificate valid_to: ${result.validTo.toISOString()}`,
      recommendation: "Renew your TLS certificate now and enable auto-renewal (certbot, ACM, Cloudflare).",
    }];
  }
  if (daysLeft <= 30) {
    return [{
      category: "tls",
      id: "tls-expiring",
      severity: "medium",
      title: `TLS certificate expires in ${daysLeft} days`,
      evidence: `Certificate valid_to: ${result.validTo.toISOString()}`,
      recommendation: "Schedule renewal and confirm your automation is working.",
    }];
  }
  return [];
}

export async function probeErrorLeakage(
  origin: string,
  fetchImpl: FetchLike,
): Promise<UrlFinding[]> {
  const url = origin.replace(/\/$/, "") + "/__ironward_probe_" + Math.random().toString(36).slice(2);
  let res;
  try {
    res = await fetchImpl(url, { method: "GET", redirect: "manual" });
  } catch {
    return [];
  }
  const body = (await res.text().catch(() => "")).slice(0, 8192);
  const findings: UrlFinding[] = [];
  const leakagePatterns: Array<[RegExp, string]> = [
    [/at\s+\w+[^\n]{0,80}\([^:\n]+:\d+:\d+\)/, "JavaScript stack trace"],
    [/Traceback \(most recent call last\):/, "Python traceback"],
    [/\bError: [A-Z][A-Za-z0-9_]* /, "Server error surface"],
    [/\/home\/[a-z0-9_]+\//i, "Absolute server filesystem path"],
    [/\/var\/www\/|\/usr\/local\/|\/opt\//, "Absolute server filesystem path"],
  ];
  for (const [re, label] of leakagePatterns) {
    if (re.test(body)) {
      findings.push({
        category: "error-leakage",
        id: `error-leakage:${label.toLowerCase().replace(/\W+/g, "-")}`,
        severity: "medium",
        title: `Error response leaks implementation detail (${label})`,
        evidence: `Probed ${url} — body contains: ${label}.`,
        recommendation:
          "Return a generic error body in production. Log stack traces server-side only.",
      });
      break;
    }
  }
  return findings;
}

export async function scanUrl(
  target: string,
  fetchImpl: FetchLike = (fetch as unknown) as FetchLike,
  opts: {
    probeExposedFiles?: boolean;
    probeErrors?: boolean;
    probeSourceMaps?: boolean;
    probeAdminPanels?: boolean;
    probeApiDocs?: boolean;
    probeEmbeddedSecrets?: boolean;
    probeTls?: boolean;
    tlsProber?: TlsProber;
  } = {},
): Promise<UrlScanResult> {
  const started = Date.now();
  const fetchedAt = new Date().toISOString();
  let urlObj: URL;
  try {
    urlObj = new URL(target);
  } catch {
    throw new Error(`Invalid URL: ${target}`);
  }
  if (urlObj.protocol !== "https:" && urlObj.protocol !== "http:") {
    throw new Error(`Unsupported protocol: ${urlObj.protocol}`);
  }

  const res = await fetchImpl(target, { method: "GET", redirect: "manual" });
  const headers = normalizeHeaders(res.headers as Headers | Record<string, string>);

  const findings: UrlFinding[] = [];
  findings.push(...analyzeSecurityHeaders(headers));
  findings.push(...analyzeCookies(headers));
  findings.push(...analyzeCors(headers));
  findings.push(...analyzeVersionDisclosure(headers));

  if (urlObj.protocol === "http:") {
    findings.push({
      category: "tls",
      id: "plaintext-http",
      severity: "high",
      title: "Site responds over plain HTTP",
      evidence: `Protocol: ${urlObj.protocol}`,
      recommendation: "Force HTTPS via HSTS + a 301 redirect from port 80.",
    });
  }

  const origin = `${urlObj.protocol}//${urlObj.host}`;
  if (opts.probeExposedFiles !== false) {
    findings.push(...(await probeExposedPaths(origin, fetchImpl)));
  }
  if (opts.probeSourceMaps !== false) {
    findings.push(...(await probeSourceMaps(origin, fetchImpl)));
  }
  if (opts.probeAdminPanels !== false) {
    findings.push(...(await probeAdminPanels(origin, fetchImpl)));
  }
  if (opts.probeApiDocs !== false) {
    findings.push(...(await probeApiDocs(origin, fetchImpl)));
  }
  if (opts.probeEmbeddedSecrets !== false) {
    findings.push(...(await probePageForSecrets(target, fetchImpl)));
  }
  if (opts.probeErrors !== false) {
    findings.push(...(await probeErrorLeakage(origin, fetchImpl)));
  }
  if (opts.probeTls && urlObj.protocol === "https:") {
    try {
      findings.push(...(await probeTlsExpiry(urlObj.hostname, opts.tlsProber ?? new NodeTlsProber())));
    } catch {
      /* ignore TLS probe failures */
    }
  }

  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  findings.sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || a.id.localeCompare(b.id),
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  const { score, grade } = scoreAndGrade(findings);
  const summary =
    findings.length === 0
      ? `No exposure detected. Grade: ${grade} (${score}/100).`
      : `Grade: ${grade} (${score}/100). ${findings.length} findings — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low.`;

  return {
    target,
    fetchedAt,
    status: res.status,
    durationMs: Date.now() - started,
    findings,
    score,
    grade,
    summary,
  };
}

export function formatUrlReport(out: UrlScanResult): string {
  const lines = [
    `${out.target} → ${out.status} (${out.durationMs}ms)`,
    `Security score: ${out.grade} (${out.score}/100)`,
    out.summary,
    "",
  ];
  if (out.findings.length === 0) return lines.join("\n").trimEnd();
  for (const f of out.findings) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  evidence: ${f.evidence}`);
    lines.push(`  fix: ${f.recommendation}`);
  }
  return lines.join("\n").trimEnd();
}
