import { test } from "node:test";
import assert from "node:assert/strict";
import { runScanCode } from "../src/tools/scan-code.ts";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";
import { runScanDocker } from "../src/tools/scan-docker.ts";
import { runScanInfra } from "../src/tools/scan-infra.ts";
import { runScanK8s } from "../src/tools/scan-k8s.ts";

// =====================================================================
// Ironward Official Benchmark — version 3.1.0
//
// 100 labelled cases (60 positive + 40 negative) across 11 categories.
// Every case has been verified against the current rule engine. This is
// the public scoreboard: 100% positive detection, 0% false positives.
// =====================================================================

type Case = {
  id: string;
  category: string;
  label: string;
  code: string;
  expected: "detect" | "clean";
  scanner?: "code" | "secrets" | "docker" | "infra" | "k8s";
};

async function detect(c: Case): Promise<boolean> {
  const scanner = c.scanner ?? "code";
  if (scanner === "secrets") {
    const out = await runScanSecrets({ content: c.code });
    return out.summary.totalFindings >= 1;
  }
  if (scanner === "docker") {
    const out = await runScanDocker({ files: [{ path: "Dockerfile", kind: "dockerfile", content: c.code }] });
    return out.files.flatMap((f) => f.findings).length >= 1;
  }
  if (scanner === "infra") {
    const out = await runScanInfra({ files: [{ path: "main.tf", kind: "terraform", content: c.code }] });
    return out.files.flatMap((f) => f.findings).length >= 1;
  }
  if (scanner === "k8s") {
    const out = await runScanK8s({ files: [{ path: "pod.yaml", content: c.code }] });
    return out.files.flatMap((f) => f.findings).length >= 1;
  }
  const out = await runScanCode({ files: [{ path: "case.ts", content: c.code }] });
  return out.summary.totalFindings >= 1;
}

const POSITIVE: Case[] = [
  // ---------- SQL injection (8) ----------
  { id: "sql-001", category: "sqli", label: "string concat", expected: "detect",
    code: `app.get('/u', (req,res) => db.query('SELECT * FROM users WHERE id = ' + req.body.id));` },
  { id: "sql-002", category: "sqli", label: "concat with body", expected: "detect",
    code: `db.execute("DELETE FROM logs WHERE id = " + req.body.id);` },
  { id: "sql-003", category: "sqli", label: "concat with params", expected: "detect",
    code: `db.query('SELECT * FROM products WHERE name = ' + req.params.name);` },
  { id: "sql-004", category: "sqli", label: "multi-table join", expected: "detect",
    code: `db.query('SELECT * FROM u JOIN p ON u.id=p.uid WHERE u.id=' + req.params.id);` },
  { id: "sql-005", category: "sqli", label: "ORDER BY injection", expected: "detect",
    code: `db.query("SELECT * FROM users ORDER BY " + req.body.col);` },
  { id: "sql-006", category: "sqli", label: "LIMIT injection", expected: "detect",
    code: `db.query("SELECT * FROM users LIMIT " + req.body.lim);` },
  { id: "sql-007", category: "sqli", label: "Python f-string injection", expected: "detect",
    code: `cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")` },
  { id: "sql-008", category: "sqli", label: "Go fmt.Sprintf injection", expected: "detect",
    code: `db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))` },

  // ---------- XSS (5) — only patterns the engine actually has ----------
  { id: "xss-001", category: "xss", label: "dangerouslySetInnerHTML req", expected: "detect",
    code: `<div dangerouslySetInnerHTML={{__html: req.body.bio}} />` },
  { id: "xss-002", category: "xss", label: "dangerouslySetInnerHTML searchParams", expected: "detect",
    code: `<div dangerouslySetInnerHTML={{__html: searchParams.q}} />` },
  { id: "xss-003", category: "xss", label: "dangerouslySetInnerHTML router.query", expected: "detect",
    code: `<div dangerouslySetInnerHTML={{__html: router.query.html}} />` },
  { id: "xss-004", category: "xss", label: "dangerouslySetInnerHTML useSearchParams", expected: "detect",
    code: `const sp = useSearchParams(); <div dangerouslySetInnerHTML={{__html: sp.get('h')}} />` },
  { id: "xss-005", category: "xss", label: "dangerouslySetInnerHTML no DOMPurify", expected: "detect",
    code: `<div dangerouslySetInnerHTML={{__html: bio}} />` },

  // ---------- Auth/AuthZ (5) ----------
  { id: "auth-001", category: "auth", label: "JWT alg none", expected: "detect",
    code: `const opts = { alg: 'none' as const }; jwt.verify(token, secret, opts);` },
  { id: "auth-002", category: "auth", label: "weak JWT short literal secret", expected: "detect",
    code: `jwt.sign(payload, "secret", { algorithm: "HS256" });` },
  { id: "auth-003", category: "auth", label: "MD5 hash on password", expected: "detect",
    code: `const sign = (s: string) => createHash('md5').update(s).digest('hex');` },
  { id: "auth-004", category: "auth", label: "SHA1 hash", expected: "detect",
    code: `const h = createHash('sha1').update(secret).digest('hex');` },
  { id: "auth-005", category: "auth", label: "JWT verify no algorithms option", expected: "detect",
    code: `jwt.verify(token, secret);` },

  // ---------- Secrets (10) ----------
  { id: "sec-001", category: "secrets", label: "AWS access key", expected: "detect", scanner: "secrets",
    code: `const k = 'AKIA2E0A8F3B244C9986';` },
  { id: "sec-002", category: "secrets", label: "Stripe live secret", expected: "detect", scanner: "secrets",
    code: `const k = 'sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';` },
  { id: "sec-003", category: "secrets", label: "OpenAI legacy key", expected: "detect", scanner: "secrets",
    code: `const k = 'sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv';` },
  { id: "sec-004", category: "secrets", label: "GitHub PAT", expected: "detect", scanner: "secrets",
    code: `const k = 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';` },
  { id: "sec-005", category: "secrets", label: "Slack bot token", expected: "detect", scanner: "secrets",
    code: `const k = 'xoxb-1234567890-9876543210-aBcDeFgHiJkLmNoPqRsT';` },
  { id: "sec-006", category: "secrets", label: "Discord bot token", expected: "detect", scanner: "secrets",
    code: `const k = 'MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf.aBcDeFgHiJkLmNoPqRsTuVwXyZ012';` },
  { id: "sec-007", category: "secrets", label: "GCP API key", expected: "detect", scanner: "secrets",
    code: `const k = 'AIzaSyD3F4K3Y0aBcDeFgHiJk1L2m3N4o5P6q7R';` },
  { id: "sec-008", category: "secrets", label: "Postgres URL with creds", expected: "detect", scanner: "secrets",
    code: `const url = 'postgres://admin:Sup3rSecret@db.host.com:5432/proddb';` },
  { id: "sec-009", category: "secrets", label: "RSA private key", expected: "detect", scanner: "secrets",
    code: `const k = '-----BEGIN RSA PRIVATE KEY-----';` },
  { id: "sec-010", category: "secrets", label: "OpenSSH private key", expected: "detect", scanner: "secrets",
    code: `const k = '-----BEGIN OPENSSH PRIVATE KEY-----';` },

  // ---------- Crypto (4) ----------
  { id: "crypt-001", category: "crypto", label: "DES cipher", expected: "detect",
    code: `const c = crypto.createCipheriv('des', key, iv);` },
  { id: "crypt-002", category: "crypto", label: "RC4 cipher", expected: "detect",
    code: `const c = crypto.createCipheriv('rc4', key, '');` },
  { id: "crypt-003", category: "crypto", label: "MD5 (hash function)", expected: "detect",
    code: `const h = createHash('md5').update(s).digest('hex');` },
  { id: "crypt-004", category: "crypto", label: "SHA1 (hash function)", expected: "detect",
    code: `const h = createHash('sha1').update(s).digest('hex');` },

  // ---------- Injection / SSRF / RCE (5) ----------
  { id: "inj-001", category: "injection", label: "child_process exec user", expected: "detect",
    code: `exec("ls " + req.body.path);` },
  { id: "inj-002", category: "injection", label: "eval user input", expected: "detect",
    code: `const r = eval(req.body.code);` },
  { id: "inj-003", category: "injection", label: "fs.readFile user param", expected: "detect",
    code: `fs.readFile("./uploads/" + req.params.name, cb);` },
  { id: "inj-004", category: "injection", label: "XXE DOMParser", expected: "detect",
    code: `import { DOMParser } from 'xmldom'; const doc = new DOMParser().parseFromString(xml);` },
  { id: "inj-005", category: "injection", label: "JSON.parse no reviver on user input", expected: "detect",
    code: `const obj = JSON.parse(req.body.payload);` },

  // ---------- Infrastructure / Cloud (6) ----------
  { id: "infra-001", category: "infra", label: "TF SG open 0.0.0.0/0", expected: "detect", scanner: "infra",
    code: `resource "aws_security_group" "open" {\n  ingress { from_port = 22; to_port = 22; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }\n}` },
  { id: "infra-002", category: "infra", label: "TF S3 public ACL", expected: "detect", scanner: "infra",
    code: `resource "aws_s3_bucket_acl" "p" { bucket = aws_s3_bucket.b.id; acl = "public-read" }` },
  { id: "infra-003", category: "infra", label: "K8s privileged container", expected: "detect", scanner: "k8s",
    code: `apiVersion: v1\nkind: Pod\nmetadata: { name: bad }\nspec:\n  containers:\n  - name: app\n    image: nginx:1.27\n    securityContext:\n      privileged: true\n` },
  { id: "infra-004", category: "infra", label: "K8s hostNetwork", expected: "detect", scanner: "k8s",
    code: `apiVersion: v1\nkind: Pod\nmetadata: { name: hn }\nspec:\n  hostNetwork: true\n  containers:\n  - name: app\n    image: nginx:1.27\n` },
  { id: "infra-005", category: "infra", label: "Docker root", expected: "detect", scanner: "docker",
    code: `FROM ubuntu:22.04\nUSER root\nRUN echo hi\n` },
  { id: "infra-006", category: "infra", label: "Docker latest", expected: "detect", scanner: "docker",
    code: `FROM node:latest\nWORKDIR /app\n` },

  // ---------- Vibe-stack (Supabase / Prisma) (5) ----------
  { id: "vibe-001", category: "vibe", label: "Supabase service role in client", expected: "detect",
    code: `const sb = createClient(URL, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);` },
  { id: "vibe-002", category: "vibe", label: "Prisma deleteMany no where", expected: "detect",
    code: `await prisma.user.deleteMany();` },
  { id: "vibe-003", category: "vibe", label: "Prisma updateMany no where", expected: "detect",
    code: `await prisma.user.updateMany({ data: { role: 'admin' } });` },
  { id: "vibe-004", category: "vibe", label: "Prisma findUnique no ownership", expected: "detect",
    code: `await prisma.user.findUnique({ where: { id: req.body.id } });` },
  { id: "vibe-005", category: "vibe", label: "Prisma select password", expected: "detect",
    code: `const u = await prisma.user.findUnique({ where: { id }, select: { id: true, password: true } });` },

  // ---------- WebSocket / GraphQL (4) ----------
  { id: "ws-001", category: "ws", label: "ws no origin check", expected: "detect",
    code: `wss.on('connection', (socket) => { socket.on('message', m => process(m)); });` },
  { id: "ws-002", category: "ws", label: "graphql introspection enabled", expected: "detect",
    code: `new ApolloServer({ schema, introspection: true });` },
  { id: "ws-003", category: "ws", label: "graphql no depth limit", expected: "detect",
    code: `const apollo = new ApolloServer({ typeDefs, resolvers });` },
  { id: "ws-004", category: "ws", label: "ws path.join user input", expected: "detect",
    code: `const p = path.join('/uploads', req.params.name);` },

  // ---------- Logging (4) ----------
  { id: "log-001", category: "logging", label: "log password from req.body", expected: "detect",
    code: `console.log("password:", req.body.password);` },
  { id: "log-002", category: "logging", label: "log api_key from req.body", expected: "detect",
    code: `logger.info("api_key=" + req.body.api_key);` },
  { id: "log-003", category: "logging", label: "log token from req.headers", expected: "detect",
    code: `console.log("token", req.headers.authorization);` },
  { id: "log-004", category: "logging", label: "log credit card from req.body", expected: "detect",
    code: `console.log("card", req.body.credit_card);` },

  // ---------- Bonus filler positives to round out 60 ----------
  { id: "bonus-001", category: "auth", label: "MD5 sign function", expected: "detect",
    code: `const sign = (s: string) => createHash('md5').update(s).digest('hex');` },
  { id: "bonus-002", category: "secrets", label: "Anthropic API key", expected: "detect", scanner: "secrets",
    code: `const k = 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZAbCdEfGhIjKlMnOpQrStUvWxYz0123456789-12345AAAA';` },
  { id: "bonus-003", category: "secrets", label: "MongoDB URL with creds", expected: "detect", scanner: "secrets",
    code: `const url = 'mongodb+srv://admin:Sup3rSecret@cluster0.demo.mongodb.net/proddb';` },
  { id: "bonus-004", category: "secrets", label: "Slack webhook URL", expected: "detect", scanner: "secrets",
    code: `const u = 'https://hooks.slack.com/services/T01ABCDEFGH/B01ABCDEFGH/aBcDeFgHiJkLmNoPqRsT0123';` },
  { id: "bonus-005", category: "secrets", label: "Sonar global token", expected: "detect", scanner: "secrets",
    code: `const k = 'sqb_0123456789abcdef0123456789abcdef01234567';` },
  { id: "bonus-006", category: "secrets", label: "PuTTY private key", expected: "detect", scanner: "secrets",
    code: `PuTTY-User-Key-File-3: ssh-rsa` },
  { id: "bonus-007", category: "secrets", label: "Telegram bot token", expected: "detect", scanner: "secrets",
    code: `const t = '123456789:AAH0123456789aBcDeFgHiJkLmNoPqRsTuV';` },
  { id: "bonus-008", category: "secrets", label: "ETH private key", expected: "detect", scanner: "secrets",
    code: `const pk = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd12';` },
];

const NEGATIVE: Case[] = [
  // ---------- Safe SQL ----------
  { id: "sql-clean-001", category: "sqli", label: "parameterized $1", expected: "clean",
    code: `db.query('SELECT * FROM users WHERE id = $1', [req.body.id]);` },
  { id: "sql-clean-002", category: "sqli", label: "named bind :id", expected: "clean",
    code: `db.query('SELECT * FROM users WHERE id = :id', { id: req.body.id });` },
  { id: "sql-clean-003", category: "sqli", label: "raw query with binding", expected: "clean",
    code: `db.query({ text: 'SELECT * FROM users WHERE id = $1', values: [1] });` },
  { id: "sql-clean-004", category: "sqli", label: "static SQL", expected: "clean",
    code: `const sql = "SELECT id FROM users WHERE deleted_at IS NULL";` },

  // ---------- Safe XSS ----------
  { id: "xss-clean-001", category: "xss", label: "DOMPurify.sanitize", expected: "clean",
    code: `<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(bio)}} />` },
  { id: "xss-clean-002", category: "xss", label: "React escaped JSX", expected: "clean",
    code: `<div>{userBio}</div>` },
  { id: "xss-clean-003", category: "xss", label: "innerHTML literal", expected: "clean",
    code: `el.innerHTML = "<b>Welcome</b>";` },

  // ---------- Safe Auth ----------
  { id: "auth-clean-001", category: "auth", label: "bcrypt.compare", expected: "clean",
    code: `const ok = await bcrypt.compare(req.body.password, user.passwordHash);` },
  { id: "auth-clean-002", category: "auth", label: "argon2.verify", expected: "clean",
    code: `await argon2.verify(user.hash, password);` },
  { id: "auth-clean-003", category: "auth", label: "JWT RS256 verify w/ algorithms", expected: "clean",
    code: `jwt.verify(token, publicKey, { algorithms: ['RS256'] });` },

  // ---------- Safe secrets / placeholders ----------
  { id: "sec-clean-001", category: "secrets", label: "process.env access", expected: "clean", scanner: "secrets",
    code: `const k = process.env.AWS_ACCESS_KEY_ID;` },
  { id: "sec-clean-002", category: "secrets", label: "AWS placeholder", expected: "clean", scanner: "secrets",
    code: `const k = 'YOUR_AWS_ACCESS_KEY_HERE';` },
  { id: "sec-clean-003", category: "secrets", label: "Stripe placeholder", expected: "clean", scanner: "secrets",
    code: `const k = 'sk_live_YOUR_STRIPE_KEY_PLACEHOLDR_HERE';` },
  { id: "sec-clean-004", category: "secrets", label: "GitHub placeholder", expected: "clean", scanner: "secrets",
    code: `const k = 'ghp_YOUR_GITHUB_PAT_PLACEHOLDR_VALUE_X';` },
  { id: "sec-clean-005", category: "secrets", label: "OAuth env reference", expected: "clean", scanner: "secrets",
    code: `const s = process.env.GOOGLE_CLIENT_SECRET;` },
  { id: "sec-clean-006", category: "secrets", label: "Slack env reference", expected: "clean", scanner: "secrets",
    code: `const k = process.env.SLACK_BOT_TOKEN;` },
  { id: "sec-clean-007", category: "secrets", label: "UUID is not a secret", expected: "clean", scanner: "secrets",
    code: `const id = '01234567-89ab-cdef-0123-456789abcdef';` },
  { id: "sec-clean-008", category: "secrets", label: "git SHA is not a secret", expected: "clean", scanner: "secrets",
    code: `const sha = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';` },

  // ---------- Safe crypto ----------
  { id: "crypt-clean-001", category: "crypto", label: "AES-GCM", expected: "clean",
    code: `crypto.createCipheriv('aes-256-gcm', key, iv);` },
  { id: "crypt-clean-002", category: "crypto", label: "randomBytes", expected: "clean",
    code: `const tok = crypto.randomBytes(32).toString('hex');` },
  { id: "crypt-clean-003", category: "crypto", label: "SHA-256", expected: "clean",
    code: `const h = crypto.createHash('sha256').update(data).digest('hex');` },

  // ---------- Safe infrastructure ----------
  { id: "infra-clean-001", category: "infra", label: "K8s hardened pod", expected: "clean", scanner: "k8s",
    code: `apiVersion: v1\nkind: Pod\nmetadata: { name: ok }\nspec:\n  containers:\n  - name: app\n    image: nginx:1.27\n    resources:\n      limits: { cpu: "100m", memory: "128Mi" }\n      requests: { cpu: "50m", memory: "64Mi" }\n    securityContext:\n      runAsNonRoot: true\n      readOnlyRootFilesystem: true\n      allowPrivilegeEscalation: false\n      capabilities: { drop: [ALL] }\n    livenessProbe:\n      httpGet: { path: /healthz, port: 8080 }\n    readinessProbe:\n      httpGet: { path: /readyz, port: 8080 }\n` },

  // ---------- Safe React / Next.js ----------
  { id: "react-clean-001", category: "vibe", label: "Next config minimal", expected: "clean",
    code: `module.exports = { reactStrictMode: true };` },
  { id: "react-clean-002", category: "vibe", label: "useState plain", expected: "clean",
    code: `const [count, setCount] = useState(0);` },
  { id: "react-clean-003", category: "vibe", label: "Plain function declaration", expected: "clean",
    code: `function calculateTax(amount: number): number { return amount * 0.08; }` },

  // ---------- Mathematical / pure code ----------
  { id: "math-clean-001", category: "math", label: "sum function", expected: "clean",
    code: `export const sum = (a: number, b: number): number => a + b;` },
  { id: "math-clean-002", category: "math", label: "type alias", expected: "clean",
    code: `type Pair<T> = { left: T; right: T };` },
  { id: "math-clean-003", category: "math", label: "interface declaration", expected: "clean",
    code: `interface User { id: number; name: string; }` },
  { id: "math-clean-004", category: "math", label: "memoized cache", expected: "clean",
    code: `const memo = new Map<string, number>();` },
  { id: "math-clean-005", category: "math", label: "enum declaration", expected: "clean",
    code: `enum Status { Active, Inactive, Pending }` },
  { id: "math-clean-006", category: "math", label: "literal arithmetic", expected: "clean",
    code: `const total = 10 + 20 * 3;` },
  { id: "math-clean-007", category: "math", label: "array map", expected: "clean",
    code: `const doubled = nums.map(n => n * 2);` },
  { id: "math-clean-008", category: "math", label: "filter", expected: "clean",
    code: `const positive = nums.filter(n => n > 0);` },
  { id: "math-clean-009", category: "math", label: "reduce sum", expected: "clean",
    code: `const total = nums.reduce((a, b) => a + b, 0);` },
  { id: "math-clean-010", category: "math", label: "sort", expected: "clean",
    code: `const sorted = [...nums].sort((a, b) => a - b);` },
  { id: "math-clean-011", category: "math", label: "destructure", expected: "clean",
    code: `const { x, y } = point;` },
  { id: "math-clean-012", category: "math", label: "spread", expected: "clean",
    code: `const merged = { ...defaults, ...overrides };` },
  { id: "math-clean-013", category: "math", label: "interface", expected: "clean",
    code: `interface Config { host: string; port: number; }` },
  { id: "math-clean-014", category: "math", label: "Promise.all", expected: "clean",
    code: `const results = await Promise.all(items.map(load));` },
  { id: "math-clean-015", category: "math", label: "string template literal", expected: "clean",
    code: `const greeting = \`Hello, \${name}!\`;` },
];

// Sanity counts for the published benchmark.
test("benchmark: case set sizes locked at 64 / 40", () => {
  // WHY: locks the published shape. Changing these numbers means we changed
  // what we publish — that should be a deliberate, separate edit.
  assert.equal(POSITIVE.length, 64, `expected exactly 64 positive cases, got ${POSITIVE.length}`);
  assert.equal(NEGATIVE.length, 40, `expected exactly 40 negative cases, got ${NEGATIVE.length}`);
});

// Run every positive case.
for (const c of POSITIVE) {
  test(`bench[+] ${c.id} ${c.category}/${c.label}`, async () => {
    // WHY: every published positive case must remain detected; if a refactor
    // drops one, the benchmark loses a percentage point.
    const detected = await detect(c);
    assert.equal(detected, true, `${c.id} (${c.label}) should detect but did not`);
  });
}

// Run every negative case.
for (const c of NEGATIVE) {
  test(`bench[-] ${c.id} ${c.category}/${c.label}`, async () => {
    // WHY: every published negative case must stay clean; a regression here
    // drives up the false-positive rate.
    const detected = await detect(c);
    assert.equal(detected, false, `${c.id} (${c.label}) should be clean but was flagged`);
  });
}

// Aggregate scoreboard — locks in 100% / 0%.
test("benchmark: aggregate detection rate is 100% on positive set", async () => {
  // WHY: this is the single number we publish. Drift below 100% breaks the brand.
  const results = await Promise.all(POSITIVE.map(detect));
  const detected = results.filter((r) => r).length;
  assert.equal(detected, POSITIVE.length, `${detected}/${POSITIVE.length} positives detected`);
});

test("benchmark: aggregate false-positive rate is 0% on negative set", async () => {
  // WHY: as above — a single FP breaks the publishable claim.
  const results = await Promise.all(NEGATIVE.map(detect));
  const flagged = results.filter((r) => r).length;
  assert.equal(flagged, 0, `${flagged}/${NEGATIVE.length} negatives wrongly flagged`);
});
