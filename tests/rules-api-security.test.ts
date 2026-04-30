import { test } from "node:test";
import assert from "node:assert/strict";
import { API_SECURITY_RULES } from "../src/rules/api-security.ts";

function findingsFor(code: string, ruleId: string): Array<{ index: number }> {
  const rule = API_SECURITY_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  const out: Array<{ index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    out.push({ index: m.index });
    if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
  }
  return out;
}

const ruleById = (id: string) => API_SECURITY_RULES.find((r) => r.id === id);

// =============== api-route-no-auth ===============

// WHY: a route handler that calls db.query with no auth middleware is the
// canonical broken-access-control bug we want to catch.
test("api-route-no-auth: db.query with no auth check is flagged", () => {
  const code = `app.get('/api/users', async (req, res) => {
    const rows = await db.query('SELECT * FROM users');
    res.json(rows);
  });`;
  assert.ok(findingsFor(code, "api-route-no-auth").length >= 1);
});

// WHY: identical handler shape but with requireAuth middleware should NOT fire.
test("api-route-no-auth: handler with requireAuth middleware is NOT flagged", () => {
  const code = `app.get('/api/users', requireAuth, async (req, res) => {
    const rows = await prisma.user.findMany({ take: 10 });
    res.json(rows);
  });`;
  assert.equal(findingsFor(code, "api-route-no-auth").length, 0);
});

// WHY: metadata locks in severity + OWASP tag so CLI exit codes don't drift.
test("api-route-no-auth: metadata is high + A01", () => {
  const r = ruleById("api-route-no-auth")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A01:2021 Broken Access Control");
});

// =============== api-excessive-data-exposure ===============

// WHY: returning the raw user record almost always leaks password hash + tokens.
test("api-excessive-data-exposure: res.json(user) is flagged", () => {
  const code = `res.json(user);`;
  assert.ok(findingsFor(code, "api-excessive-data-exposure").length >= 1);
});

// WHY: a projected response shape is the safe pattern; must not fire.
test("api-excessive-data-exposure: res.json({ id, name }) is NOT flagged", () => {
  const code = `res.json({ id: user.id, name: user.name });`;
  assert.equal(findingsFor(code, "api-excessive-data-exposure").length, 0);
});

// WHY: confirms severity + OWASP for the excessive-exposure rule.
test("api-excessive-data-exposure: metadata is high + A03", () => {
  const r = ruleById("api-excessive-data-exposure")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A03:2021 Sensitive Data Exposure");
});

// =============== api-findmany-no-limit ===============

// WHY: unbounded findMany is a real DoS / data-exposure path; must fire.
test("api-findmany-no-limit: prisma.user.findMany() with no take is flagged", () => {
  const code = `const users = await prisma.user.findMany();`;
  assert.ok(findingsFor(code, "api-findmany-no-limit").length >= 1);
});

// WHY: a take: 100 cap is the safe pattern; rule must not fire.
test("api-findmany-no-limit: findMany({ take: 100 }) is NOT flagged", () => {
  const code = `const users = await prisma.user.findMany({ take: 100 });`;
  assert.equal(findingsFor(code, "api-findmany-no-limit").length, 0);
});

// WHY: pagination guidance is medium severity — confirm it stays that way.
test("api-findmany-no-limit: metadata is medium severity", () => {
  const r = ruleById("api-findmany-no-limit")!;
  assert.equal(r.severity, "medium");
});

// =============== api-multer-no-file-validation ===============

// WHY: multer with bare storage and no fileFilter/limits is the upload-DoS bug.
test("api-multer-no-file-validation: multer({ storage }) with no filter is flagged", () => {
  const code = `const upload = multer({ storage: storage });`;
  assert.ok(findingsFor(code, "api-multer-no-file-validation").length >= 1);
});

// WHY: same call with fileFilter + limits should be safe.
test("api-multer-no-file-validation: multer with fileFilter and limits is NOT flagged", () => {
  const code = `const upload = multer({ storage: storage, fileFilter: ff, limits: { fileSize: 1024 } });`;
  assert.equal(findingsFor(code, "api-multer-no-file-validation").length, 0);
});

// WHY: severity + owasp lock-in for upload misconfig.
test("api-multer-no-file-validation: metadata is high + A04", () => {
  const r = ruleById("api-multer-no-file-validation")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A04:2021 Insecure Design");
});

// =============== api-cors-credentials-wildcard ===============

// WHY: the explicit '*'+credentials combo is invalid per the CORS spec.
test("api-cors-credentials-wildcard: cors with origin '*' and credentials true is flagged", () => {
  const code = `app.use(cors({ origin: '*', credentials: true }));`;
  assert.ok(findingsFor(code, "api-cors-credentials-wildcard").length >= 1);
});

// WHY: explicit allowlist with credentials is safe; rule must stay quiet.
test("api-cors-credentials-wildcard: cors with explicit origin is NOT flagged", () => {
  const code = `app.use(cors({ origin: 'https://app.example.com', credentials: true }));`;
  assert.equal(findingsFor(code, "api-cors-credentials-wildcard").length, 0);
});

// WHY: severity + owasp for the cors rule.
test("api-cors-credentials-wildcard: metadata is medium + A05", () => {
  const r = ruleById("api-cors-credentials-wildcard")!;
  assert.equal(r.severity, "medium");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== api-http-verb-tampering ===============

// WHY: dispatching writes by req.method comparison is the verb-tampering shape.
test("api-http-verb-tampering: if (req.method === 'POST') is flagged", () => {
  const code = `if (req.method === 'POST') { await createUser(req.body); }`;
  assert.ok(findingsFor(code, "api-http-verb-tampering").length >= 1);
});

// WHY: a normal app.post route uses the framework router — must not fire.
test("api-http-verb-tampering: app.post route is NOT flagged", () => {
  const code = `app.post('/api/x', async (req, res) => { await createUser(req.body); });`;
  assert.equal(findingsFor(code, "api-http-verb-tampering").length, 0);
});

// WHY: severity + owasp for verb tampering.
test("api-http-verb-tampering: metadata is medium + A01", () => {
  const r = ruleById("api-http-verb-tampering")!;
  assert.equal(r.severity, "medium");
  assert.equal(r.owasp, "A01:2021 Broken Access Control");
});

// =============== api-unrestricted-resource-creation ===============

// WHY: a POST that creates records with no rate limiter mention is the
// account-creation-spam shape we want to flag.
test("api-unrestricted-resource-creation: app.post + create() with no limiter is flagged", () => {
  const code = `app.post('/api/users', async (req, res) => {
    const u = await prisma.user.create({ data: req.body });
    res.json(u);
  });`;
  assert.ok(findingsFor(code, "api-unrestricted-resource-creation").length >= 1);
});

// WHY: same handler with rateLimit middleware nearby should NOT fire.
test("api-unrestricted-resource-creation: rateLimit nearby suppresses the rule", () => {
  const code = `app.post('/api/users', rateLimit({ max: 5 }), async (req, res) => {
    const u = await prisma.user.create({ data: req.body });
    res.json(u);
  });`;
  assert.equal(findingsFor(code, "api-unrestricted-resource-creation").length, 0);
});

// WHY: severity + owasp for unrestricted creation.
test("api-unrestricted-resource-creation: metadata is high + A04", () => {
  const r = ruleById("api-unrestricted-resource-creation")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A04:2021 Insecure Design");
});
