import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: jwt.sign with expiresIn is the canonical safe form. Must never trip
// the no-expires-in rule.
test("auth-depth: jwt.sign with expiresIn is NOT flagged", () => {
  const code = `jwt.sign({ sub: id }, secret, { expiresIn: '15m' });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-sign-no-expires-in"));
});

// WHY: jwt.verify with an explicit algorithms allowlist should be safe.
// Currently the rule's negative lookahead is anchored AFTER the `)` of the
// verify call, so an `algorithms` option inside the call body is missed.
test("auth-depth: jwt.verify with algorithms: ['HS256'] inside the call is NOT flagged", () => {
  // WHY: regression test for the v2.7.0 fix. The rule's regex now matches the entire
  // jwt.verify(...) invocation and a negativePattern checks the call for `algorithms:`.
  const code = `const p = jwt.verify(token, secret, { algorithms: ['HS256'] });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-verify-no-algorithms-option"),
    `expected NOT to flag — got: ${f.map((x) => x.ruleId).join(", ")}`);
});

test("auth-depth: jwt.verify WITHOUT algorithms option is still flagged", () => {
  // WHY: lock in that the v2.7.0 fix didn't accidentally turn the rule off entirely.
  const code = `const p = jwt.verify(token, secret);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-verify-no-algorithms-option"),
    `expected to flag — got: ${f.map((x) => x.ruleId).join(", ")}`);
});

// WHY: bcrypt.compare against a stored hash is the safe pattern; must not
// trip the plaintext-compare rule.
test("auth-depth: bcrypt.compare against a stored hash is NOT flagged", () => {
  const code = `const ok = await bcrypt.compare(req.body.password, user.passwordHash);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "auth-plaintext-password-compare"));
});

// WHY: crypto.timingSafeEqual is the safe pattern for token comparisons;
// must not be misclassified as plaintext compare or timing-unsafe compare.
test("auth-depth: crypto.timingSafeEqual is NOT flagged", () => {
  const code = `const ok = crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(provided));`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "timing-unsafe-comparison"));
  assert.ok(!f.some((x) => x.ruleId === "reset-token-equality-compare"));
});

// WHY: a long random session secret (>= 32 chars) is acceptable; must not
// trip the short-secret rule.
test("auth-depth: express-session with a 64-char random secret is NOT flagged", () => {
  const code = `app.use(session({
    secret: '7c2f7d6dca5b06ee2bb8a2b3a3d9b9e6f6a4dab7e7c1bf3b5a7c8a8a3a4b3c2a',
    cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
    resave: false,
    saveUninitialized: false,
  }));`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "express-session-short-secret"));
});

// WHY: res.cookie with httpOnly + secure + sameSite is the canonical safe
// pattern; must not trip the cookie rules.
test("auth-depth: res.cookie with httpOnly+secure+sameSite is NOT flagged", () => {
  const code = `res.cookie('session', sid, { httpOnly: true, secure: true, sameSite: 'lax' });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "cookie-session-name-no-httponly"));
  assert.ok(!f.some((x) => x.ruleId === "cookie-session-name-no-secure"));
  assert.ok(!f.some((x) => x.ruleId === "cookie-no-samesite"));
});

// WHY: an OAuth callback that *does* compare req.query.state to session must
// NOT trip the missing-state rule.
test("auth-depth: OAuth callback with state validation is NOT flagged", () => {
  const code = `const code = req.query.code; if (req.query.state !== req.session.state) throw new Error('csrf');`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "oauth-callback-no-state-validation"));
});

// WHY: critical/high auth rules must really be tagged that way.
test("auth-depth: critical-/high-severity auth rules carry the right severity in CODE_RULES", () => {
  const expectations: Array<[string, "critical" | "high"]> = [
    ["express-session-short-secret", "critical"],
    ["auth-plaintext-password-compare", "critical"],
    ["jwt-verify-no-algorithms-option", "high"],
    ["jwt-sign-no-expires-in", "high"],
    ["oauth-passport-no-state-option", "high"],
    ["reset-token-equality-compare", "high"],
    ["session-id-in-url-query", "high"],
  ];
  for (const [id, sev] of expectations) {
    const r = ruleById(id);
    assert.ok(r, `missing rule ${id}`);
    assert.equal(r.severity, sev, `${id} expected severity ${sev}`);
  }
});

// WHY: every authentication rule should declare a confidence value in band.
test("auth-depth: authentication rules carry sensible confidence values", () => {
  const authRules = CODE_RULES.filter((r) => r.category === "authentication");
  assert.ok(authRules.length >= 10);
  for (const r of authRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: every authentication rule should carry an OWASP A0X:202Y tag.
test("auth-depth: authentication rules have OWASP A0X:202Y tags", () => {
  const authRules = CODE_RULES.filter((r) => r.category === "authentication");
  for (const r of authRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});

// WHY: variant positive — express-session with a one-character secret should
// fire (boundary case, just past the 1-char minimum of the regex).
test("auth-depth: express-session with a 1-char secret is flagged", () => {
  const code = `app.use(session({ secret: 'x' }));`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "express-session-short-secret");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: variant positive — magic-link token from Math.random must fire.
test("auth-depth: magic-link token from Math.random is flagged", () => {
  const code = `const magicLink = Math.random().toString(36);`; // ironward-ignore
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "magic-link-token-short-weak"));
});

// WHY: variant positive — sessionId in URL must fire (covers JSESSIONID and
// case variants).
test("auth-depth: JSESSIONID in URL is flagged", () => {
  // WHY: regression test for the v2.7.0 fix that added ;jsessionid= path-param matching
  // for Java/Tomcat-style URLs.
  const code = `const link = "https://example.com/foo;JSESSIONID=abc123";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "session-id-in-url-query"),
    `expected session-id-in-url-query to flag JSESSIONID; got: ${f.map((x) => x.ruleId).join(", ")}`);
  // Sanity: ensure scan returned something iterable.
  const f2 = scanCodeRules(`const l = "https://example.com/p?sessionid=abc";`);
  assert.ok(f2.some((x) => x.ruleId === "session-id-in-url-query"));
  assert.ok(Array.isArray(f));
});

// WHY: confidence on each finding equals (or rule's confidence is at least)
// 60 for the higher-confidence auth rules. Catches an accidental confidence
// downgrade.
test("auth-depth: high-confidence auth rules really are >= 60", () => {
  const ids = [
    "express-session-short-secret",
    "auth-plaintext-password-compare",
    "jwt-verify-no-algorithms-option",
    "reset-token-equality-compare",
    "magic-link-token-short-weak",
  ];
  for (const id of ids) {
    const r = ruleById(id);
    assert.ok(r, id);
    assert.ok(r.confidence == null || r.confidence >= 60, `${id} confidence < 60`);
  }
});
