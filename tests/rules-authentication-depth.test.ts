import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// =============================================================================
// JWT alg: 'none' case variants (rule: jwt-alg-none)
// =============================================================================

// WHY: lower-case canonical form must fire.
test("auth-depth: alg: 'none' lower-case is flagged", () => {
  const code = `jwt.verify(token, secret, { algorithms: ['HS256'], alg: 'none' });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-alg-none"));
});

// WHY: upper-case 'NONE' must also fire — the rule's regex uses /i flag, so
// case variants should all hit. Locks in current behavior.
test("auth-depth: alg: 'NONE' upper-case is flagged", () => {
  const code = `verify(token, { alg: 'NONE' });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-alg-none"));
});

// WHY: title-case 'None' is the third common variant — same case-insensitive
// expectation.
test("auth-depth: alg: 'None' title-case is flagged", () => {
  const code = `verify(token, { alg: 'None' });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-alg-none"));
});

// WHY: a single source containing all three variants must produce at least 2
// distinct findings (one per line). Locks in case-insensitivity holistically.
test("auth-depth: alg-none case variants produce >=2 findings across lines", () => {
  const code = `
    const a = { alg: 'none' };
    const b = { alg: 'NONE' };
    const c = { alg: 'None' };
  `;
  const f = scanCodeRules(code);
  const hits = f.filter((x) => x.ruleId === "jwt-alg-none");
  // TODO: actual behavior — engine dedupes by ruleId+line, so three distinct
  // lines => three findings. Lock in >=2 to be resilient if a line ever merges.
  assert.ok(hits.length >= 2, `expected >=2 alg-none findings, got ${hits.length}`);
});

// =============================================================================
// Plaintext password compare (rule: auth-plaintext-password-compare)
// =============================================================================

// WHY: == form must fire — a regression where the rule only catches === would
// silently miss half of legacy code.
test("auth-depth: user.password == req.body.password is flagged", () => {
  const code = `if (user.password == req.body.password) login();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "auth-plaintext-password-compare"));
});

// WHY: === form is the canonical case — must fire.
test("auth-depth: user.password === req.body.password is flagged", () => {
  const code = `if (user.password === req.body.password) login();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "auth-plaintext-password-compare"));
});

// WHY: Java-style .equals() is a common port pattern. Document the gap so
// devs know the rule is JS-equality-shaped only.
test("auth-depth: user.password.equals(req.body.password) Java-style is NOT flagged (documented gap)", () => {
  const code = `if (user.password.equals(req.body.password)) login();`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — regex covers ==/=== only. .equals() is Java-style
  // and would need a separate rule. Lock in current behavior.
  assert.ok(!f.some((x) => x.ruleId === "auth-plaintext-password-compare"));
});

// =============================================================================
// Timing-unsafe comparison (rule: timing-unsafe-comparison)
// =============================================================================

// WHY: each of the four sensitive identifiers (password, token, hash, secret)
// should fire — generic timing-attack coverage.
test("auth-depth: password/token/secret == req.body.x are flagged for timing", () => {
  // hash is NOT in the rule's identifier list (rule covers password|token|secret|apiKey|api_key|hmac|signature)
  for (const ident of ["password", "token", "secret"]) {
    const code = `if (${ident} === req.body.x) {}`;
    const f = scanCodeRules(code);
    assert.ok(
      f.some((x) => x.ruleId === "timing-unsafe-comparison"),
      `${ident} should trip timing-unsafe-comparison`,
    );
  }
});

// WHY: 'hash' is not in the timing-unsafe-comparison identifier list. Document
// the gap so devs don't assume coverage.
test("auth-depth: hash === req.body.x is NOT flagged by timing rule (documented gap)", () => {
  const code = `if (hash === req.body.x) {}`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — 'hash' is not in the rule's identifier set
  // (password|token|secret|apiKey|api_key|hmac|signature). Add 'hash' to the
  // rule if this gap matters.
  assert.ok(!f.some((x) => x.ruleId === "timing-unsafe-comparison"));
});

// WHY: the safe alternative (timingSafeEqual) must NOT fire — verifies the
// rule isn't accidentally matching the safe pattern.
test("auth-depth: crypto.timingSafeEqual(...) is NOT flagged", () => {
  const code = `if (crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) ok();`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "timing-unsafe-comparison"));
});

// =============================================================================
// OAuth state (rules: oauth-passport-no-state-option, oauth-callback-no-state-validation)
// =============================================================================

// WHY: passport.authenticate with non-state options must fire (no state: true).
test("auth-depth: passport.authenticate without state is flagged", () => {
  const code = `passport.authenticate('google', { scope: ['profile'] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "oauth-passport-no-state-option"));
});

// WHY: with state: true must NOT fire — safe pattern.
test("auth-depth: passport.authenticate with state: true is NOT flagged", () => {
  const code = `passport.authenticate('google', { scope: ['profile'], state: true });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "oauth-passport-no-state-option"));
});

// WHY: a custom express handler that reads req.query.code without checking
// req.session.state must fire the callback-no-state-validation rule.
test("auth-depth: custom OAuth callback without state check is flagged", () => {
  const code = `
    app.get('/cb', async (req, res) => {
      const c = req.query.code;
      const tokens = await exchange(c);
      res.redirect('/');
    });
  `;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "oauth-callback-no-state-validation"));
});

// =============================================================================
// JWT decode vs verify (rule: jwt-decode-not-verify)
// =============================================================================

// WHY: jwt.decode(token) must fire — the whole point of the rule is to
// distinguish decode (no signature check) from verify.
test("auth-depth: jwt.decode(token) is flagged", () => {
  const code = `const payload = jwt.decode(token);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-decode-not-verify"));
});

// WHY: jwt.verify(token, secret, { algorithms: ['HS256'] }) must NOT fire the
// decode rule — verify is the safe path. (It may trip other rules; we only
// assert decode-not-verify is absent.)
test("auth-depth: jwt.verify(token, secret, { algorithms: [...] }) is NOT flagged by decode rule", () => {
  const code = `const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-decode-not-verify"));
});

// =============================================================================
// JWT without expiresIn (rule: jwt-sign-no-expires-in)
// =============================================================================

// WHY: jwt.sign(payload, secret) without options must fire.
test("auth-depth: jwt.sign(payload, secret) without options is flagged", () => {
  const code = `jwt.sign({ sub: userId }, secret);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-sign-no-expires-in"));
});

// WHY: jwt.sign with expiresIn option must NOT fire — safe pattern.
test("auth-depth: jwt.sign with { expiresIn: '1h' } is NOT flagged", () => {
  const code = `jwt.sign({ sub: userId }, secret, { expiresIn: '1h' });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-sign-no-expires-in"));
});

// =============================================================================
// ironward-ignore suppression
// =============================================================================

// WHY: an inline `// ironward-ignore` comment on the same line must suppress
// the finding. This is the engine's primary opt-out mechanism.
test("auth-depth: jwt.decode with // ironward-ignore on same line is suppressed", () => {
  const code = `const payload = jwt.decode(token); // ironward-ignore`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-decode-not-verify"));
});
