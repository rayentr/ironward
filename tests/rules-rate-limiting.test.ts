import { test } from "node:test";
import assert from "node:assert/strict";
import { RATE_LIMITING_RULES } from "../src/rules/rate-limiting.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = RATE_LIMITING_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    return true;
  }
  return false;
}

// WHY: vanilla register route with no limiter — must fire.
test("rate-limit-missing-register: register without limiter is flagged", () => {
  const code = `app.post('/register', async (req, res) => { await createUser(req.body); res.sendStatus(201); });`;
  assert.equal(fire(code, "rate-limit-missing-register"), true);
});

// WHY: same route with rateLimit middleware in the registration line must not flag.
test("rate-limit-missing-register: register with rateLimit() is NOT flagged", () => {
  const code = `app.post('/register', rateLimit({ windowMs: 60000, max: 5 }), async (req, res) => { await createUser(req.body); });`;
  assert.equal(fire(code, "rate-limit-missing-register"), false);
});

test("rate-limit-missing-register: metadata is well-formed", () => {
  // WHY: lock severity at high — account creation flood is a real abuse vector.
  const r = RATE_LIMITING_RULES.find((x) => x.id === "rate-limit-missing-register")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: forgot-password is the most-abused enumeration / spam endpoint.
test("rate-limit-missing-password-reset: forgot-password without limiter is flagged", () => {
  const code = `app.post('/forgot-password', async (req, res) => { await sendResetEmail(req.body.email); });`;
  assert.equal(fire(code, "rate-limit-missing-password-reset"), true);
});

// WHY: throttle middleware should suppress.
test("rate-limit-missing-password-reset: route guarded by throttle is NOT flagged", () => {
  const code = `app.post('/reset-password', throttle, async (req, res) => { await reset(req.body); });`;
  assert.equal(fire(code, "rate-limit-missing-password-reset"), false);
});

test("rate-limit-missing-password-reset: metadata is well-formed", () => {
  // WHY: severity high — email bombing + enumeration impact.
  const r = RATE_LIMITING_RULES.find((x) => x.id === "rate-limit-missing-password-reset")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: brute force of a 6-digit code without rate limit is critical.
test("rate-limit-missing-otp: verify-otp without limiter is flagged", () => {
  const code = `app.post('/verify-otp', async (req, res) => { ok(verifyOtp(req.body.code)); });`;
  assert.equal(fire(code, "rate-limit-missing-otp"), true);
});

// WHY: limiter must suppress.
test("rate-limit-missing-otp: verify-otp with limiter is NOT flagged", () => {
  const code = `app.post('/verify-otp', limiter, async (req, res) => { ok(verifyOtp(req.body.code)); });`;
  assert.equal(fire(code, "rate-limit-missing-otp"), false);
});

test("rate-limit-missing-otp: metadata is critical (2FA bypass)", () => {
  // WHY: brute-force of 6-digit code is critical; downgrade would be dangerous.
  const r = RATE_LIMITING_RULES.find((x) => x.id === "rate-limit-missing-otp")!;
  assert.equal(r.severity, "critical");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: token-creation route with no limiter — must fire.
test("rate-limit-missing-api-key-gen: api-keys POST without limiter is flagged", () => {
  const code = `app.post('/api-keys', async (req, res) => { res.json(await createKey(req.user.id)); });`;
  assert.equal(fire(code, "rate-limit-missing-api-key-gen"), true);
});

// WHY: slowDown should suppress.
test("rate-limit-missing-api-key-gen: api-keys with slowDown is NOT flagged", () => {
  const code = `app.post('/api-keys', slowDown({ delayAfter: 3 }), async (req, res) => { res.json(await createKey(req.user.id)); });`;
  assert.equal(fire(code, "rate-limit-missing-api-key-gen"), false);
});

test("rate-limit-missing-api-key-gen: metadata is well-formed", () => {
  // WHY: severity high — credential generation flood is real, not theoretical.
  const r = RATE_LIMITING_RULES.find((x) => x.id === "rate-limit-missing-api-key-gen")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: passwordless / magic-link is heavy on email and tokens.
test("rate-limit-missing-magic-link: magic-link without limiter is flagged", () => {
  const code = `app.post('/magic-link', async (req, res) => { await sendMagicLink(req.body.email); });`;
  assert.equal(fire(code, "rate-limit-missing-magic-link"), true);
});

// WHY: limiter must suppress.
test("rate-limit-missing-magic-link: passwordless with limiter is NOT flagged", () => {
  const code = `app.post('/passwordless', limiter, async (req, res) => { await sendMagicLink(req.body.email); });`;
  assert.equal(fire(code, "rate-limit-missing-magic-link"), false);
});

test("rate-limit-missing-magic-link: metadata is well-formed", () => {
  // WHY: severity high — abuse of the email channel + token flood.
  const r = RATE_LIMITING_RULES.find((x) => x.id === "rate-limit-missing-magic-link")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
