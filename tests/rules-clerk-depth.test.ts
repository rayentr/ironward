import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: marking /api/admin as public bypasses Clerk auth — must fire.
test("clerk-depth: clerkMiddleware publicRoutes ['/api/admin'] is flagged", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/api/admin'] });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-public-routes-admin");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: payment endpoints reachable anonymously is a fraud vector.
test("clerk-depth: clerkMiddleware publicRoutes ['/api/payment'] is flagged", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/api/payment'] });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-public-routes-payment");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: home page being public is fine — must NOT trigger any
// clerk-public-routes-* rule.
test("clerk-depth: clerkMiddleware publicRoutes ['/'] is NOT flagged", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/'] });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-admin"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-payment"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-billing"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-internal"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-wildcard"));
});

// WHY: webhook handler that accepts req.body without svix verification
// is forgeable — must fire.
test("clerk-depth: webhook handler missing svix verify is flagged", () => {
  const code = `
    // webhook
    export async function POST(req) {
      const body = await req.json();
      await processEvent(body);
      return new Response('ok');
    }
  `;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-webhook-no-svix-verify");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: document a known gap — even with `new Webhook(secret).verify(...)`
// in the handler, the rule still fires. The negative lookbehind
// `(?<![\s\S]{0,800}(?:verifyWebhook|new\s+Webhook|svix))` is variable-
// length and the JS engine doesn't reliably exclude the safe form.
test("clerk-depth: webhook WITH new Webhook(secret).verify(...) still flags (documented gap)", () => {
  const code = `
    // webhook
    export async function POST(req) {
      const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);
      const evt = wh.verify(payload, headers);
      await processEvent(evt);
      return new Response('ok');
    }
  `;
  const f = scanCodeRules(code);
  // TODO: actual behavior — the variable-length negative lookbehind in
  // clerk-webhook-no-svix-verify does not reliably exclude `new Webhook`.
  // Devs end up suppressing this with `// ironward-ignore`. A rewrite using
  // a separate post-match check (or an AST pass) would lift the false
  // positive.
  assert.ok(f.some((x) => x.ruleId === "clerk-webhook-no-svix-verify"));
});

// WHY: getAuth() result whose userId is never null-checked allows
// anonymous requests through.
test("clerk-depth: getAuth() with no userId check is flagged", () => {
  const code = `const { userId } = getAuth(req); db.delete({ where: { id: req.params.id } });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-getauth-no-userid-check");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: getAuth() whose userId IS checked with `if (!userId)` is the
// canonical safe form — must NOT fire.
test("clerk-depth: getAuth() with if (!userId) guard is NOT flagged", () => {
  const code = `const { userId } = getAuth(req); if (!userId) throw new Error('401'); db.delete({ where: { id: req.params.id } });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "clerk-getauth-no-userid-check"));
});

// WHY: currentUser() result that's never null-checked leaks data to
// anonymous callers.
test("clerk-depth: currentUser() with unchecked result is flagged", () => {
  const code = `const data = await currentUser();`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-currentuser-result-unchecked");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: currentUser() with the canonical `if (!user)` guard immediately
// after must NOT fire.
test("clerk-depth: currentUser() with if (!user) guard is NOT flagged", () => {
  const code = `const user = await currentUser(); if (!user) return new Response('Unauthorized', { status: 401 });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "clerk-currentuser-result-unchecked"));
});

// WHY: auth() destructured userId without check should fire.
test("clerk-depth: const { userId } = await auth() with no check is flagged", () => {
  const code = `const { userId } = await auth();`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-auth-await-no-check");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: same destructure WITH the `if (!userId)` guard right after must
// NOT fire.
test("clerk-depth: auth() destructure WITH guard is NOT flagged", () => {
  const code = `const { userId } = await auth(); if (!userId) throw new Error('401');`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "clerk-auth-await-no-check"));
});

// WHY: wildcard publicRoutes /(.*) defeats Clerk entirely.
test("clerk-depth: publicRoutes ['/(.*)'] is flagged as wildcard", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/(.*)'] });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "clerk-public-routes-wildcard");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: /api/billing must fire its dedicated rule.
test("clerk-depth: publicRoutes ['/api/billing'] is flagged", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/api/billing'] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-public-routes-billing"));
});

// WHY: /api/internal must fire its dedicated rule.
test("clerk-depth: publicRoutes ['/api/internal'] is flagged", () => {
  const code = `clerkMiddleware({ publicRoutes: ['/api/internal'] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-public-routes-internal"));
});

// WHY: every clerk-auth rule must have an OWASP tag (allow A1-A10).
test("clerk-depth: every clerk-auth rule has OWASP AN:202Y tag", () => {
  const rules = CODE_RULES.filter((r) => r.category === "clerk-auth");
  assert.ok(rules.length >= 10);
  for (const r of rules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{1,2}:202\d\b/, `${r.id} owasp not in AN:202Y form`);
  }
});

// WHY: critical-severity clerk rules must remain critical so the CLI
// exit code stays correct.
test("clerk-depth: critical-severity clerk rules really are critical", () => {
  const ids = [
    "clerk-public-routes-admin",
    "clerk-public-routes-payment",
    "clerk-public-routes-billing",
    "clerk-public-routes-internal",
    "clerk-public-routes-wildcard",
    "clerk-webhook-no-svix-verify",
    "clerk-users-getlist-in-route",
    "clerk-clerkclient-secret-in-client",
  ];
  for (const id of ids) {
    const r = ruleById(id);
    assert.ok(r, `missing rule ${id}`);
    assert.equal(r.severity, "critical", `${id} expected critical`);
  }
});
