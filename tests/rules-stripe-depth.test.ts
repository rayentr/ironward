import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: variant positive — sk_live_ inside a function-call argument should
// still match (regex is context-free, but verify so a future "anchor" change
// doesn't break it).
test("stripe-depth: sk_live_ literal inside a function-call arg is flagged", () => {
  const code = `initStripe("sk_live_AbCdEfGhIjKlMnOpQrSt1234");`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "stripe-secret-key-literal-live");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: variant positive — sk_live_ embedded in a JSON literal must still
// fire. JSON files often slip past secret scanners.
test("stripe-depth: sk_live_ inside a JSON-style literal is flagged", () => {
  const code = `const cfg = { "stripeKey": "sk_live_AbCdEfGhIjKlMnOpQrSt1234" };`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-key-literal-live"));
});

// WHY: variant positive — template-literal interpolation around a sk_live_
// substring still matches (regex is literal-text-based).
test("stripe-depth: sk_live_ inside a template literal is flagged", () => {
  const code = "const k = `sk_live_AbCdEfGhIjKlMnOpQrSt1234`;";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-key-literal-live"));
});

// WHY: pk_test_ is a publishable test key — never a secret. Should NOT be
// flagged by sk_live_ / sk_test_ rules. Catches accidental over-broad regex.
test("stripe-depth: pk_test_ literal is NOT flagged by sk_ rules", () => {
  const code = `const k = "pk_test_AbCdEfGhIjKlMnOpQrSt1234";`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-secret-key-literal-live"));
  assert.ok(!f.some((x) => x.ruleId === "stripe-secret-key-literal-test"));
});

// WHY: server-side new Stripe(process.env.STRIPE_SECRET_KEY) is the canonical
// safe pattern; must never be flagged by stripe-secret-in-public-env.
test("stripe-depth: new Stripe(STRIPE_SECRET_KEY) server-only is NOT flagged", () => {
  const code = `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-secret-in-public-env"));
});

// WHY: a webhook handler that calls constructEvent should NOT trip the
// missing-constructEvent rule. The current rule's negative lookbehind
// over-matches on real webhook code that *does* call constructEvent.
test("stripe-depth: webhook properly verified with constructEvent is NOT flagged", () => {
  // WHY: this is the regression test for the v2.7.0 fix that replaced the buggy variable-length
  // negative lookbehind with a `negativePattern` engine feature. A safe handler must stay quiet.
  const code = `export async function POST(req) {
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  return Response.json({ received: true });
}`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-webhook-no-construct-event"),
    `expected stripe-webhook-no-construct-event to NOT fire on safe handler; got: ${f.map((x) => x.ruleId).join(", ")}`);
  assert.ok(!f.some((x) => x.ruleId === "stripe-webhook-no-signature-header"),
    `expected stripe-webhook-no-signature-header to NOT fire when stripe-signature is read; got: ${f.map((x) => x.ruleId).join(", ")}`);
});

// WHY: when amount is computed server-side from a database lookup, the
// payment-intent rule must stay quiet.
test("stripe-depth: paymentIntents.create with hardcoded server amount is NOT flagged", () => {
  const code = `await stripe.paymentIntents.create({ amount: 1999, currency: 'usd' });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-payment-intent-amount-from-body"));
});

// WHY: variant positive — paymentIntents.create reading req.body.amount is
// the canonical insecure pattern.
test("stripe-depth: paymentIntents.create with amount from req.body is flagged", () => {
  const code = `await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'usd' });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "stripe-payment-intent-amount-from-body");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: a refunds.create handler with no auth call should fire the
// stripe-refund-no-auth rule.
test("stripe-depth: refund triggered without auth check on the route is flagged", () => {
  const code = `export async function POST(req) {
  const { chargeId } = await req.json();
  return Response.json(await stripe.refunds.create({ charge: chargeId }));
}`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-refund-no-auth"));
});

// WHY: refund handler with getServerSession at the top should NOT fire.
test("stripe-depth: refund route with getServerSession is NOT flagged", () => {
  // WHY: regression test for the v2.7.0 fix — auth check appearing BEFORE refunds.create
  // must suppress stripe-refund-no-auth via the new negativePattern engine feature.
  const code = `export async function POST(req) {
  const session = await getServerSession();
  if (!session) return new Response('unauthorized', { status: 401 });
  const { chargeId } = await req.json();
  return Response.json(await stripe.refunds.create({ charge: chargeId }));
}`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-refund-no-auth"),
    `expected stripe-refund-no-auth to NOT fire when auth check precedes refund; got: ${f.map((x) => x.ruleId).join(", ")}`);
});

// WHY: every stripe critical rule must really be tagged critical so the CLI
// totals don't drift.
test("stripe-depth: critical-severity stripe rules are tagged critical in CODE_RULES", () => {
  const ids = [
    "stripe-secret-in-public-env",
    "stripe-secret-key-literal-live",
    "stripe-webhook-no-construct-event",
    "stripe-payment-intent-amount-from-body",
    "stripe-checkout-line-items-from-body",
    "stripe-checkout-amount-from-body",
    "stripe-confirm-customer-from-body",
    "stripe-refund-no-auth",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every stripe rule must declare a confidence in the documented band.
test("stripe-depth: stripe rules carry sensible confidence values", () => {
  const stripeRules = CODE_RULES.filter((r) => r.category === "stripe");
  assert.ok(stripeRules.length >= 14);
  for (const r of stripeRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: every stripe rule must carry an OWASP tag in A0X:202Y form.
test("stripe-depth: stripe rules have OWASP A0X:202Y tags", () => {
  const stripeRules = CODE_RULES.filter((r) => r.category === "stripe");
  for (const r of stripeRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not A0X:202Y`);
  }
});

// WHY: VITE_ secret-prefix variant of the stripe key rule must still fire.
test("stripe-depth: new Stripe(VITE_STRIPE_*) is flagged", () => {
  const code = `const stripe = new Stripe(process.env.VITE_STRIPE_SECRET_KEY);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-in-public-env"));
});

// WHY: stripe finding severity propagates to the finding object, not just the
// rule definition. Verify they match end to end.
test("stripe-depth: finding.severity matches rule.severity for sk_live_ rule", () => {
  const code = `const k = "sk_live_AbCdEfGhIjKlMnOpQrSt1234";`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "stripe-secret-key-literal-live");
  const rule = ruleById("stripe-secret-key-literal-live");
  assert.ok(finding && rule);
  assert.equal(finding.severity, rule.severity);
});
