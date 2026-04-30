import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("stripe: flags sk_live_ literal in source", () => {
  const code = `const s = "sk_live_AbCdEfGhIjKlMnOpQrSt1234";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-key-literal-live"));
});

test("stripe: flags sk_test_ literal in source", () => {
  const code = `const s = "sk_test_AbCdEfGhIjKlMnOpQrSt1234";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-key-literal-test"));
});

test("stripe: flags new Stripe(NEXT_PUBLIC_STRIPE_*)", () => {
  const code = `const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-secret-in-public-env"));
});

test("stripe: flags paymentIntents.create with amount from req.body", () => {
  const code = `await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'usd' });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-payment-intent-amount-from-body"));
});

test("stripe: flags unit_amount taken from req.body", () => {
  const code = `const session = await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: req.body.price, currency: 'usd' } }] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-checkout-amount-from-body"));
});

test("stripe: flags webhook secret defaulted to empty string", () => {
  const code = `const secret = process.env.STRIPE_WEBHOOK_SECRET || "";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-webhook-secret-default"));
});

test("stripe: flags new Stripe(...) with pk_ publishable key", () => {
  const code = `const s = new Stripe("pk_live_abc123");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-publishable-key-in-server"));
});

test("stripe: flags rk_live_ restricted key literal", () => {
  const code = `const k = "rk_live_AbCdEfGhIjKlMnOp1234";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "stripe-restricted-key-literal"));
});

test("stripe: does NOT flag STRIPE_SECRET_KEY env reference (server-only var)", () => {
  const code = `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-secret-in-public-env"));
});

test("stripe: does NOT flag amount derived from server-side product lookup", () => {
  const code = `const product = await db.products.find(productId);
await stripe.paymentIntents.create({ amount: product.price, currency: 'usd' });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "stripe-payment-intent-amount-from-body"));
});
