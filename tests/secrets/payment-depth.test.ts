import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic payment provider tokens. Length matches each pattern's regex requirement.
const STRIPE_LIVE   = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";       // sk_live_ + 24
const STRIPE_TEST   = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";       // sk_test_ + 24
const STRIPE_RK_L   = "rk_live_5fE89jrLykWErzkuU2aeq8ed";       // rk_live_ + 24
const STRIPE_RK_T   = "rk_test_5fE89jrLykWErzkuU2aeq8ed";       // rk_test_ + 24
const STRIPE_PUB    = "pk_live_6gF12ksMzlXFsalvV3bfr9fe";       // pk_live_ + 24
const STRIPE_WEBHOOK = "whsec_AbCdEfGhIjKlMnOpQrStUvWxYz012345"; // whsec_ + 32
const SQUARE_TOKEN   = "EAAA0123456789abcdefghijklmnopqrstuv";   // EAAA + 30+
const SHOPIFY_TOKEN  = "shpat_0123456789abcdef0123456789abcdef"; // shpat_ + 32 hex

// ============================================================
// stripe_live_secret
// ============================================================

// WHY: basic — sk_live_ key in a const fires critical.
test("stripe_live_secret: basic detection", async () => {
  const code = `const key = '${STRIPE_LIVE}';`;
  const f = await findFor(code, "stripe_live_secret");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — key inside config object still fires.
test("stripe_live_secret: object property", async () => {
  const code = `const cfg = { stripe: { secretKey: '${STRIPE_LIVE}' } };`;
  const f = await findFor(code, "stripe_live_secret");
  assert.ok(f);
});

// WHY: template literal — Authorization template with the key fires.
test("stripe_live_secret: template literal", async () => {
  const code = "const auth = `Bearer " + STRIPE_LIVE + "`;";
  const f = await findFor(code, "stripe_live_secret");
  assert.ok(f);
});

// WHY: placeholder — sk_live_XXXX style placeholder must not fire.
test("stripe_live_secret: placeholder NOT flagged", async () => {
  const code = `const key = 'sk_live_XXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_live_secret");
  assert.equal(f, undefined);
});

// WHY: env reference — process.env.STRIPE_SECRET_KEY (no inline value) must not fire.
test("stripe_live_secret: env reference NOT flagged", async () => {
  const code = `const key = process.env.STRIPE_SECRET_KEY;`;
  const f = await findFor(code, "stripe_live_secret");
  assert.equal(f, undefined);
});

// ============================================================
// stripe_test_secret
// ============================================================

// WHY: basic — sk_test_ key fires high severity.
test("stripe_test_secret: basic detection", async () => {
  const code = `const key = '${STRIPE_TEST}';`;
  const f = await findFor(code, "stripe_test_secret");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — sk_test in nested config still fires.
test("stripe_test_secret: object property", async () => {
  const code = `const cfg = { stripe: { test: { key: '${STRIPE_TEST}' } } };`;
  const f = await findFor(code, "stripe_test_secret");
  assert.ok(f);
});

// WHY: template literal — sk_test_ in template fires.
test("stripe_test_secret: template literal", async () => {
  const code = "const h = `Bearer " + STRIPE_TEST + "`;";
  const f = await findFor(code, "stripe_test_secret");
  assert.ok(f);
});

// WHY: placeholder — XXXX-padded test key not flagged.
test("stripe_test_secret: placeholder NOT flagged", async () => {
  const code = `const key = 'sk_test_XXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_test_secret");
  assert.equal(f, undefined);
});

// WHY: env reference — env-var reference must not fire.
test("stripe_test_secret: env reference NOT flagged", async () => {
  const code = `const key = process.env.STRIPE_TEST_KEY;`;
  const f = await findFor(code, "stripe_test_secret");
  assert.equal(f, undefined);
});

// ============================================================
// stripe_restricted_live (rk_live_)
// ============================================================

// WHY: basic — rk_live_ restricted key fires critical.
test("stripe_restricted_live: basic detection", async () => {
  const code = `const k = '${STRIPE_RK_L}';`;
  const f = await findFor(code, "stripe_restricted_live");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — restricted key in object still fires.
test("stripe_restricted_live: object property", async () => {
  const code = `const cfg = { restricted: { live: '${STRIPE_RK_L}' } };`;
  const f = await findFor(code, "stripe_restricted_live");
  assert.ok(f);
});

// WHY: template literal — restricted live in template fires.
test("stripe_restricted_live: template literal", async () => {
  const code = "const a = `Bearer " + STRIPE_RK_L + "`;";
  const f = await findFor(code, "stripe_restricted_live");
  assert.ok(f);
});

// WHY: placeholder — XXXX-padded restricted live not flagged.
test("stripe_restricted_live: placeholder NOT flagged", async () => {
  const code = `const k = 'rk_live_XXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_restricted_live");
  assert.equal(f, undefined);
});

// WHY: env reference — env-var reference is safe and must not fire.
test("stripe_restricted_live: env reference NOT flagged", async () => {
  const code = `const k = process.env.STRIPE_RESTRICTED_KEY;`;
  const f = await findFor(code, "stripe_restricted_live");
  assert.equal(f, undefined);
});

// ============================================================
// stripe_restricted_test (rk_test_)
// ============================================================

// WHY: basic — rk_test_ in const fires (medium severity per pattern).
test("stripe_restricted_test: basic detection", async () => {
  const code = `const k = '${STRIPE_RK_T}';`;
  const f = await findFor(code, "stripe_restricted_test");
  assert.ok(f);
  // Pattern is medium severity in secrets.json; allow medium too.
  assert.ok(["critical", "high", "medium"].includes(f.severity));
});

// WHY: nested object.
test("stripe_restricted_test: object property", async () => {
  const code = `const cfg = { stripe: { rkTest: '${STRIPE_RK_T}' } };`;
  const f = await findFor(code, "stripe_restricted_test");
  assert.ok(f);
});

// WHY: template literal.
test("stripe_restricted_test: template literal", async () => {
  const code = "const a = `Bearer " + STRIPE_RK_T + "`;";
  const f = await findFor(code, "stripe_restricted_test");
  assert.ok(f);
});

// WHY: placeholder.
test("stripe_restricted_test: placeholder NOT flagged", async () => {
  const code = `const k = 'rk_test_XXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_restricted_test");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("stripe_restricted_test: env reference NOT flagged", async () => {
  const code = `const k = process.env.STRIPE_RESTRICTED_TEST;`;
  const f = await findFor(code, "stripe_restricted_test");
  assert.equal(f, undefined);
});

// ============================================================
// stripe_publishable_live (pk_live_) — low severity (public-ish but flagged)
// ============================================================

// WHY: basic — pk_live_ fires (low severity is acceptable).
test("stripe_publishable_live: basic detection", async () => {
  const code = `const pub = '${STRIPE_PUB}';`;
  const f = await findFor(code, "stripe_publishable_live");
  assert.ok(f);
  assert.ok(["critical", "high", "medium", "low"].includes(f.severity));
});

// WHY: nested object.
test("stripe_publishable_live: object property", async () => {
  const code = `const cfg = { stripe: { pub: '${STRIPE_PUB}' } };`;
  const f = await findFor(code, "stripe_publishable_live");
  assert.ok(f);
});

// WHY: template literal.
test("stripe_publishable_live: template literal", async () => {
  const code = "const inline = `key=" + STRIPE_PUB + "`;";
  const f = await findFor(code, "stripe_publishable_live");
  assert.ok(f);
});

// WHY: placeholder.
test("stripe_publishable_live: placeholder NOT flagged", async () => {
  const code = `const pub = 'pk_live_XXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_publishable_live");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("stripe_publishable_live: env reference NOT flagged", async () => {
  const code = `const pub = process.env.STRIPE_PUBLISHABLE_KEY;`;
  const f = await findFor(code, "stripe_publishable_live");
  assert.equal(f, undefined);
});

// ============================================================
// stripe_webhook_secret (whsec_)
// ============================================================

// WHY: basic — whsec_ secret fires.
test("stripe_webhook_secret: basic detection", async () => {
  const code = `const wh = '${STRIPE_WEBHOOK}';`;
  const f = await findFor(code, "stripe_webhook_secret");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("stripe_webhook_secret: object property", async () => {
  const code = `const cfg = { stripe: { webhookSecret: '${STRIPE_WEBHOOK}' } };`;
  const f = await findFor(code, "stripe_webhook_secret");
  assert.ok(f);
});

// WHY: template literal.
test("stripe_webhook_secret: template literal", async () => {
  const code = "const h = `Bearer " + STRIPE_WEBHOOK + "`;";
  const f = await findFor(code, "stripe_webhook_secret");
  assert.ok(f);
});

// WHY: placeholder.
test("stripe_webhook_secret: placeholder NOT flagged", async () => {
  const code = `const wh = 'whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "stripe_webhook_secret");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("stripe_webhook_secret: env reference NOT flagged", async () => {
  const code = `const wh = process.env.STRIPE_WEBHOOK_SECRET;`;
  const f = await findFor(code, "stripe_webhook_secret");
  assert.equal(f, undefined);
});

// ============================================================
// square_access_token
// ============================================================

// WHY: basic — Square EAAA-prefixed access token fires.
test("square_access_token: basic detection", async () => {
  const code = `const t = '${SQUARE_TOKEN}';`;
  const f = await findFor(code, "square_access_token");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("square_access_token: object property", async () => {
  const code = `const cfg = { square: { accessToken: '${SQUARE_TOKEN}' } };`;
  const f = await findFor(code, "square_access_token");
  assert.ok(f);
});

// WHY: template literal.
test("square_access_token: template literal", async () => {
  const code = "const a = `Bearer " + SQUARE_TOKEN + "`;";
  const f = await findFor(code, "square_access_token");
  assert.ok(f);
});

// WHY: placeholder.
test("square_access_token: placeholder NOT flagged", async () => {
  const code = `const t = 'EAAAYOUR_SQUARE_ACCESS_TOKEN_HERE_PLACEHOLDER';`;
  const f = await findFor(code, "square_access_token");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("square_access_token: env reference NOT flagged", async () => {
  const code = `const t = process.env.SQUARE_ACCESS_TOKEN;`;
  const f = await findFor(code, "square_access_token");
  assert.equal(f, undefined);
});

// ============================================================
// shopify_access_token (shpat_)
// ============================================================

// WHY: basic — shpat_ token fires.
test("shopify_access_token: basic detection", async () => {
  const code = `const t = '${SHOPIFY_TOKEN}';`;
  const f = await findFor(code, "shopify_access_token");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("shopify_access_token: object property", async () => {
  const code = `const cfg = { shopify: { accessToken: '${SHOPIFY_TOKEN}' } };`;
  const f = await findFor(code, "shopify_access_token");
  assert.ok(f);
});

// WHY: template literal.
test("shopify_access_token: template literal", async () => {
  const code = "const a = `Bearer " + SHOPIFY_TOKEN + "`;";
  const f = await findFor(code, "shopify_access_token");
  assert.ok(f);
});

// WHY: placeholder.
test("shopify_access_token: placeholder NOT flagged", async () => {
  const code = `const t = 'shpat_YOUR_SHOPIFY_ACCESS_TOKEN_PLACEHOLDER';`;
  const f = await findFor(code, "shopify_access_token");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("shopify_access_token: env reference NOT flagged", async () => {
  const code = `const t = process.env.SHOPIFY_ACCESS_TOKEN;`;
  const f = await findFor(code, "shopify_access_token");
  assert.equal(f, undefined);
});
