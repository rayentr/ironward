import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const A0_SECRET = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ12";  // 64
const A0_MGMT_JWT = "eyJaBcDeFgHiJkLmNoPqRsT.eyJaBcDeFgHiJkLmNoPqRsTuVwXyZ.aBcDeFgHiJkLmNoPqRsTu";
const OKTA_TOKEN = "00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";  // 00 + 40
// Clerk allowlist excludes 50-100 char range (the canonical shape) — rule
// fires only on 101+ alnum tokens. Use 110-char synthetic.
const CLERK_LIVE = "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ123A";
const CLERK_TEST = "sk_test_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ123A";
const KINDE_VAL = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // 40
const WORKOS = "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJk1A2";  // sk_live_ + exactly 50
const STYTCH = "secret-test-01234567-89ab-cdef-0123-456789abcdef";
const NEXTAUTH = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJ"; // 45 chars
const ZOOM_JWT = "eyJaBcDeFgHiJkLmNoPqRsT.eyJaBcDeFgHiJkLmNoPqRsTuVwXyZ.aBcDeFgHiJkLmNoPqRsTu";

// ============================================================
// auth0_client_secret
// ============================================================

// WHY: contextual auth0_client_secret = '64+ char' shape is canonical.
test("auth0_client_secret: basic detection", async () => {
  const f = await findFor(`auth0_client_secret = '${A0_SECRET}'`, "auth0_client_secret");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: kebab-case variant.
test("auth0_client_secret: kebab-case", async () => {
  const f = await findFor(`auth0-client-secret = '${A0_SECRET}'`, "auth0_client_secret");
  assert.ok(f);
});

// WHY: object property variant.
test("auth0_client_secret: object property", async () => {
  const f = await findFor(`const cfg = { auth0_client_secret: '${A0_SECRET}' };`, "auth0_client_secret");
  assert.ok(f);
});

// WHY: env reference safe.
test("auth0_client_secret: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.AUTH0_CLIENT_SECRET;`, "auth0_client_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("auth0_client_secret: placeholder NOT flagged", async () => {
  const f = await findFor(`auth0_client_secret = 'YOUR_AUTH0_CLIENT_SECRET_PLACEHOLDER_TEXT_VAL_FILL_TO_64_CHARS_X1'`, "auth0_client_secret");
  assert.equal(f, undefined);
});

// ============================================================
// auth0_mgmt_token (JWT, contextual)
// ============================================================

// WHY: contextual auth0_mgmt_api_token = 'JWT' shape.
test("auth0_mgmt_token: basic detection", async () => {
  const f = await findFor(`auth0_mgmt_api_token = '${A0_MGMT_JWT}'`, "auth0_mgmt_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: object property variant.
test("auth0_mgmt_token: object property", async () => {
  const f = await findFor(`const cfg = { auth0_mgmt_api_token: '${A0_MGMT_JWT}' };`, "auth0_mgmt_token");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("auth0_mgmt_token: kebab-case", async () => {
  const f = await findFor(`auth0-mgmt-api-token = '${A0_MGMT_JWT}'`, "auth0_mgmt_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("auth0_mgmt_token: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.AUTH0_MGMT_TOKEN;`, "auth0_mgmt_token");
  assert.equal(f, undefined);
});

// WHY: placeholder JWT must not fire (no real token chars).
test("auth0_mgmt_token: env reference with token name NOT flagged", async () => {
  const f = await findFor(`const s = process.env.AUTH0_MANAGEMENT_API_TOKEN;`, "auth0_mgmt_token");
  assert.equal(f, undefined);
});

// ============================================================
// okta_api_token (00 + 40)
// ============================================================

// WHY: 00-prefixed Okta API token format.
test("okta_api_token: basic detection", async () => {
  const f = await findFor(`const k = '${OKTA_TOKEN}';`, "okta_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("okta_api_token: object property", async () => {
  const f = await findFor(`const cfg = { okta: { token: '${OKTA_TOKEN}' } };`, "okta_api_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("okta_api_token: template literal", async () => {
  const f = await findFor("const a = `SSWS " + OKTA_TOKEN + "`;", "okta_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("okta_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.OKTA_API_TOKEN;`, "okta_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("okta_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = '00YOUR_OKTA_API_TOKEN_PLACEHOLDR_VALUE_X12';`, "okta_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// clerk_secret_key (sk_live_/sk_test_ + 50)
// ============================================================

// WHY: sk_live_ Clerk production secret.
test("clerk_secret_key: live basic detection", async () => {
  const f = await findFor(`const k = '${CLERK_LIVE}';`, "clerk_secret_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: sk_test_ test mode secret still leaks dev environment.
test("clerk_secret_key: test mode", async () => {
  const f = await findFor(`const k = '${CLERK_TEST}';`, "clerk_secret_key");
  assert.ok(f);
});

// WHY: secret in object property.
test("clerk_secret_key: object property", async () => {
  const f = await findFor(`const cfg = { clerk: { secretKey: '${CLERK_LIVE}' } };`, "clerk_secret_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("clerk_secret_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.CLERK_SECRET_KEY;`, "clerk_secret_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("clerk_secret_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'sk_live_YOUR_CLERK_SECRET_KEY_PLACEHOLDR_TEXT_VALUE_FILL';`, "clerk_secret_key");
  assert.equal(f, undefined);
});

// ============================================================
// kinde_client_secret (40+ alnum, contextual)
// ============================================================

// WHY: contextual kinde_client_secret = 'value' shape.
test("kinde_client_secret: basic detection", async () => {
  const f = await findFor(`kinde_client_secret = '${KINDE_VAL}'`, "kinde_client_secret");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: kebab-case variant.
test("kinde_client_secret: kebab-case", async () => {
  const f = await findFor(`kinde-client-secret = '${KINDE_VAL}'`, "kinde_client_secret");
  assert.ok(f);
});

// WHY: object property variant.
test("kinde_client_secret: object property", async () => {
  const f = await findFor(`const cfg = { kinde_client_secret: '${KINDE_VAL}' };`, "kinde_client_secret");
  assert.ok(f);
});

// WHY: env reference safe.
test("kinde_client_secret: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.KINDE_CLIENT_SECRET;`, "kinde_client_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("kinde_client_secret: placeholder NOT flagged", async () => {
  const f = await findFor(`kinde_client_secret = 'YOUR_KINDE_CLIENT_SECRET_PLACEHOLDR_X'`, "kinde_client_secret");
  assert.equal(f, undefined);
});

// ============================================================
// workos_api_key (sk_live_/sk_test_/sk_dev_ + 50)
// ============================================================

// WHY: WorkOS sk_live_ key follows similar shape to Clerk.
test("workos_api_key: live basic detection", async () => {
  const f = await findFor(`const k = '${WORKOS}';`, "workos_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: dev environment secret.
test("workos_api_key: dev environment", async () => {
  const dev = "sk_dev_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJk1A2";  // sk_dev_ + 50
  const f = await findFor(`const k = '${dev}';`, "workos_api_key");
  assert.ok(f);
});

// WHY: token in object property.
test("workos_api_key: object property", async () => {
  const f = await findFor(`const cfg = { workos: { apiKey: '${WORKOS}' } };`, "workos_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("workos_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.WORKOS_API_KEY;`, "workos_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("workos_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'sk_live_YOUR_WORKOS_API_KEY_PLACEHOLDR_TEXT_VALUE_FILL_X12';`, "workos_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// stytch_api_token (secret-test/live-<uuid>)
// ============================================================

// WHY: secret-test- prefix is canonical Stytch test token.
test("stytch_api_token: test basic detection", async () => {
  const f = await findFor(`const k = '${STYTCH}';`, "stytch_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: secret-live- production variant.
test("stytch_api_token: live variant", async () => {
  const live = "secret-live-01234567-89ab-cdef-0123-456789abcdef";
  const f = await findFor(`const k = '${live}';`, "stytch_api_token");
  assert.ok(f);
});

// WHY: token in object property.
test("stytch_api_token: object property", async () => {
  const f = await findFor(`const cfg = { stytch: { secret: '${STYTCH}' } };`, "stytch_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("stytch_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.STYTCH_SECRET;`, "stytch_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("stytch_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'secret-test-YOURPLACE-AAAA-BBBB-CCCC-DDDDEEEEFFFF';`, "stytch_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// nextauth_secret_contextual
// ============================================================

// WHY: contextual nextauth_secret = '32+ char' shape.
test("nextauth_secret_contextual: basic detection", async () => {
  const f = await findFor(`nextauth_secret = '${NEXTAUTH}'`, "nextauth_secret_contextual");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: kebab-case variant.
test("nextauth_secret_contextual: kebab-case", async () => {
  const f = await findFor(`nextauth-secret = '${NEXTAUTH}'`, "nextauth_secret_contextual");
  assert.ok(f);
});

// WHY: object property variant.
test("nextauth_secret_contextual: object property", async () => {
  const f = await findFor(`const cfg = { nextauth_secret: '${NEXTAUTH}' };`, "nextauth_secret_contextual");
  assert.ok(f);
});

// WHY: env reference safe.
test("nextauth_secret_contextual: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.NEXTAUTH_SECRET;`, "nextauth_secret_contextual");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("nextauth_secret_contextual: placeholder NOT flagged", async () => {
  const f = await findFor(`nextauth_secret = 'YOUR_NEXTAUTH_SECRET_PLACEHOLDR_X'`, "nextauth_secret_contextual");
  assert.equal(f, undefined);
});

// ============================================================
// zoom_jwt (Zoom JWT, contextual)
// ============================================================

// WHY: contextual zoom_jwt = 'JWT' shape.
test("zoom_jwt: basic detection", async () => {
  const f = await findFor(`zoom_jwt = '${ZOOM_JWT}'`, "zoom_jwt");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: zoom_token alias.
test("zoom_jwt: zoom_token alias", async () => {
  const f = await findFor(`zoom_token = '${ZOOM_JWT}'`, "zoom_jwt");
  assert.ok(f);
});

// WHY: object property variant.
test("zoom_jwt: object property", async () => {
  const f = await findFor(`const cfg = { zoom_jwt: '${ZOOM_JWT}' };`, "zoom_jwt");
  assert.ok(f);
});

// WHY: env reference safe.
test("zoom_jwt: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ZOOM_JWT;`, "zoom_jwt");
  assert.equal(f, undefined);
});

// WHY: env reference with token name NOT flagged.
test("zoom_jwt: zoom_token env NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ZOOM_TOKEN;`, "zoom_jwt");
  assert.equal(f, undefined);
});
