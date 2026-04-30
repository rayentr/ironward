import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const HEX_32 = "0123456789abcdef0123456789abcdef";
const HEX_40 = "0123456789abcdef0123456789abcdef01234567";
const ALNUM_40 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";

const DD_API = HEX_32;
const DD_APP = HEX_40;
const NR_LICENSE = ALNUM_40;
const NR_USER = "NRAK-ABCDEFGHIJKLMNOPQRSTUVW0123";  // NRAK- + 27 chars
const PD_TOKEN = "aBcDeFgHiJkLmNoPqRsT"; // 20 chars
const PD_INTEGRATION = HEX_32;
const SENTRY_AUTH = "sntrys_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmN12";  // sntrys_ + 88 chars
const ROLLBAR = HEX_32;
const HONEYCOMB = "hcaik_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuV";  // hcaik_ + 58 chars

// ============================================================
// datadog_api_key (32 hex, contextual)
// ============================================================

// WHY: contextual datadog_api_key = '...' shape.
test("datadog_api_key: basic detection", async () => {
  const f = await findFor(`datadog_api_key = '${DD_API}'`, "datadog_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("datadog_api_key: object property", async () => {
  const f = await findFor(`const cfg = { datadog_api_key: '${DD_API}' };`, "datadog_api_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("datadog_api_key: kebab-case", async () => {
  const f = await findFor(`datadog-api-key = '${DD_API}'`, "datadog_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("datadog_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DATADOG_API_KEY;`, "datadog_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("datadog_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`datadog_api_key = 'YOUR_DATADOG_API_KEY_PLACEHOLDR_X'`, "datadog_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// datadog_app_key (40 hex, contextual)
// ============================================================

// WHY: contextual datadog_app_key = '40-hex' shape.
test("datadog_app_key: basic detection", async () => {
  const f = await findFor(`datadog_app_key = '${DD_APP}'`, "datadog_app_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("datadog_app_key: object property", async () => {
  const f = await findFor(`const cfg = { datadog_app_key: '${DD_APP}' };`, "datadog_app_key");
  assert.ok(f);
});

// WHY: application alias variant.
test("datadog_app_key: application alias", async () => {
  const f = await findFor(`datadog_application_key = '${DD_APP}'`, "datadog_app_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("datadog_app_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DATADOG_APP_KEY;`, "datadog_app_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("datadog_app_key: placeholder NOT flagged", async () => {
  const f = await findFor(`datadog_app_key = 'YOUR_DATADOG_APP_KEY_PLACEHOLDER_X'`, "datadog_app_key");
  assert.equal(f, undefined);
});

// ============================================================
// newrelic_license (40 alnum, contextual)
// ============================================================

// WHY: contextual new_relic_license_key = '...' shape.
test("newrelic_license: basic detection", async () => {
  const f = await findFor(`new_relic_license_key = '${NR_LICENSE}'`, "newrelic_license");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: api_key variant of the same rule.
test("newrelic_license: api_key alias", async () => {
  const f = await findFor(`new_relic_api_key = '${NR_LICENSE}'`, "newrelic_license");
  assert.ok(f);
});

// WHY: object property variant.
test("newrelic_license: object property", async () => {
  const f = await findFor(`const cfg = { new_relic_license_key: '${NR_LICENSE}' };`, "newrelic_license");
  assert.ok(f);
});

// WHY: env reference safe.
test("newrelic_license: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.NEW_RELIC_LICENSE_KEY;`, "newrelic_license");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("newrelic_license: placeholder NOT flagged", async () => {
  const f = await findFor(`new_relic_license_key = 'YOUR_NEWRELIC_LICENSE_KEY_PLACE_X'`, "newrelic_license");
  assert.equal(f, undefined);
});

// ============================================================
// newrelic_user_api_key (NRAK-...)
// ============================================================

// WHY: NRAK- prefix is canonical NewRelic User API key.
test("newrelic_user_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${NR_USER}';`, "newrelic_user_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("newrelic_user_api_key: object property", async () => {
  const f = await findFor(`const cfg = { newrelic: { userApiKey: '${NR_USER}' } };`, "newrelic_user_api_key");
  assert.ok(f);
});

// WHY: token in template literal.
test("newrelic_user_api_key: template literal", async () => {
  const f = await findFor("const a = `Api-Key: " + NR_USER + "`;", "newrelic_user_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("newrelic_user_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.NEW_RELIC_USER_API_KEY;`, "newrelic_user_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("newrelic_user_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'NRAK-YOUR_NEWRELIC_USER_PLACEHOLDR';`, "newrelic_user_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// pagerduty_api_token (20 chars, contextual)
// ============================================================

// WHY: contextual pagerduty_api_token = '20-char' shape.
test("pagerduty_api_token: basic detection", async () => {
  const f = await findFor(`pagerduty_api_token = '${PD_TOKEN}'`, "pagerduty_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: pagerduty_token alias.
test("pagerduty_api_token: pagerduty_token alias", async () => {
  const f = await findFor(`pagerduty_token = '${PD_TOKEN}'`, "pagerduty_api_token");
  assert.ok(f);
});

// WHY: object property variant.
test("pagerduty_api_token: object property", async () => {
  const f = await findFor(`const cfg = { pagerduty_api_token: '${PD_TOKEN}' };`, "pagerduty_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("pagerduty_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.PAGERDUTY_API_TOKEN;`, "pagerduty_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("pagerduty_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`pagerduty_api_token = 'YOUR_PAGERDUTY_TKN'`, "pagerduty_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// pagerduty_integration_key (32 hex, contextual)
// ============================================================

// WHY: contextual pagerduty_integration_key = '32-hex' shape.
test("pagerduty_integration_key: basic detection", async () => {
  const f = await findFor(`pagerduty_integration_key = '${PD_INTEGRATION}'`, "pagerduty_integration_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("pagerduty_integration_key: object property", async () => {
  const f = await findFor(`const cfg = { pagerduty_integration_key: '${PD_INTEGRATION}' };`, "pagerduty_integration_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("pagerduty_integration_key: kebab-case", async () => {
  const f = await findFor(`pagerduty-integration-key = '${PD_INTEGRATION}'`, "pagerduty_integration_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("pagerduty_integration_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.PAGERDUTY_INTEGRATION_KEY;`, "pagerduty_integration_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("pagerduty_integration_key: placeholder NOT flagged", async () => {
  const f = await findFor(`pagerduty_integration_key = 'YOUR_PAGERDUTY_INTEGRATION_KEY_X'`, "pagerduty_integration_key");
  assert.equal(f, undefined);
});

// ============================================================
// sentry_auth_token (sntrys_ + 88 chars)
// ============================================================

// WHY: sntrys_ prefix is canonical Sentry auth token format.
test("sentry_auth_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SENTRY_AUTH}';`, "sentry_auth_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("sentry_auth_token: object property", async () => {
  const f = await findFor(`const cfg = { sentry: { authToken: '${SENTRY_AUTH}' } };`, "sentry_auth_token");
  assert.ok(f);
});

// WHY: token in template literal — Sentry CLI release upload pattern.
test("sentry_auth_token: template literal", async () => {
  const f = await findFor("const a = `Authorization: Bearer " + SENTRY_AUTH + "`;", "sentry_auth_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("sentry_auth_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SENTRY_AUTH_TOKEN;`, "sentry_auth_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("sentry_auth_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'sntrys_YOUR_SENTRY_AUTH_TOKEN_PLACEHOLDR_TEXT_VALUE_HERE_FILL_TO_88_CHARS_PLZ_X12';`, "sentry_auth_token");
  assert.equal(f, undefined);
});

// ============================================================
// rollbar_token (32 hex, contextual)
// ============================================================

// WHY: contextual rollbar_token = '32-hex' shape.
test("rollbar_token: basic detection", async () => {
  const f = await findFor(`rollbar_token = '${ROLLBAR}'`, "rollbar_token");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: rollbar_access_token alias.
test("rollbar_token: access_token alias", async () => {
  const f = await findFor(`rollbar_access_token = '${ROLLBAR}'`, "rollbar_token");
  assert.ok(f);
});

// WHY: object property variant.
test("rollbar_token: object property", async () => {
  const f = await findFor(`const cfg = { rollbar_token: '${ROLLBAR}' };`, "rollbar_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("rollbar_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ROLLBAR_TOKEN;`, "rollbar_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("rollbar_token: placeholder NOT flagged", async () => {
  const f = await findFor(`rollbar_token = 'YOUR_ROLLBAR_ACCESS_TOKEN_PLACEHOLDR_X'`, "rollbar_token");
  assert.equal(f, undefined);
});

// ============================================================
// honeycomb_key (hcaik_ + 58 chars)
// ============================================================

// WHY: hcaik_ prefix is canonical Honeycomb API key format.
test("honeycomb_key: basic detection", async () => {
  const f = await findFor(`const k = '${HONEYCOMB}';`, "honeycomb_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: key in object property.
test("honeycomb_key: object property", async () => {
  const f = await findFor(`const cfg = { honeycomb: { apiKey: '${HONEYCOMB}' } };`, "honeycomb_key");
  assert.ok(f);
});

// WHY: key in template literal.
test("honeycomb_key: template literal", async () => {
  const f = await findFor("const a = `X-Honeycomb-Team: " + HONEYCOMB + "`;", "honeycomb_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("honeycomb_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.HONEYCOMB_API_KEY;`, "honeycomb_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("honeycomb_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'hcaik_YOUR_HONEYCOMB_API_KEY_PLACEHOLDR_TEXT_X1234567';`, "honeycomb_key");
  assert.equal(f, undefined);
});
