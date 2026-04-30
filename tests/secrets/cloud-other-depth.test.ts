import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const VULTR = "ABCDEFGHIJKL0123456789MNOPQRSTUVWXYZ"; // 36 upper alnum
const HETZNER = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ012A"; // 64 alnum
const OVH = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"; // 32 alnum
const FLY_IO = "fo1_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // fo1_ + 40
const RENDER = "rnd_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // rnd_ + 40
const VERCEL_VRCL = "vrcl_aBcDeFgHiJkLmNoPqRsTuVwXyZ012"; // vrcl_ + 24+
const ALIBABA = "LTAI" + "aBcDeFgHiJkL0123"; // LTAI + 16
const HEROKU_OAUTH = "HRKU-01234567-89ab-cdef-0123-456789abcdef";
const NETLIFY_HOOK = "https://api.netlify.com/build_hooks/0123456789abcdef01234567";

// ============================================================
// vultr_api_key (36 upper alnum, contextual)
// ============================================================

// WHY: contextual vultr_api_key = '36-char' shape.
test("vultr_api_key: basic detection", async () => {
  const f = await findFor(`vultr_api_key = '${VULTR}'`, "vultr_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: object property variant.
test("vultr_api_key: object property", async () => {
  const f = await findFor(`const cfg = { vultr_api_key: '${VULTR}' };`, "vultr_api_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("vultr_api_key: kebab-case", async () => {
  const f = await findFor(`vultr-api-key = '${VULTR}'`, "vultr_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("vultr_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.VULTR_API_KEY;`, "vultr_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("vultr_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`vultr_api_key = 'YOUR_VULTR_API_KEY_PLACEHOLDR_X1234'`, "vultr_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// hetzner_api_token (64 alnum, contextual)
// ============================================================

// WHY: contextual hetzner_api_token = '64-char' shape.
test("hetzner_api_token: basic detection", async () => {
  const f = await findFor(`hetzner_api_token = '${HETZNER}'`, "hetzner_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: hetzner_cloud_api_token alias.
test("hetzner_api_token: cloud variant", async () => {
  const f = await findFor(`hetzner_cloud_api_token = '${HETZNER}'`, "hetzner_api_token");
  assert.ok(f);
});

// WHY: object property variant.
test("hetzner_api_token: object property", async () => {
  const f = await findFor(`const cfg = { hetzner_api_token: '${HETZNER}' };`, "hetzner_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("hetzner_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.HETZNER_TOKEN;`, "hetzner_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("hetzner_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`hetzner_api_token = 'YOUR_HETZNER_TOKEN_PLACEHOLDR_TEXT_VALUE_FILL_TO_64_CHARS_X1'`, "hetzner_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// ovh_application_secret (32 alnum, contextual)
// ============================================================

// WHY: contextual ovh_application_secret = '32-char' shape.
test("ovh_application_secret: basic detection", async () => {
  const f = await findFor(`ovh_application_secret = '${OVH}'`, "ovh_application_secret");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: ovh_app_secret alias.
test("ovh_application_secret: app alias", async () => {
  const f = await findFor(`ovh_app_secret = '${OVH}'`, "ovh_application_secret");
  assert.ok(f);
});

// WHY: object property variant.
test("ovh_application_secret: object property", async () => {
  const f = await findFor(`const cfg = { ovh_application_secret: '${OVH}' };`, "ovh_application_secret");
  assert.ok(f);
});

// WHY: env reference safe.
test("ovh_application_secret: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.OVH_APPLICATION_SECRET;`, "ovh_application_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("ovh_application_secret: placeholder NOT flagged", async () => {
  const f = await findFor(`ovh_application_secret = 'YOUR_OVH_APPLICATION_SECRET_PLAC'`, "ovh_application_secret");
  assert.equal(f, undefined);
});

// ============================================================
// fly_io_token (fo1_ + 40+)
// ============================================================

// WHY: fo1_ prefix is canonical Fly.io API token.
test("fly_io_token: basic detection", async () => {
  const f = await findFor(`const k = '${FLY_IO}';`, "fly_io_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("fly_io_token: object property", async () => {
  const f = await findFor(`const cfg = { fly: { token: '${FLY_IO}' } };`, "fly_io_token");
  assert.ok(f);
});

// WHY: in template literal.
test("fly_io_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + FLY_IO + "`;", "fly_io_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("fly_io_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.FLY_API_TOKEN;`, "fly_io_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("fly_io_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'fo1_YOUR_FLY_IO_API_TOKEN_PLACEHOLDR_TXT';`, "fly_io_token");
  assert.equal(f, undefined);
});

// ============================================================
// render_api_key (rnd_ + 40+)
// ============================================================

// WHY: rnd_ prefix is canonical Render API key.
test("render_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${RENDER}';`, "render_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("render_api_key: object property", async () => {
  const f = await findFor(`const cfg = { render: { apiKey: '${RENDER}' } };`, "render_api_key");
  assert.ok(f);
});

// WHY: in template literal.
test("render_api_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + RENDER + "`;", "render_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("render_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.RENDER_API_KEY;`, "render_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("render_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'rnd_YOUR_RENDER_API_KEY_PLACEHOLDR_TXT';`, "render_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// vercel_pat_prefixed (vrcl_/vercel_ + 24+)
// ============================================================

// WHY: vrcl_ prefix is the canonical Vercel PAT format.
test("vercel_pat_prefixed: basic detection", async () => {
  const f = await findFor(`const k = '${VERCEL_VRCL}';`, "vercel_pat_prefixed");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: vercel_ prefix variant.
test("vercel_pat_prefixed: vercel_ prefix", async () => {
  const v = "vercel_aBcDeFgHiJkLmNoPqRsTuVwXyZ012";
  const f = await findFor(`const k = '${v}';`, "vercel_pat_prefixed");
  assert.ok(f);
});

// WHY: in object property.
test("vercel_pat_prefixed: object property", async () => {
  const f = await findFor(`const cfg = { vercel: { token: '${VERCEL_VRCL}' } };`, "vercel_pat_prefixed");
  assert.ok(f);
});

// WHY: env reference safe.
test("vercel_pat_prefixed: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.VERCEL_TOKEN;`, "vercel_pat_prefixed");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("vercel_pat_prefixed: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'vrcl_YOUR_VERCEL_TOKEN_PLAC';`, "vercel_pat_prefixed");
  assert.equal(f, undefined);
});

// ============================================================
// alibaba_access_key (LTAI + 12-20)
// ============================================================

// WHY: LTAI prefix is canonical Alibaba access key.
test("alibaba_access_key: basic detection", async () => {
  const f = await findFor(`const k = '${ALIBABA}';`, "alibaba_access_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("alibaba_access_key: object property", async () => {
  const f = await findFor(`const cfg = { aliyun: { accessKeyId: '${ALIBABA}' } };`, "alibaba_access_key");
  assert.ok(f);
});

// WHY: in template literal.
test("alibaba_access_key: template literal", async () => {
  const f = await findFor("const a = `accessKey=" + ALIBABA + "`;", "alibaba_access_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("alibaba_access_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ALIBABA_ACCESS_KEY;`, "alibaba_access_key");
  assert.equal(f, undefined);
});

// WHY: env name aliyun (alibaba parent) NOT flagged.
test("alibaba_access_key: env name aliyun NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ALIYUN_ACCESS_KEY_ID;`, "alibaba_access_key");
  assert.equal(f, undefined);
});

// ============================================================
// heroku_oauth_access (HRKU-<uuid>)
// ============================================================

// WHY: HRKU- prefix is canonical Heroku OAuth access token.
test("heroku_oauth_access: basic detection", async () => {
  const f = await findFor(`const k = '${HEROKU_OAUTH}';`, "heroku_oauth_access");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("heroku_oauth_access: object property", async () => {
  const f = await findFor(`const cfg = { heroku: { oauthToken: '${HEROKU_OAUTH}' } };`, "heroku_oauth_access");
  assert.ok(f);
});

// WHY: in template literal.
test("heroku_oauth_access: template literal", async () => {
  const f = await findFor("const a = `Bearer " + HEROKU_OAUTH + "`;", "heroku_oauth_access");
  assert.ok(f);
});

// WHY: env reference safe.
test("heroku_oauth_access: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.HEROKU_OAUTH_TOKEN;`, "heroku_oauth_access");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("heroku_oauth_access: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'HRKU-YOURPLACE-AAAA-BBBB-CCCC-DDDDEEEEFFFF';`, "heroku_oauth_access");
  assert.equal(f, undefined);
});

// ============================================================
// netlify_build_hook (URL)
// ============================================================

// WHY: build_hook URL leaks deploy trigger to anyone with the URL.
test("netlify_build_hook: basic detection", async () => {
  const f = await findFor(`const url = '${NETLIFY_HOOK}';`, "netlify_build_hook");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("netlify_build_hook: object property", async () => {
  const f = await findFor(`const cfg = { netlify: { buildHook: '${NETLIFY_HOOK}' } };`, "netlify_build_hook");
  assert.ok(f);
});

// WHY: in template literal.
test("netlify_build_hook: template literal", async () => {
  const f = await findFor("const u = `" + NETLIFY_HOOK + "?branch=main`;", "netlify_build_hook");
  assert.ok(f);
});

// WHY: env reference safe.
test("netlify_build_hook: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.NETLIFY_BUILD_HOOK;`, "netlify_build_hook");
  assert.equal(f, undefined);
});

// WHY: placeholder URL must not fire.
test("netlify_build_hook: placeholder NOT flagged", async () => {
  const f = await findFor(`const u = 'https://api.netlify.com/build_hooks/YOUR_NETLIFY_HOOK_X1';`, "netlify_build_hook");
  assert.equal(f, undefined);
});
