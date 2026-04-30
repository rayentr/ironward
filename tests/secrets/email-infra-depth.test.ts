import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const HEX_32 = "0123456789abcdef0123456789abcdef";
const HEX_40 = "0123456789abcdef0123456789abcdef01234567";
const HEX_64 = HEX_32 + HEX_32;
const HEX_37 = "0123456789abcdef0123456789abcdef01234";  // 37 hex
const POSTMARK_UUID = "01234567-89ab-cdef-0123-456789abcdef";

const SENDGRID = "SG." + "aBcDeFgHiJkLmNoPqRsTuV" + "." + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg"; // SG.<22>.<43>
const MAILGUN = "key-" + HEX_32;
const MAILCHIMP = HEX_32 + "-us12";
const RESEND = "re_aBcDeFgHiJ_aBcDeFgHiJkLmNoPqRsTuVw";
const MAILERSEND = "mlsn." + HEX_64;
const BREVO = "xkeysib-" + HEX_64 + "-aBcDeFgHiJkLmNoP";  // xkeysib-<64hex>-<16alnum>
const DO_PAT = "dop_v1_" + HEX_64;
const DO_OAUTH = "doo_v1_" + HEX_64;

// ============================================================
// sendgrid_key (SG.<22>.<43>)
// ============================================================

// WHY: SG.-prefixed SendGrid API key.
test("sendgrid_key: basic detection", async () => {
  const f = await findFor(`const k = '${SENDGRID}';`, "sendgrid_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("sendgrid_key: object property", async () => {
  const f = await findFor(`const cfg = { sendgrid: { apiKey: '${SENDGRID}' } };`, "sendgrid_key");
  assert.ok(f);
});

// WHY: in template literal.
test("sendgrid_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + SENDGRID + "`;", "sendgrid_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("sendgrid_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SENDGRID_API_KEY;`, "sendgrid_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("sendgrid_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'SG.YOUR_SENDGRID_API.YOUR_SENDGRID_API_KEY_PLACEHOLDR_TXT_VAL';`, "sendgrid_key");
  assert.equal(f, undefined);
});

// ============================================================
// mailgun_key (key- + 32 hex)
// ============================================================

// WHY: key- prefix is canonical Mailgun API key.
test("mailgun_key: basic detection", async () => {
  const f = await findFor(`const k = '${MAILGUN}';`, "mailgun_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("mailgun_key: object property", async () => {
  const f = await findFor(`const cfg = { mailgun: { apiKey: '${MAILGUN}' } };`, "mailgun_key");
  assert.ok(f);
});

// WHY: in template literal.
test("mailgun_key: template literal", async () => {
  const f = await findFor("const a = `Authorization: api " + MAILGUN + "`;", "mailgun_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("mailgun_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAILGUN_API_KEY;`, "mailgun_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("mailgun_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'key-YOUR_MAILGUN_KEY_PLACEHOLDR_X1234';`, "mailgun_key");
  assert.equal(f, undefined);
});

// ============================================================
// mailchimp_key (32 hex + -usN)
// ============================================================

// WHY: hex-usN format is canonical Mailchimp API key.
test("mailchimp_key: basic detection", async () => {
  const f = await findFor(`const k = '${MAILCHIMP}';`, "mailchimp_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("mailchimp_key: object property", async () => {
  const f = await findFor(`const cfg = { mailchimp: { apiKey: '${MAILCHIMP}' } };`, "mailchimp_key");
  assert.ok(f);
});

// WHY: in template literal.
test("mailchimp_key: template literal", async () => {
  const f = await findFor("const a = `apikey:" + MAILCHIMP + "`;", "mailchimp_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("mailchimp_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAILCHIMP_API_KEY;`, "mailchimp_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("mailchimp_key: env-name reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAILCHIMP_KEY;`, "mailchimp_key");
  assert.equal(f, undefined);
});

// ============================================================
// resend_api_key (re_<10>_<20>)
// ============================================================

// WHY: re_<id>_<key> prefix is canonical Resend API key.
test("resend_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${RESEND}';`, "resend_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("resend_api_key: object property", async () => {
  const f = await findFor(`const cfg = { resend: { apiKey: '${RESEND}' } };`, "resend_api_key");
  assert.ok(f);
});

// WHY: in template literal.
test("resend_api_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + RESEND + "`;", "resend_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("resend_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.RESEND_API_KEY;`, "resend_api_key");
  assert.equal(f, undefined);
});

// WHY: env name with re_ prefix in string must not fire.
test("resend_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 're_YOUR_PLACE_YOUR_RESEND_KEY_PLAC';`, "resend_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// mailersend_api_key (mlsn. + 64 hex)
// ============================================================

// WHY: mlsn. prefix is canonical MailerSend API token.
test("mailersend_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${MAILERSEND}';`, "mailersend_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("mailersend_api_key: object property", async () => {
  const f = await findFor(`const cfg = { mailersend: { apiKey: '${MAILERSEND}' } };`, "mailersend_api_key");
  assert.ok(f);
});

// WHY: in template literal.
test("mailersend_api_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + MAILERSEND + "`;", "mailersend_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("mailersend_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAILERSEND_API_KEY;`, "mailersend_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("mailersend_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'mlsn.YOUR_MAILERSEND_API_KEY_PLACEHOLDR_TEXT_VAL_FILL_TO_64_HEX_X1';`, "mailersend_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// brevo_api_key (xkeysib-<64hex>-<16alnum>)
// ============================================================

// WHY: xkeysib- prefix is canonical Brevo (formerly Sendinblue) API key.
test("brevo_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${BREVO}';`, "brevo_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: in object property.
test("brevo_api_key: object property", async () => {
  const f = await findFor(`const cfg = { brevo: { apiKey: '${BREVO}' } };`, "brevo_api_key");
  assert.ok(f);
});

// WHY: in template literal.
test("brevo_api_key: template literal", async () => {
  const f = await findFor("const a = `api-key=" + BREVO + "`;", "brevo_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("brevo_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.BREVO_API_KEY;`, "brevo_api_key");
  assert.equal(f, undefined);
});

// WHY: legacy SENDINBLUE_API_KEY env name still safe.
test("brevo_api_key: legacy env name NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SENDINBLUE_API_KEY;`, "brevo_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// cloudflare_api_token (40 chars, contextual)
// ============================================================

const CF_TOKEN = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // 40

// WHY: contextual cloudflare_api_token = '40-char' shape.
test("cloudflare_api_token: basic detection", async () => {
  const f = await findFor(`cloudflare_api_token = '${CF_TOKEN}'`, "cloudflare_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: kebab-case variant.
test("cloudflare_api_token: kebab-case", async () => {
  const f = await findFor(`cloudflare-api-token = '${CF_TOKEN}'`, "cloudflare_api_token");
  assert.ok(f);
});

// WHY: object property variant.
test("cloudflare_api_token: object property", async () => {
  const f = await findFor(`const cfg = { cloudflare_api_token: '${CF_TOKEN}' };`, "cloudflare_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("cloudflare_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.CLOUDFLARE_API_TOKEN;`, "cloudflare_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("cloudflare_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`cloudflare_api_token = 'YOUR_CLOUDFLARE_API_TOKEN_PLACE_X12'`, "cloudflare_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// cloudflare_global_key (37 hex, contextual)
// ============================================================

// WHY: contextual cloudflare_global_api_key = '37-hex' shape (legacy global).
test("cloudflare_global_key: basic detection", async () => {
  const f = await findFor(`cloudflare_global_api_key = '${HEX_37}'`, "cloudflare_global_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: cloudflare_key alias variant.
test("cloudflare_global_key: cloudflare_key alias", async () => {
  const f = await findFor(`cloudflare_key = '${HEX_37}'`, "cloudflare_global_key");
  assert.ok(f);
});

// WHY: object property variant.
test("cloudflare_global_key: object property", async () => {
  const f = await findFor(`const cfg = { cloudflare_key: '${HEX_37}' };`, "cloudflare_global_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("cloudflare_global_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.CLOUDFLARE_GLOBAL_API_KEY;`, "cloudflare_global_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("cloudflare_global_key: placeholder NOT flagged", async () => {
  const f = await findFor(`cloudflare_global_api_key = 'YOUR_CLOUDFLARE_GLOBAL_API_KEY_X1234567'`, "cloudflare_global_key");
  assert.equal(f, undefined);
});

// ============================================================
// digitalocean_pat (dop_v1_ + 64 hex)
// ============================================================

// WHY: dop_v1_ prefix is canonical DigitalOcean PAT.
test("digitalocean_pat: basic detection", async () => {
  const f = await findFor(`const k = '${DO_PAT}';`, "digitalocean_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("digitalocean_pat: object property", async () => {
  const f = await findFor(`const cfg = { digitalocean: { token: '${DO_PAT}' } };`, "digitalocean_pat");
  assert.ok(f);
});

// WHY: in template literal.
test("digitalocean_pat: template literal", async () => {
  const f = await findFor("const a = `Bearer " + DO_PAT + "`;", "digitalocean_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("digitalocean_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DIGITALOCEAN_PAT;`, "digitalocean_pat");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("digitalocean_pat: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'dop_v1_YOUR_DIGITALOCEAN_PAT_PLACEHOLDR_TEXT_VALUE_FILL_TO_64_HEX_X12';`, "digitalocean_pat");
  assert.equal(f, undefined);
});

// ============================================================
// digitalocean_oauth (doo_v1_ + 64 hex)
// ============================================================

// WHY: doo_v1_ prefix is canonical DigitalOcean OAuth token.
test("digitalocean_oauth: basic detection", async () => {
  const f = await findFor(`const k = '${DO_OAUTH}';`, "digitalocean_oauth");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("digitalocean_oauth: object property", async () => {
  const f = await findFor(`const cfg = { do: { oauthToken: '${DO_OAUTH}' } };`, "digitalocean_oauth");
  assert.ok(f);
});

// WHY: in template literal.
test("digitalocean_oauth: template literal", async () => {
  const f = await findFor("const a = `Bearer " + DO_OAUTH + "`;", "digitalocean_oauth");
  assert.ok(f);
});

// WHY: env reference safe.
test("digitalocean_oauth: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DO_OAUTH_TOKEN;`, "digitalocean_oauth");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("digitalocean_oauth: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'doo_v1_YOUR_DO_OAUTH_PLACEHOLDR_TEXT_VALUE_FILL_TO_64_HEX_CHARS_X1';`, "digitalocean_oauth");
  assert.equal(f, undefined);
});

// ============================================================
// linode_pat (linode + 64 hex contextual)
// ============================================================

// WHY: contextual linode = '64-hex' shape.
test("linode_pat: basic detection", async () => {
  const f = await findFor(`linode_token = '${HEX_64}'`, "linode_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: linode_pat alias variant.
test("linode_pat: linode_pat alias", async () => {
  const f = await findFor(`linode_pat = '${HEX_64}'`, "linode_pat");
  assert.ok(f);
});

// WHY: linode_api_token alias.
test("linode_pat: linode_api_token alias", async () => {
  const f = await findFor(`linode_api_token = '${HEX_64}'`, "linode_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("linode_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.LINODE_TOKEN;`, "linode_pat");
  assert.equal(f, undefined);
});

// WHY: env name akamai (linode parent) NOT flagged.
test("linode_pat: env name akamai NOT flagged", async () => {
  const f = await findFor(`const k = process.env.AKAMAI_API_TOKEN;`, "linode_pat");
  assert.equal(f, undefined);
});
