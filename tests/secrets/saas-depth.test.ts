import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic SaaS API tokens. All values use varied alphabets so the
// placeholder filter (6+ identical chars) doesn't trip.
const LINEAR = "lin_api_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // lin_api_ + 40
const NOTION = "secret_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg"; // secret_ + 43
const AIRTABLE_PAT = "patAbCdEfGhIjKlMn.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // pat<14>.<64hex>
const SHOPIFY_AT = "shpat_0123456789abcdef0123456789abcdef"; // shpat_ + 32 hex
const SHOPIFY_CUSTOM = "shpca_0123456789abcdef0123456789abcdef";
const SHOPIFY_PRIVATE = "shppa_0123456789abcdef0123456789abcdef";
const ZENDESK_VAL = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // 40 alnum
const INTERCOM_PAT = "dG9rOiaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH"; // dG9rOi + 44+
const HUBSPOT_PAT = "pat-na1-01234567-89ab-cdef-0123-456789abcdef";
const SALESFORCE_AT = "00D0123456789AB!aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aB.._-Cd";
const ALGOLIA_HEX = "0123456789abcdef0123456789abcdef"; // 32 hex
const MAPBOX_SECRET = "sk.eyJaBcDeFgHiJkLmNoPqRsTu.aBcDeFgHiJkLmNoPqRsTu";
const TWILIO_SID = "AC0123456789abcdef0123456789abcdef";
const POSTHOG_PERSONAL = "phx_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // phx_ + 40
const PLANETSCALE = "pscale_tkn_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // pscale_tkn_ + 40
const XATA = "xau_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"; // xau_ + 40

// ============================================================
// linear_api_key (lin_api_ + 40)
// ============================================================

// WHY: lin_api_ prefix is canonical Linear API key.
test("linear_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${LINEAR}';`, "linear_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token nested in Linear SDK config.
test("linear_api_key: object property", async () => {
  const f = await findFor(`const cfg = { linear: { apiKey: '${LINEAR}' } };`, "linear_api_key");
  assert.ok(f);
});

// WHY: token in Authorization header template literal.
test("linear_api_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + LINEAR + "`;", "linear_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("linear_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.LINEAR_API_KEY;`, "linear_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("linear_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'lin_api_YOUR_LINEAR_API_KEY_PLACEHOLDR_X';`, "linear_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// notion_integration_token (secret_/ntn_ + 43)
// ============================================================

// WHY: secret_ prefixed Notion integration token.
test("notion_integration_token: basic detection", async () => {
  const f = await findFor(`const k = '${NOTION}';`, "notion_integration_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: ntn_ prefix is the newer Notion format.
test("notion_integration_token: ntn_ prefix", async () => {
  const NTN = "ntn_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg";
  const f = await findFor(`const k = '${NTN}';`, "notion_integration_token");
  assert.ok(f);
});

// WHY: token in object property.
test("notion_integration_token: object property", async () => {
  const f = await findFor(`const cfg = { notion: { auth: '${NOTION}' } };`, "notion_integration_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("notion_integration_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.NOTION_TOKEN;`, "notion_integration_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("notion_integration_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'secret_YOUR_NOTION_INTEGRATION_TOKEN_PLACE_X';`, "notion_integration_token");
  assert.equal(f, undefined);
});

// ============================================================
// airtable_pat (pat<14>.<64hex>)
// ============================================================

// WHY: Airtable PAT format is canonical.
test("airtable_pat: basic detection", async () => {
  const f = await findFor(`const k = '${AIRTABLE_PAT}';`, "airtable_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: PAT in object property.
test("airtable_pat: object property", async () => {
  const f = await findFor(`const cfg = { airtable: { pat: '${AIRTABLE_PAT}' } };`, "airtable_pat");
  assert.ok(f);
});

// WHY: PAT in template literal.
test("airtable_pat: template literal", async () => {
  const f = await findFor("const a = `Authorization: Bearer " + AIRTABLE_PAT + "`;", "airtable_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("airtable_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.AIRTABLE_PAT;`, "airtable_pat");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("airtable_pat: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'patYOUR_AIRTABL.YOUR_AIRTABLE_PERSONAL_ACCESS_TOKEN_FILL_TO_64_HEX_CHARS_X1';`, "airtable_pat");
  assert.equal(f, undefined);
});

// ============================================================
// shopify_access_token (shpat_ + 32 hex)
// ============================================================

// WHY: shpat_ Admin API access token.
test("shopify_access_token: basic detection", async () => {
  const f = await findFor(`const k = '${SHOPIFY_AT}';`, "shopify_access_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("shopify_access_token: object property", async () => {
  const f = await findFor(`const cfg = { shopify: { token: '${SHOPIFY_AT}' } };`, "shopify_access_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("shopify_access_token: template literal", async () => {
  const f = await findFor("const a = `X-Shopify-Access-Token: " + SHOPIFY_AT + "`;", "shopify_access_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("shopify_access_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SHOPIFY_ACCESS_TOKEN;`, "shopify_access_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("shopify_access_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'shpat_YOUR_SHOPIFY_ADMIN_API_PLACEH';`, "shopify_access_token");
  assert.equal(f, undefined);
});

// ============================================================
// shopify_custom_app (shpca_)
// ============================================================

// WHY: shpca_ custom app token.
test("shopify_custom_app: basic detection", async () => {
  const f = await findFor(`const k = '${SHOPIFY_CUSTOM}';`, "shopify_custom_app");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("shopify_custom_app: object property", async () => {
  const f = await findFor(`const cfg = { shopify: { customApp: '${SHOPIFY_CUSTOM}' } };`, "shopify_custom_app");
  assert.ok(f);
});

// WHY: token in template literal.
test("shopify_custom_app: template literal", async () => {
  const f = await findFor("const a = `Bearer " + SHOPIFY_CUSTOM + "`;", "shopify_custom_app");
  assert.ok(f);
});

// WHY: env reference safe.
test("shopify_custom_app: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SHOPIFY_CUSTOM_APP_TOKEN;`, "shopify_custom_app");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("shopify_custom_app: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'shpca_YOUR_SHOPIFY_CUSTOM_APP_PLACE';`, "shopify_custom_app");
  assert.equal(f, undefined);
});

// ============================================================
// shopify_private_app (shppa_)
// ============================================================

// WHY: shppa_ private app password.
test("shopify_private_app: basic detection", async () => {
  const f = await findFor(`const k = '${SHOPIFY_PRIVATE}';`, "shopify_private_app");
  assert.ok(f);
});

// WHY: in object property.
test("shopify_private_app: object property", async () => {
  const f = await findFor(`const cfg = { shopify: { privatePass: '${SHOPIFY_PRIVATE}' } };`, "shopify_private_app");
  assert.ok(f);
});

// WHY: in template literal.
test("shopify_private_app: template literal", async () => {
  const f = await findFor("const a = `pwd=" + SHOPIFY_PRIVATE + "`;", "shopify_private_app");
  assert.ok(f);
});

// WHY: env reference safe.
test("shopify_private_app: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SHOPIFY_PRIVATE_APP;`, "shopify_private_app");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("shopify_private_app: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'shppa_YOUR_SHOPIFY_PRIVATE_APP_PASS';`, "shopify_private_app");
  assert.equal(f, undefined);
});

// ============================================================
// zendesk_api_token (40 alnum, contextual)
// ============================================================

// WHY: contextual zendesk_token = 'value' shape.
test("zendesk_api_token: basic detection", async () => {
  const f = await findFor(`zendesk_token = '${ZENDESK_VAL}'`, "zendesk_api_token");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: zendesk_api_token alias variant.
test("zendesk_api_token: api_token alias", async () => {
  const f = await findFor(`zendesk_api_token = '${ZENDESK_VAL}'`, "zendesk_api_token");
  assert.ok(f);
});

// WHY: object property variant.
test("zendesk_api_token: object property", async () => {
  const f = await findFor(`const cfg = { zendesk_token: '${ZENDESK_VAL}' };`, "zendesk_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("zendesk_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ZENDESK_TOKEN;`, "zendesk_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("zendesk_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`zendesk_token = 'YOUR_ZENDESK_API_TOKEN_PLACEHOLDR_X'`, "zendesk_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// intercom_pat (dG9rOi + 40+)
// ============================================================

// WHY: dG9rOi-prefixed Intercom PAT (base64-encoded).
test("intercom_pat: basic detection", async () => {
  const f = await findFor(`const k = '${INTERCOM_PAT}';`, "intercom_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: PAT in object property.
test("intercom_pat: object property", async () => {
  const f = await findFor(`const cfg = { intercom: { token: '${INTERCOM_PAT}' } };`, "intercom_pat");
  assert.ok(f);
});

// WHY: PAT in template literal.
test("intercom_pat: template literal", async () => {
  const f = await findFor("const a = `Bearer " + INTERCOM_PAT + "`;", "intercom_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("intercom_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.INTERCOM_TOKEN;`, "intercom_pat");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("intercom_pat: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'dG9rOiYOUR_INTERCOM_PERSONAL_ACCESS_TOKEN_PLACE';`, "intercom_pat");
  assert.equal(f, undefined);
});

// ============================================================
// hubspot_pat (pat-na/eu-<uuid>)
// ============================================================

// WHY: HubSpot PAT format with region prefix.
test("hubspot_pat: basic detection", async () => {
  const f = await findFor(`const k = '${HUBSPOT_PAT}';`, "hubspot_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: eu region variant.
test("hubspot_pat: eu region", async () => {
  const eu = "pat-eu1-01234567-89ab-cdef-0123-456789abcdef";
  const f = await findFor(`const k = '${eu}';`, "hubspot_pat");
  assert.ok(f);
});

// WHY: PAT in object property.
test("hubspot_pat: object property", async () => {
  const f = await findFor(`const cfg = { hubspot: { token: '${HUBSPOT_PAT}' } };`, "hubspot_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("hubspot_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.HUBSPOT_PAT;`, "hubspot_pat");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("hubspot_pat: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'pat-na1-YOURPLACEHOLD-AAAA-BBBB-CCCC-DDDDEEEEFFFF';`, "hubspot_pat");
  assert.equal(f, undefined);
});

// ============================================================
// salesforce_access_token (00D...!...)
// ============================================================

// WHY: Salesforce access token has the 00D org prefix + ! separator.
test("salesforce_access_token: basic detection", async () => {
  const f = await findFor(`const k = '${SALESFORCE_AT}';`, "salesforce_access_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("salesforce_access_token: object property", async () => {
  const f = await findFor(`const cfg = { sf: { accessToken: '${SALESFORCE_AT}' } };`, "salesforce_access_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("salesforce_access_token: template literal", async () => {
  const f = await findFor("const a = `Authorization: Bearer " + SALESFORCE_AT + "`;", "salesforce_access_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("salesforce_access_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SALESFORCE_ACCESS_TOKEN;`, "salesforce_access_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("salesforce_access_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = '00D0000000000AB!YOUR_SALESFORCE_ACCESS_TOKEN_PLACE';`, "salesforce_access_token");
  assert.equal(f, undefined);
});

// ============================================================
// algolia_admin_key (32 hex, contextual)
// ============================================================

// WHY: contextual algolia_admin_key = '32-hex' shape.
test("algolia_admin_key: basic detection", async () => {
  const f = await findFor(`algolia_admin_key = '${ALGOLIA_HEX}'`, "algolia_admin_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: object property variant.
test("algolia_admin_key: object property", async () => {
  const f = await findFor(`const cfg = { algolia_admin_key: '${ALGOLIA_HEX}' };`, "algolia_admin_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("algolia_admin_key: kebab-case", async () => {
  const f = await findFor(`algolia-admin-key = '${ALGOLIA_HEX}'`, "algolia_admin_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("algolia_admin_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ALGOLIA_ADMIN_KEY;`, "algolia_admin_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("algolia_admin_key: placeholder NOT flagged", async () => {
  const f = await findFor(`algolia_admin_key = 'YOUR_ALGOLIA_ADMIN_KEY_PLACEHOLDER_X'`, "algolia_admin_key");
  assert.equal(f, undefined);
});

// ============================================================
// mapbox_secret_token (sk.eyJ...)
// ============================================================

// WHY: sk. prefix is the canonical Mapbox secret token (vs pk. public).
test("mapbox_secret_token: basic detection", async () => {
  const f = await findFor(`const k = '${MAPBOX_SECRET}';`, "mapbox_secret_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("mapbox_secret_token: object property", async () => {
  const f = await findFor(`const cfg = { mapbox: { secretToken: '${MAPBOX_SECRET}' } };`, "mapbox_secret_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("mapbox_secret_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + MAPBOX_SECRET + "`;", "mapbox_secret_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("mapbox_secret_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAPBOX_SECRET_TOKEN;`, "mapbox_secret_token");
  assert.equal(f, undefined);
});

// WHY: env reference (with sk.eyJ prefix in env name) must not fire.
test("mapbox_secret_token: env path reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MAPBOX_SECRET_TOKEN_SK;`, "mapbox_secret_token");
  assert.equal(f, undefined);
});

// ============================================================
// twilio_account_sid (AC + 32 hex)
// ============================================================

// WHY: AC-prefixed Twilio Account SID.
test("twilio_account_sid: basic detection", async () => {
  const f = await findFor(`const k = '${TWILIO_SID}';`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: client init pattern.
test("twilio_account_sid: client init", async () => {
  const f = await findFor(`const c = twilio('${TWILIO_SID}', authToken);`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: object property.
test("twilio_account_sid: object property", async () => {
  const f = await findFor(`const cfg = { twilio: { accountSid: '${TWILIO_SID}' } };`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: env reference safe.
test("twilio_account_sid: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.TWILIO_ACCOUNT_SID;`, "twilio_account_sid");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("twilio_account_sid: placeholder NOT flagged", async () => {
  const f = await findFor(`const sid = 'YOUR_TWILIO_ACCOUNT_SID_PLACEHOLDER_X';`, "twilio_account_sid");
  assert.equal(f, undefined);
});

// ============================================================
// posthog_personal_api_key (phx_ + 40+)
// ============================================================

// WHY: phx_ personal API key (full account access).
test("posthog_personal_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${POSTHOG_PERSONAL}';`, "posthog_personal_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("posthog_personal_api_key: object property", async () => {
  const f = await findFor(`const cfg = { posthog: { personalApiKey: '${POSTHOG_PERSONAL}' } };`, "posthog_personal_api_key");
  assert.ok(f);
});

// WHY: token in template literal.
test("posthog_personal_api_key: template literal", async () => {
  const f = await findFor("const a = `Bearer " + POSTHOG_PERSONAL + "`;", "posthog_personal_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("posthog_personal_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.POSTHOG_PERSONAL_API_KEY;`, "posthog_personal_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("posthog_personal_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'phx_YOUR_POSTHOG_PERSONAL_API_KEY_PLAC';`, "posthog_personal_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// planetscale_token (pscale_tkn_ + 40+)
// ============================================================

// WHY: PlanetScale tkn token format.
test("planetscale_token: basic detection", async () => {
  const f = await findFor(`const k = '${PLANETSCALE}';`, "planetscale_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: pw variant (password).
test("planetscale_token: pw variant", async () => {
  const pw = "pscale_pw_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";
  const f = await findFor(`const k = '${pw}';`, "planetscale_token");
  assert.ok(f);
});

// WHY: oauth variant.
test("planetscale_token: oauth variant", async () => {
  const o = "pscale_oauth_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";
  const f = await findFor(`const k = '${o}';`, "planetscale_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("planetscale_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.PLANETSCALE_TOKEN;`, "planetscale_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("planetscale_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'pscale_tkn_YOUR_PLANETSCALE_TOKEN_PLACEH';`, "planetscale_token");
  assert.equal(f, undefined);
});

// ============================================================
// xata_api_key (xau_ + 40+)
// ============================================================

// WHY: xau_ Xata API key prefix.
test("xata_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${XATA}';`, "xata_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: token in object property.
test("xata_api_key: object property", async () => {
  const f = await findFor(`const cfg = { xata: { apiKey: '${XATA}' } };`, "xata_api_key");
  assert.ok(f);
});

// WHY: token in template literal.
test("xata_api_key: template literal", async () => {
  const f = await findFor("const a = `Authorization: Bearer " + XATA + "`;", "xata_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("xata_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.XATA_API_KEY;`, "xata_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("xata_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'xau_YOUR_XATA_API_KEY_PLACEHOLDR_X';`, "xata_api_key");
  assert.equal(f, undefined);
});
