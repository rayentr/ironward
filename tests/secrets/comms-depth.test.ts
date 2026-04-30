import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic comms tokens. Synthetic IDs / varied alphabets so the placeholder
// detector (6+ identical chars) doesn't trip.
const SLACK_BOT = "xoxb-1234567890-9876543210-aBcDeFgHiJkLmNoPqRsT";
const SLACK_USER = "xoxp-1234567890-9876543210-1112131415-aBcDeFgHiJkLmNoPqRsT";
const SLACK_APP = "xapp-1-A012345678-1234567890-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SLACK_WEBHOOK = "https://hooks.slack.com/services/T01ABCDEFGH/B01ABCDEFGH/aBcDeFgHiJkLmNoPqRsT0123";
const DISCORD_BOT = "MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf.aBcDeFgHiJkLmNoPqRsTuVwXyZ012";
const DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZab12";
const TWILIO_SID = "AC0123456789abcdef0123456789abcdef";
const TWILIO_API_KEY = "SK0123456789abcdef0123456789abcdef";
const TWILIO_AUTH_TOKEN = "0a1b2c3d4e5f6789abcdef0123456789";
const TELEGRAM_BOT = "123456789:AAH0123456789aBcDeFgHiJkLmNoPqRsTuV"; // 9 digits :AA + 33 chars
const VONAGE_SECRET = "aBcDeFgH1J2K3L4M";
const PLIVO_TOKEN = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH";

// ============================================================
// slack_bot_token (xoxb-...)
// ============================================================

// WHY: canonical xoxb- bot token in a bare assignment.
test("slack_bot_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SLACK_BOT}';`, "slack_bot_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: Slack SDK init nests the token in a config object.
test("slack_bot_token: object property", async () => {
  const f = await findFor(`const cfg = { slack: { botToken: '${SLACK_BOT}' } };`, "slack_bot_token");
  assert.ok(f);
});

// WHY: token in template literal — Authorization header building.
test("slack_bot_token: template literal", async () => {
  const f = await findFor("const auth = `Bearer " + SLACK_BOT + "`;", "slack_bot_token");
  assert.ok(f);
});

// WHY: xoxb-YOUR-TOKEN-HERE is a documentation placeholder — must not fire.
test("slack_bot_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'xoxb-YOUR-SLACK-BOT-TOKEN-HERE-PLACEHOLDR';`, "slack_bot_token");
  assert.equal(f, undefined);
});

// WHY: env reference is the safe pattern.
test("slack_bot_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SLACK_BOT_TOKEN;`, "slack_bot_token");
  assert.equal(f, undefined);
});

// ============================================================
// slack_user_token (xoxp-...)
// ============================================================

// WHY: xoxp- user token is a higher-trust credential than bot.
test("slack_user_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SLACK_USER}';`, "slack_user_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token nested in config object.
test("slack_user_token: object property", async () => {
  const f = await findFor(`const cfg = { slack: { userToken: '${SLACK_USER}' } };`, "slack_user_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("slack_user_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + SLACK_USER + "`;", "slack_user_token");
  assert.ok(f);
});

// WHY: env reference safe pattern.
test("slack_user_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SLACK_USER_TOKEN;`, "slack_user_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("slack_user_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'xoxp-YOUR-SLACK-USER-TOKEN-HERE-PLACEHOLDR';`, "slack_user_token");
  assert.equal(f, undefined);
});

// ============================================================
// slack_webhook
// ============================================================

// WHY: canonical Slack webhook URL.
test("slack_webhook: basic detection", async () => {
  const f = await findFor(`const url = '${SLACK_WEBHOOK}';`, "slack_webhook");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: webhook nested in alerter config.
test("slack_webhook: object property", async () => {
  const f = await findFor(`const alert = { slack: { webhook: '${SLACK_WEBHOOK}' } };`, "slack_webhook");
  assert.ok(f);
});

// WHY: webhook in template literal.
test("slack_webhook: template literal", async () => {
  const f = await findFor("const u = `" + SLACK_WEBHOOK + "?ts=now`;", "slack_webhook");
  assert.ok(f);
});

// WHY: env reference is safe.
test("slack_webhook: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.SLACK_WEBHOOK;`, "slack_webhook");
  assert.equal(f, undefined);
});

// WHY: placeholder URL with YOUR/WEBHOOK/HERE must not fire.
test("slack_webhook: placeholder NOT flagged", async () => {
  const f = await findFor(`const url = 'https://hooks.slack.com/services/TYOURTEAM/BYOURBOTID/YOUR_PLACEHOLDR_HERE';`, "slack_webhook");
  assert.equal(f, undefined);
});

// ============================================================
// slack_app_token (xapp-...)
// ============================================================

// WHY: xapp- app-level token used for Socket Mode.
test("slack_app_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SLACK_APP}';`, "slack_app_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("slack_app_token: object property", async () => {
  const f = await findFor(`const cfg = { slack: { appToken: '${SLACK_APP}' } };`, "slack_app_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("slack_app_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + SLACK_APP + "`;", "slack_app_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("slack_app_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SLACK_APP_TOKEN;`, "slack_app_token");
  assert.equal(f, undefined);
});

// WHY: placeholder text must not fire.
test("slack_app_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'xapp-YOUR-SLACK-APP-TOKEN-HERE-PLACEHOLDR';`, "slack_app_token");
  assert.equal(f, undefined);
});

// ============================================================
// discord_bot_token
// ============================================================

// WHY: canonical 3-part Discord bot token format.
test("discord_bot_token: basic detection", async () => {
  const f = await findFor(`const tok = '${DISCORD_BOT}';`, "discord_bot_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: discord.js client.login() pattern.
test("discord_bot_token: client.login pattern", async () => {
  const f = await findFor(`client.login('${DISCORD_BOT}');`, "discord_bot_token");
  assert.ok(f);
});

// WHY: token in object property.
test("discord_bot_token: object property", async () => {
  const f = await findFor(`const cfg = { discord: { token: '${DISCORD_BOT}' } };`, "discord_bot_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("discord_bot_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.DISCORD_BOT_TOKEN;`, "discord_bot_token");
  assert.equal(f, undefined);
});

// WHY: placeholder text must not fire.
test("discord_bot_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'YOUR_DISCORD_TOKEN_PLACEHOLDER';`, "discord_bot_token");
  assert.equal(f, undefined);
});

// ============================================================
// discord_webhook
// ============================================================

// WHY: canonical Discord webhook URL.
test("discord_webhook: basic detection", async () => {
  const f = await findFor(`const url = '${DISCORD_WEBHOOK}';`, "discord_webhook");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: webhook in object property.
test("discord_webhook: object property", async () => {
  const f = await findFor(`const cfg = { discord: { webhook: '${DISCORD_WEBHOOK}' } };`, "discord_webhook");
  assert.ok(f);
});

// WHY: webhook in template literal.
test("discord_webhook: template literal", async () => {
  const f = await findFor("const u = `" + DISCORD_WEBHOOK + "`;", "discord_webhook");
  assert.ok(f);
});

// WHY: env reference safe.
test("discord_webhook: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.DISCORD_WEBHOOK;`, "discord_webhook");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("discord_webhook: placeholder NOT flagged", async () => {
  const f = await findFor(`const url = 'https://discord.com/api/webhooks/YOUR_PLACEHOLDER_ID/YOUR_PLACEHOLDR_TOKEN_HERE';`, "discord_webhook");
  assert.equal(f, undefined);
});

// ============================================================
// twilio_account_sid (AC + 32 hex)
// ============================================================

// WHY: canonical Twilio AC-prefixed Account SID.
test("twilio_account_sid: basic detection", async () => {
  const f = await findFor(`const sid = '${TWILIO_SID}';`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: Twilio client init pattern.
test("twilio_account_sid: client init pattern", async () => {
  const f = await findFor(`const client = twilio('${TWILIO_SID}', authToken);`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: SID in object property.
test("twilio_account_sid: object property", async () => {
  const f = await findFor(`const cfg = { twilio: { accountSid: '${TWILIO_SID}' } };`, "twilio_account_sid");
  assert.ok(f);
});

// WHY: env reference safe.
test("twilio_account_sid: env reference NOT flagged", async () => {
  const f = await findFor(`const sid = process.env.TWILIO_ACCOUNT_SID;`, "twilio_account_sid");
  assert.equal(f, undefined);
});

// WHY: a placeholder string with YOUR text must not fire.
test("twilio_account_sid: placeholder NOT flagged", async () => {
  const f = await findFor(`const sid = 'YOUR_TWILIO_ACCOUNT_SID_PLACEHOLDER_X';`, "twilio_account_sid");
  assert.equal(f, undefined);
});

// ============================================================
// twilio_api_key (SK + 32 hex)
// ============================================================

// WHY: canonical SK-prefixed Twilio API key.
test("twilio_api_key: basic detection", async () => {
  const f = await findFor(`const key = '${TWILIO_API_KEY}';`, "twilio_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: API key in object property.
test("twilio_api_key: object property", async () => {
  const f = await findFor(`const cfg = { twilio: { apiKey: '${TWILIO_API_KEY}' } };`, "twilio_api_key");
  assert.ok(f);
});

// WHY: API key in template literal.
test("twilio_api_key: template literal", async () => {
  const f = await findFor("const a = `key=" + TWILIO_API_KEY + "`;", "twilio_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("twilio_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const key = process.env.TWILIO_API_KEY;`, "twilio_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("twilio_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const key = 'YOUR_TWILIO_API_KEY_PLACEHOLDER_X';`, "twilio_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// twilio_auth_token_contextual
// ============================================================

// WHY: contextual rule needs the twilio_auth_token=... assignment shape.
test("twilio_auth_token_contextual: basic detection", async () => {
  const f = await findFor(`twilio_auth_token = '${TWILIO_AUTH_TOKEN}'`, "twilio_auth_token_contextual");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: object property variant.
test("twilio_auth_token_contextual: object property", async () => {
  const f = await findFor(`const cfg = { twilio_auth_token: '${TWILIO_AUTH_TOKEN}' };`, "twilio_auth_token_contextual");
  assert.ok(f);
});

// WHY: env reference safe.
test("twilio_auth_token_contextual: env reference NOT flagged", async () => {
  const f = await findFor(`const t = process.env.TWILIO_AUTH_TOKEN;`, "twilio_auth_token_contextual");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("twilio_auth_token_contextual: placeholder NOT flagged", async () => {
  const f = await findFor(`twilio_auth_token = 'YOUR_TWILIO_AUTH_TOKEN_PLACEHOLDR'`, "twilio_auth_token_contextual");
  assert.equal(f, undefined);
});

// WHY: severity metadata lock-in (auth tokens grant full account access).
test("twilio_auth_token_contextual: critical severity", async () => {
  const f = await findFor(`twilio_auth_token = '${TWILIO_AUTH_TOKEN}'`, "twilio_auth_token_contextual");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// ============================================================
// telegram_bot_token
// ============================================================

// WHY: canonical Telegram Bot API token format.
test("telegram_bot_token: basic detection", async () => {
  const f = await findFor(`const tok = '${TELEGRAM_BOT}';`, "telegram_bot_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("telegram_bot_token: object property", async () => {
  const f = await findFor(`const bot = { token: '${TELEGRAM_BOT}' };`, "telegram_bot_token");
  assert.ok(f);
});

// WHY: token after Bearer prefix (auth header style — NOT inside path which
// would attach a non-word boundary).
test("telegram_bot_token: bearer prefix", async () => {
  const f = await findFor("const a = `Bearer " + TELEGRAM_BOT + "`;", "telegram_bot_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("telegram_bot_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.TELEGRAM_BOT_TOKEN;`, "telegram_bot_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("telegram_bot_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = '123456789:AAYOUR_TELEGRAM_BOT_TOKEN_PLACEHOLDR';`, "telegram_bot_token");
  assert.equal(f, undefined);
});

// ============================================================
// vonage_api_secret (Nexmo)
// ============================================================

// WHY: contextual vonage_api_secret = '...' shape.
test("vonage_api_secret: basic detection", async () => {
  const f = await findFor(`vonage_api_secret = '${VONAGE_SECRET}'`, "vonage_api_secret");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: legacy nexmo_api_secret name still in use.
test("vonage_api_secret: nexmo alias", async () => {
  const f = await findFor(`nexmo_api_secret = '${VONAGE_SECRET}'`, "vonage_api_secret");
  assert.ok(f);
});

// WHY: secret in object property.
test("vonage_api_secret: object property", async () => {
  const f = await findFor(`const cfg = { vonage_api_secret: '${VONAGE_SECRET}' };`, "vonage_api_secret");
  assert.ok(f);
});

// WHY: env reference safe.
test("vonage_api_secret: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.VONAGE_API_SECRET;`, "vonage_api_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("vonage_api_secret: placeholder NOT flagged", async () => {
  const f = await findFor(`vonage_api_secret = 'YOUR_VONAGE_SECRET'`, "vonage_api_secret");
  assert.equal(f, undefined);
});

// ============================================================
// plivo_auth_token (Plivo)
// ============================================================

// WHY: contextual plivo_auth_token = '...' shape.
test("plivo_auth_token: basic detection", async () => {
  const f = await findFor(`plivo_auth_token = '${PLIVO_TOKEN}'`, "plivo_auth_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("plivo_auth_token: object property", async () => {
  const f = await findFor(`const cfg = { plivo_auth_token: '${PLIVO_TOKEN}' };`, "plivo_auth_token");
  assert.ok(f);
});

// WHY: severity metadata for SMS/voice provider auth token.
test("plivo_auth_token: critical severity", async () => {
  const f = await findFor(`plivo_auth_token = '${PLIVO_TOKEN}'`, "plivo_auth_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: env reference safe.
test("plivo_auth_token: env reference NOT flagged", async () => {
  const f = await findFor(`const t = process.env.PLIVO_AUTH_TOKEN;`, "plivo_auth_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("plivo_auth_token: placeholder NOT flagged", async () => {
  const f = await findFor(`plivo_auth_token = 'YOUR_PLIVO_AUTH_TOKEN_PLACEHOLDER_X'`, "plivo_auth_token");
  assert.equal(f, undefined);
});
