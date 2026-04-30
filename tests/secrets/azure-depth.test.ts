import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic Azure credentials. 88-char base64 for storage keys, varied alphabets
// to dodge the placeholder filter (6+ identical chars).
const AZ_STORAGE_KEY_88 =
  "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg+/=Hi1JkL=="; // 88 chars
const AZ_SVCBUS_KEY_44 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg="; // 44 chars
const AZ_SUB_KEY_HEX = "0a1b2c3d4e5f6789abcdef0123456789"; // 32 hex chars
const AZ_AD_CLIENT_SECRET = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789~aBcDeF"; // contains ~

// ============================================================
// azure_storage_key (AccountKey/SharedAccessKey = 88 chars)
// ============================================================

// WHY: canonical AccountKey assignment with an 88-char base64 secret.
test("azure_storage_key: basic detection", async () => {
  const code = `AccountKey=${AZ_STORAGE_KEY_88}`;
  const f = await findFor(code, "azure_storage_key");
  assert.ok(f, "expected azure_storage_key finding");
  assert.equal(f.severity, "critical");
});

// WHY: SDK init usually nests AccountKey inside an options object.
test("azure_storage_key: object property with SharedAccessKey", async () => {
  const code = `const opts = "SharedAccessKey=${AZ_STORAGE_KEY_88}";`;
  const f = await findFor(code, "azure_storage_key");
  assert.ok(f);
});

// WHY: env files use KEY=value with no quotes; the rule must still match.
test("azure_storage_key: env-file format", async () => {
  const code = `STORAGE_KEY_LINE=AccountKey=${AZ_STORAGE_KEY_88}`;
  const f = await findFor(code, "azure_storage_key");
  assert.ok(f);
});

// WHY: explicit placeholder text must not fire.
test("azure_storage_key: placeholder NOT flagged", async () => {
  const code = `AccountKey=YOUR_AZURE_STORAGE_KEY_PLACEHOLDER` + "x".repeat(50);
  const f = await findFor(code, "azure_storage_key");
  assert.equal(f, undefined);
});

// WHY: env var reference is the safe pattern.
test("azure_storage_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.AZURE_STORAGE_KEY;`;
  const f = await findFor(code, "azure_storage_key");
  assert.equal(f, undefined);
});

// ============================================================
// azure_storage_connection_string
// ============================================================

// WHY: full connection-string is the most copy-pasted Azure secret format.
test("azure_storage_connection_string: basic detection", async () => {
  const code = `const cs = "DefaultEndpointsProtocol=https;AccountName=demo123;AccountKey=${AZ_STORAGE_KEY_88}";`;
  const f = await findFor(code, "azure_storage_connection_string");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: same string nested in a config object.
test("azure_storage_connection_string: object property", async () => {
  const code = `const cfg = { storage: { conn: "DefaultEndpointsProtocol=https;AccountName=acc;AccountKey=${AZ_STORAGE_KEY_88}" } };`;
  const f = await findFor(code, "azure_storage_connection_string");
  assert.ok(f);
});

// WHY: connection string in a template literal still triggers.
test("azure_storage_connection_string: template literal", async () => {
  const code = "const cs = `DefaultEndpointsProtocol=https;AccountName=t;AccountKey=" + AZ_STORAGE_KEY_88 + "`;";
  const f = await findFor(code, "azure_storage_connection_string");
  assert.ok(f);
});

// WHY: a placeholder-bearing AccountKey value must not fire.
test("azure_storage_connection_string: placeholder NOT flagged", async () => {
  const code = `const cs = "DefaultEndpointsProtocol=https;AccountName=YOUR_ACCOUNT;AccountKey=YOUR_PLACEHOLDER_KEY_HERE";`;
  const f = await findFor(code, "azure_storage_connection_string");
  assert.equal(f, undefined);
});

// WHY: env reference is safe.
test("azure_storage_connection_string: env reference NOT flagged", async () => {
  const code = `const cs = process.env.AZURE_STORAGE_CONNECTION_STRING;`;
  const f = await findFor(code, "azure_storage_connection_string");
  assert.equal(f, undefined);
});

// ============================================================
// azure_sas_token
// ============================================================

const AZ_SAS =
  "sv=2023-01-03&sr=b&st=2024-01-01T00:00:00Z&se=2024-12-31T00:00:00Z&sp=r&sig=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHi%2BJkL";

// WHY: canonical SAS token format with sv= sr= st= se= sp= sig= chain.
test("azure_sas_token: basic detection", async () => {
  const code = `const sas = "?${AZ_SAS}";`;
  const f = await findFor(code, "azure_sas_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: SAS appended to a blob URL — the typical real-world shape.
test("azure_sas_token: blob URL", async () => {
  const code = `const url = "https://acc.blob.core.windows.net/container/file.txt?${AZ_SAS}";`;
  const f = await findFor(code, "azure_sas_token");
  assert.ok(f);
});

// WHY: SAS in template literal — common when building URLs at runtime.
test("azure_sas_token: template literal", async () => {
  const code = "const u = `${baseUrl}?" + AZ_SAS + "`;";
  const f = await findFor(code, "azure_sas_token");
  assert.ok(f);
});

// WHY: an obvious placeholder SAS should not fire.
test("azure_sas_token: placeholder NOT flagged", async () => {
  const code = `const sas = "sv=2024-01-01&sr=b&st=YOUR_START&se=YOUR_END&sp=r&sig=YOUR_PLACEHOLDER_SIG";`;
  const f = await findFor(code, "azure_sas_token");
  assert.equal(f, undefined);
});

// WHY: env reference safe pattern.
test("azure_sas_token: env reference NOT flagged", async () => {
  const code = `const sas = process.env.AZURE_SAS_TOKEN;`;
  const f = await findFor(code, "azure_sas_token");
  assert.equal(f, undefined);
});

// ============================================================
// azure_service_bus_key
// ============================================================

const AZ_SB_CS = `Endpoint=sb://my-bus.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=${AZ_SVCBUS_KEY_44}`;

// WHY: canonical Service Bus connection string with 44-char base64 key.
test("azure_service_bus_key: basic detection", async () => {
  const code = `const sb = "${AZ_SB_CS}";`;
  const f = await findFor(code, "azure_service_bus_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: SB connection string nested in config.
test("azure_service_bus_key: object property", async () => {
  const code = `const cfg = { bus: { conn: "${AZ_SB_CS}" } };`;
  const f = await findFor(code, "azure_service_bus_key");
  assert.ok(f);
});

// WHY: SB connection in template literal.
test("azure_service_bus_key: template literal", async () => {
  const code = "const sb = `" + AZ_SB_CS + "`;";
  const f = await findFor(code, "azure_service_bus_key");
  assert.ok(f);
});

// WHY: placeholder Service Bus key must not fire.
test("azure_service_bus_key: placeholder NOT flagged", async () => {
  const code = `const sb = "Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=YOUR_AZURE_SERVICE_BUS_KEY_PLACEHOLDR=";`;
  const f = await findFor(code, "azure_service_bus_key");
  assert.equal(f, undefined);
});

// WHY: env var reference is the safe pattern.
test("azure_service_bus_key: env reference NOT flagged", async () => {
  const code = `const sb = process.env.AZURE_SERVICE_BUS_CONNECTION;`;
  const f = await findFor(code, "azure_service_bus_key");
  assert.equal(f, undefined);
});

// ============================================================
// azure_subscription_key (Cognitive Services / API Management)
// ============================================================

// WHY: canonical Ocp-Apim-Subscription-Key header value.
test("azure_subscription_key: basic detection", async () => {
  const code = `subscription-key='${AZ_SUB_KEY_HEX}'`;
  const f = await findFor(code, "azure_subscription_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: Ocp-Apim-Subscription-Key form is the common API Management header.
test("azure_subscription_key: ocp-apim header form", async () => {
  const code = `Ocp-Apim-Subscription-Key='${AZ_SUB_KEY_HEX}'`;
  const f = await findFor(code, "azure_subscription_key");
  assert.ok(f);
});

// WHY: header line with key= pair (no quoted key).
test("azure_subscription_key: header assignment with equals", async () => {
  const code = `let req = "Ocp-Apim-Subscription-Key=${AZ_SUB_KEY_HEX}";`;
  const f = await findFor(code, "azure_subscription_key");
  assert.ok(f);
});

// WHY: an obvious YOUR-SUBSCRIPTION-KEY placeholder must not fire.
test("azure_subscription_key: placeholder NOT flagged", async () => {
  const code = `subscription-key='YOUR_SUBSCRIPTION_KEY_PLACEHOLDER'`;
  const f = await findFor(code, "azure_subscription_key");
  assert.equal(f, undefined);
});

// WHY: env var reference safe pattern.
test("azure_subscription_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.AZURE_SUBSCRIPTION_KEY;`;
  const f = await findFor(code, "azure_subscription_key");
  assert.equal(f, undefined);
});

// ============================================================
// azure_ad_client_secret (Entra/AD v2 secrets contain ~)
// ============================================================

// WHY: AD v2 client secrets contain a ~ in a known-length high-entropy string.
test("azure_ad_client_secret: basic detection", async () => {
  const code = `const s = '${AZ_AD_CLIENT_SECRET}';`;
  const f = await findFor(code, "azure_ad_client_secret");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: nested in MSAL config object.
test("azure_ad_client_secret: object property", async () => {
  const code = `const msal = { auth: { clientSecret: '${AZ_AD_CLIENT_SECRET}' } };`;
  const f = await findFor(code, "azure_ad_client_secret");
  assert.ok(f);
});

// WHY: client secret in template literal.
test("azure_ad_client_secret: template literal", async () => {
  const code = "const s = `client_secret=" + AZ_AD_CLIENT_SECRET + "`;";
  const f = await findFor(code, "azure_ad_client_secret");
  assert.ok(f);
});

// WHY: placeholder client secret must not fire.
test("azure_ad_client_secret: placeholder NOT flagged", async () => {
  const code = `const s = 'YOUR_AZURE_AD_CLIENT_SECRET~PLACEHOLDER';`;
  const f = await findFor(code, "azure_ad_client_secret");
  assert.equal(f, undefined);
});

// WHY: env reference is safe.
test("azure_ad_client_secret: env reference NOT flagged", async () => {
  const code = `const s = process.env.AZURE_AD_CLIENT_SECRET;`;
  const f = await findFor(code, "azure_ad_client_secret");
  assert.equal(f, undefined);
});
