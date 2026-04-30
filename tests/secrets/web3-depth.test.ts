import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic web3 credentials. Hex values varied to dodge placeholder filter.
const ETH_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd12"; // 0x + 64 hex
const HEX_32 = "0123456789abcdef0123456789abcdef";
const ETHERSCAN_34 = "ABCDEFGHIJKLMNOP1234567890ABCDE123";
const MORALIS_API = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ12"; // 64+ chars
const ALCHEMY_KEY_32 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"; // 32 chars
const SOLANA_88 = "5KQwrPbwdL6PhXuoyAeJEjJyaSuJrRfPLsxgYZQRRYbRcXKHs2H8eRvmGRiNDCG2zJfYwS9p1pVjk1Frx5K6w5C7"; // 88 base58 (no 0/O/I/l)

const INFURA_URL = "https://mainnet.infura.io/v3/" + HEX_32;
const ALCHEMY_URL = "https://eth-mainnet.g.alchemy.com/v2/aBcDeFgHiJkLmNoPqRsTuVwX";

// ============================================================
// ethereum_private_key (0x + 64 hex)
// ============================================================

// WHY: 0x-prefixed 64-hex private key — the canonical wallet leak.
test("ethereum_private_key: basic detection", async () => {
  const f = await findFor(`const pk = '${ETH_KEY}';`, "ethereum_private_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: ethers.js wallet init pattern.
test("ethereum_private_key: ethers Wallet init", async () => {
  const f = await findFor(`const wallet = new ethers.Wallet('${ETH_KEY}');`, "ethereum_private_key");
  assert.ok(f);
});

// WHY: nested in config object.
test("ethereum_private_key: object property", async () => {
  const f = await findFor(`const cfg = { wallet: { privateKey: '${ETH_KEY}' } };`, "ethereum_private_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("ethereum_private_key: env reference NOT flagged", async () => {
  const f = await findFor(`const pk = process.env.ETH_PRIVATE_KEY;`, "ethereum_private_key");
  assert.equal(f, undefined);
});

// WHY: a placeholder hex with YOUR_ marker must not fire.
test("ethereum_private_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const pk = '0xYOUR_ETH_PRIVATE_KEY_PLACEHOLDR';`, "ethereum_private_key");
  assert.equal(f, undefined);
});

// ============================================================
// infura_project_id (URL-embedded)
// ============================================================

// WHY: full Infura URL with project id is the canonical RPC string.
test("infura_project_id: basic detection", async () => {
  const f = await findFor(`const url = '${INFURA_URL}';`, "infura_project_id");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: URL embedded in object property.
test("infura_project_id: object property", async () => {
  const f = await findFor(`const cfg = { rpcUrl: '${INFURA_URL}' };`, "infura_project_id");
  assert.ok(f);
});

// WHY: URL in template literal.
test("infura_project_id: template literal", async () => {
  const f = await findFor("const u = `" + INFURA_URL + "?cors=allow`;", "infura_project_id");
  assert.ok(f);
});

// WHY: env reference safe.
test("infura_project_id: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.INFURA_URL;`, "infura_project_id");
  assert.equal(f, undefined);
});

// WHY: a placeholder URL must not fire.
test("infura_project_id: placeholder NOT flagged", async () => {
  const f = await findFor(`const url = 'https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID_PLACEHO';`, "infura_project_id");
  assert.equal(f, undefined);
});

// ============================================================
// infura_project_secret (32 hex, contextual)
// ============================================================

// WHY: contextual infura_project_secret = '32-hex' shape.
test("infura_project_secret: basic detection", async () => {
  const f = await findFor(`infura_project_secret = '${HEX_32}'`, "infura_project_secret");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: object property variant.
test("infura_project_secret: object property", async () => {
  const f = await findFor(`const cfg = { infura_project_secret: '${HEX_32}' };`, "infura_project_secret");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("infura_project_secret: kebab-case", async () => {
  const f = await findFor(`infura-project-secret = '${HEX_32}'`, "infura_project_secret");
  assert.ok(f);
});

// WHY: env reference safe.
test("infura_project_secret: env reference NOT flagged", async () => {
  const f = await findFor(`const s = process.env.INFURA_PROJECT_SECRET;`, "infura_project_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("infura_project_secret: placeholder NOT flagged", async () => {
  const f = await findFor(`infura_project_secret = 'YOUR_INFURA_PROJECT_SECRET_PLACEHOLDR'`, "infura_project_secret");
  assert.equal(f, undefined);
});

// ============================================================
// alchemy_api_key_url (URL-embedded)
// ============================================================

// WHY: full Alchemy RPC URL is the canonical leak shape.
test("alchemy_api_key_url: basic detection", async () => {
  const f = await findFor(`const url = '${ALCHEMY_URL}';`, "alchemy_api_key_url");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: URL nested in provider config.
test("alchemy_api_key_url: object property", async () => {
  const f = await findFor(`const cfg = { provider: { url: '${ALCHEMY_URL}' } };`, "alchemy_api_key_url");
  assert.ok(f);
});

// WHY: URL in template literal.
test("alchemy_api_key_url: template literal", async () => {
  const f = await findFor("const u = `" + ALCHEMY_URL + "`;", "alchemy_api_key_url");
  assert.ok(f);
});

// WHY: env reference safe.
test("alchemy_api_key_url: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.ALCHEMY_URL;`, "alchemy_api_key_url");
  assert.equal(f, undefined);
});

// WHY: placeholder URL must not fire.
test("alchemy_api_key_url: placeholder NOT flagged", async () => {
  const f = await findFor(`const url = 'https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY_PLACEHOLDR';`, "alchemy_api_key_url");
  assert.equal(f, undefined);
});

// ============================================================
// alchemy_api_key_contextual (32 chars, contextual)
// ============================================================

// WHY: contextual alchemy_api_key = '32-char' shape.
test("alchemy_api_key_contextual: basic detection", async () => {
  const f = await findFor(`alchemy_api_key = '${ALCHEMY_KEY_32}'`, "alchemy_api_key_contextual");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: alchemy_key alias variant.
test("alchemy_api_key_contextual: alchemy_key alias", async () => {
  const f = await findFor(`alchemy_key = '${ALCHEMY_KEY_32}'`, "alchemy_api_key_contextual");
  assert.ok(f);
});

// WHY: object property variant.
test("alchemy_api_key_contextual: object property", async () => {
  const f = await findFor(`const cfg = { alchemy_api_key: '${ALCHEMY_KEY_32}' };`, "alchemy_api_key_contextual");
  assert.ok(f);
});

// WHY: env reference safe.
test("alchemy_api_key_contextual: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ALCHEMY_API_KEY;`, "alchemy_api_key_contextual");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("alchemy_api_key_contextual: placeholder NOT flagged", async () => {
  const f = await findFor(`alchemy_api_key = 'YOUR_ALCHEMY_API_KEY_HERE_X1234'`, "alchemy_api_key_contextual");
  assert.equal(f, undefined);
});

// ============================================================
// moralis_api_key (64+ alnum, contextual)
// ============================================================

// WHY: contextual moralis_api_key = '64+ char' shape.
test("moralis_api_key: basic detection", async () => {
  const f = await findFor(`moralis_api_key = '${MORALIS_API}'`, "moralis_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("moralis_api_key: object property", async () => {
  const f = await findFor(`const cfg = { moralis_api_key: '${MORALIS_API}' };`, "moralis_api_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("moralis_api_key: kebab-case", async () => {
  const f = await findFor(`moralis-api-key = '${MORALIS_API}'`, "moralis_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("moralis_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.MORALIS_API_KEY;`, "moralis_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("moralis_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`moralis_api_key = 'YOUR_MORALIS_API_KEY_PLACEHOLDR_TEXT_VALUE_FILL_TO_64_CHARS_X1'`, "moralis_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// solana_private_key_base58 (87-88 base58 chars, contextual)
// ============================================================

// WHY: contextual solana_private_key = 'base58' shape.
test("solana_private_key_base58: basic detection", async () => {
  const f = await findFor(`solana_private_key = '${SOLANA_88}'`, "solana_private_key_base58");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: sol_private_key alias.
test("solana_private_key_base58: sol alias", async () => {
  const f = await findFor(`sol_private_key = '${SOLANA_88}'`, "solana_private_key_base58");
  assert.ok(f);
});

// WHY: solana_key short alias.
test("solana_private_key_base58: solana_key short alias", async () => {
  const f = await findFor(`solana_key = '${SOLANA_88}'`, "solana_private_key_base58");
  assert.ok(f);
});

// WHY: env reference safe.
test("solana_private_key_base58: env reference NOT flagged", async () => {
  const f = await findFor(`const sk = process.env.SOLANA_PRIVATE_KEY;`, "solana_private_key_base58");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("solana_private_key_base58: placeholder NOT flagged", async () => {
  const f = await findFor(`solana_private_key = 'YOUR_SOLANA_PRIVATE_KEY_PLACEHOLDR_TEXT_VALUE_FILL_88_X12345678901234567890ZZ'`, "solana_private_key_base58");
  assert.equal(f, undefined);
});

// ============================================================
// etherscan_api_key (34 alnum, contextual)
// ============================================================

// WHY: contextual etherscan_api_key = '34-char' shape.
test("etherscan_api_key: basic detection", async () => {
  const f = await findFor(`etherscan_api_key = '${ETHERSCAN_34}'`, "etherscan_api_key");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("etherscan_api_key: object property", async () => {
  const f = await findFor(`const cfg = { etherscan_api_key: '${ETHERSCAN_34}' };`, "etherscan_api_key");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("etherscan_api_key: kebab-case", async () => {
  const f = await findFor(`etherscan-api-key = '${ETHERSCAN_34}'`, "etherscan_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("etherscan_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ETHERSCAN_API_KEY;`, "etherscan_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("etherscan_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`etherscan_api_key = 'YOUR_ETHERSCAN_API_KEY_PLACEHOLDR_X'`, "etherscan_api_key");
  assert.equal(f, undefined);
});
