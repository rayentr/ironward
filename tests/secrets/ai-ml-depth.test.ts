import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic AI/ML provider tokens — pattern-shaped but not real.
// openai_key requires 20+ chars before AND after the T3BlbkFJ marker.
const OPENAI_KEY    = "sk-proj-aBcDeFgHiJkLmNoPqRsTuT3BlbkFJzxAbCdEfGhIjKlMnOpQr"; // 20 + T3BlbkFJ + 22
const ANTHROPIC_KEY = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV0123456789-_abcdefghijkABCDEFG12";
const HF_TOKEN      = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
const REPLICATE_TOK = "r8_AbCdEfGhIjKlMnOpQrStUvWxYz01234567890ab";  // r8_ + 38
const GROQ_KEY      = "gsk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp"; // gsk_ + 52
const COHERE_KEY    = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"; // 40 chars
const PERPLEXITY    = "pplx-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl"; // pplx- + 48

// ============================================================
// openai_key
// ============================================================

// WHY: basic — sk-proj-...T3BlbkFJ... openai key fires critical.
test("openai_key: basic detection", async () => {
  const code = `const k = '${OPENAI_KEY}';`;
  const f = await findFor(code, "openai_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — key in config object still fires.
test("openai_key: object property", async () => {
  const code = `const cfg = { openai: { apiKey: '${OPENAI_KEY}' } };`;
  const f = await findFor(code, "openai_key");
  assert.ok(f);
});

// WHY: template literal — Bearer-style template fires.
test("openai_key: template literal", async () => {
  const code = "const a = `Bearer " + OPENAI_KEY + "`;";
  const f = await findFor(code, "openai_key");
  assert.ok(f);
});

// WHY: placeholder — XXX-padded openai key not flagged.
test("openai_key: placeholder NOT flagged", async () => {
  const code = `const k = 'sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "openai_key");
  assert.equal(f, undefined);
});

// WHY: env reference — env var reference must not fire.
test("openai_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.OPENAI_API_KEY;`;
  const f = await findFor(code, "openai_key");
  assert.equal(f, undefined);
});

// ============================================================
// anthropic_api_key
// ============================================================

// WHY: basic — sk-ant-api03-... fires critical.
test("anthropic_api_key: basic detection", async () => {
  const code = `const k = '${ANTHROPIC_KEY}';`;
  const f = await findFor(code, "anthropic_api_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("anthropic_api_key: object property", async () => {
  const code = `const cfg = { anthropic: { key: '${ANTHROPIC_KEY}' } };`;
  const f = await findFor(code, "anthropic_api_key");
  assert.ok(f);
});

// WHY: template literal.
test("anthropic_api_key: template literal", async () => {
  const code = "const a = `Bearer " + ANTHROPIC_KEY + "`;";
  const f = await findFor(code, "anthropic_api_key");
  assert.ok(f);
});

// WHY: placeholder.
test("anthropic_api_key: placeholder NOT flagged", async () => {
  const code = `const k = 'sk-ant-api03-YOUR_ANTHROPIC_KEY_HERE_PLACEHOLDER_VALUE_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`;
  const f = await findFor(code, "anthropic_api_key");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("anthropic_api_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.ANTHROPIC_API_KEY;`;
  const f = await findFor(code, "anthropic_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// huggingface_token (hf_)
// ============================================================

// WHY: basic.
test("huggingface_token: basic detection", async () => {
  const code = `const t = '${HF_TOKEN}';`;
  const f = await findFor(code, "huggingface_token");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("huggingface_token: object property", async () => {
  const code = `const cfg = { hf: { token: '${HF_TOKEN}' } };`;
  const f = await findFor(code, "huggingface_token");
  assert.ok(f);
});

// WHY: template literal.
test("huggingface_token: template literal", async () => {
  const code = "const a = `Bearer " + HF_TOKEN + "`;";
  const f = await findFor(code, "huggingface_token");
  assert.ok(f);
});

// WHY: placeholder.
test("huggingface_token: placeholder NOT flagged", async () => {
  const code = `const t = 'hf_YOUR_HUGGINGFACE_TOKEN_PLACEHOLDER';`;
  const f = await findFor(code, "huggingface_token");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("huggingface_token: env reference NOT flagged", async () => {
  const code = `const t = process.env.HF_TOKEN;`;
  const f = await findFor(code, "huggingface_token");
  assert.equal(f, undefined);
});

// ============================================================
// replicate_token (r8_)
// ============================================================

// WHY: basic.
test("replicate_token: basic detection", async () => {
  const code = `const t = '${REPLICATE_TOK}';`;
  const f = await findFor(code, "replicate_token");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("replicate_token: object property", async () => {
  const code = `const cfg = { replicate: { token: '${REPLICATE_TOK}' } };`;
  const f = await findFor(code, "replicate_token");
  assert.ok(f);
});

// WHY: template literal.
test("replicate_token: template literal", async () => {
  const code = "const a = `Token " + REPLICATE_TOK + "`;";
  const f = await findFor(code, "replicate_token");
  assert.ok(f);
});

// WHY: placeholder.
test("replicate_token: placeholder NOT flagged", async () => {
  const code = `const t = 'r8_YOUR_REPLICATE_TOKEN_HERE_PLACEHOLDER';`;
  const f = await findFor(code, "replicate_token");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("replicate_token: env reference NOT flagged", async () => {
  const code = `const t = process.env.REPLICATE_API_TOKEN;`;
  const f = await findFor(code, "replicate_token");
  assert.equal(f, undefined);
});

// ============================================================
// groq_key (gsk_)
// ============================================================

// WHY: basic.
test("groq_key: basic detection", async () => {
  const code = `const k = '${GROQ_KEY}';`;
  const f = await findFor(code, "groq_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("groq_key: object property", async () => {
  const code = `const cfg = { groq: { key: '${GROQ_KEY}' } };`;
  const f = await findFor(code, "groq_key");
  assert.ok(f);
});

// WHY: template literal.
test("groq_key: template literal", async () => {
  const code = "const a = `Bearer " + GROQ_KEY + "`;";
  const f = await findFor(code, "groq_key");
  assert.ok(f);
});

// WHY: placeholder.
test("groq_key: placeholder NOT flagged", async () => {
  const code = `const k = 'gsk_YOUR_GROQ_KEY_HERE_PLACEHOLDER_LONG_ENOUGH_FILLER';`;
  const f = await findFor(code, "groq_key");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("groq_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.GROQ_API_KEY;`;
  const f = await findFor(code, "groq_key");
  assert.equal(f, undefined);
});

// ============================================================
// cohere_key — context-prefixed pattern: cohere[_-]?(api[_-]?key|token)\s*[:=]\s*'...'
// ============================================================

// WHY: basic — needs the cohere-prefixed assignment context.
test("cohere_key: basic detection (with context prefix)", async () => {
  const code = `cohere_api_key = '${COHERE_KEY}'`;
  const f = await findFor(code, "cohere_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — pattern requires the cohere context, so use cohere_api_key prop.
test("cohere_key: object property", async () => {
  const code = `const cfg = { cohere_api_key: '${COHERE_KEY}' };`;
  const f = await findFor(code, "cohere_key");
  assert.ok(f);
});

// WHY: template literal — cohere pattern is context-prefixed, so a Bearer template
// does not match. Document the limitation but assert the basic-context literal-string variant.
// TODO: cohere_key requires a `cohere[_-]api[_-]key` prefix to fire — it cannot
// match raw 40-char tokens in a Bearer template literal.
test("cohere_key: template literal NOT flagged (pattern requires cohere prefix)", async () => {
  const code = "const a = `Bearer " + COHERE_KEY + "`;";
  const f = await findFor(code, "cohere_key");
  assert.equal(f, undefined);
});

// WHY: placeholder — token containing a placeholder marker does not fire.
test("cohere_key: placeholder NOT flagged", async () => {
  const code = `cohere_api_key = 'YOUR_COHERE_KEY_PLACEHOLDER_VALUE_XXXXX'`;
  const f = await findFor(code, "cohere_key");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("cohere_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.COHERE_API_KEY;`;
  const f = await findFor(code, "cohere_key");
  assert.equal(f, undefined);
});

// ============================================================
// perplexity_key (pplx-)
// ============================================================

// WHY: basic.
test("perplexity_key: basic detection", async () => {
  const code = `const k = '${PERPLEXITY}';`;
  const f = await findFor(code, "perplexity_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("perplexity_key: object property", async () => {
  const code = `const cfg = { perplexity: { apiKey: '${PERPLEXITY}' } };`;
  const f = await findFor(code, "perplexity_key");
  assert.ok(f);
});

// WHY: template literal.
test("perplexity_key: template literal", async () => {
  const code = "const a = `Bearer " + PERPLEXITY + "`;";
  const f = await findFor(code, "perplexity_key");
  assert.ok(f);
});

// WHY: placeholder.
test("perplexity_key: placeholder NOT flagged", async () => {
  const code = `const k = 'pplx-YOUR_PERPLEXITY_KEY_HERE_PLACEHOLDER_VALUE_XXX';`;
  const f = await findFor(code, "perplexity_key");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("perplexity_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.PERPLEXITY_API_KEY;`;
  const f = await findFor(code, "perplexity_key");
  assert.equal(f, undefined);
});
