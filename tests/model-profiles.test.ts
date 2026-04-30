import { test } from "node:test";
import assert from "node:assert/strict";
import { getModelProfile, truncateCodeForModel } from "../src/engines/model-profiles.ts";

test("getModelProfile anthropic claude-opus-4-5 returns opus tier with right context window", () => {
  const p = getModelProfile("anthropic", "claude-opus-4-5");
  assert.equal(p.tier, "opus");
  assert.equal(p.contextWindow, 200_000);
  assert.equal(p.provider, "anthropic");
  assert.equal(p.id, "claude-opus-4-5");
});

test("getModelProfile ollama deepseek-coder:33b returns sonnet tier", () => {
  const p = getModelProfile("ollama", "deepseek-coder:33b");
  assert.equal(p.tier, "sonnet");
  assert.equal(p.provider, "ollama");
});

test("getModelProfile ollama unknown-model falls back to ollama haiku defaults", () => {
  const p = getModelProfile("ollama", "unknown-model");
  assert.equal(p.tier, "haiku");
  assert.equal(p.provider, "ollama");
  assert.equal(p.contextWindow, 8_000);
  assert.equal(p.jsonReliability, "low");
  assert.equal(p.promptStyle, "structured");
  assert.equal(p.maxCodeLength, 4_000);
});

test("getModelProfile anthropic unknown falls back to anthropic sonnet defaults", () => {
  const p = getModelProfile("anthropic", "unknown");
  assert.equal(p.tier, "sonnet");
  assert.equal(p.provider, "anthropic");
  assert.equal(p.contextWindow, 200_000);
  assert.equal(p.jsonReliability, "high");
});

test("truncateCodeForModel returns code unchanged when under limit", () => {
  const profile = getModelProfile("anthropic", "claude-opus-4-5");
  const code = "const x = 1;\nconst y = 2;";
  assert.equal(truncateCodeForModel(code, profile), code);
});

test("truncateCodeForModel adds [truncated] markers and trims to maxCodeLength", () => {
  const profile = getModelProfile("ollama", "llama3.2:3b"); // maxCodeLength 2000
  const big = "a".repeat(5_000);
  const out = truncateCodeForModel(big, profile);
  assert.ok(out.includes("[truncated by ironward"));
  assert.ok(out.includes("[end truncation]"));
  assert.ok(out.includes(profile.id));
  assert.ok(out.includes(String(profile.maxCodeLength)));
  // The actual code body should be exactly maxCodeLength chars of 'a'
  assert.ok(out.includes("a".repeat(profile.maxCodeLength)));
  // And NOT contain more than maxCodeLength contiguous 'a's
  assert.ok(!out.includes("a".repeat(profile.maxCodeLength + 1)));
});
