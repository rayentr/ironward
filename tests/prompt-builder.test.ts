import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPrompt } from "../src/engines/prompt-builder.ts";
import { getModelProfile } from "../src/engines/model-profiles.ts";

const SAMPLE_CODE = "function login(req) { return db.query('select * from users where id = ' + req.body.id); }";

test("opus prompt is longer than haiku prompt for the same tool/code", () => {
  const opus = getModelProfile("anthropic", "claude-opus-4-5");
  const haiku = getModelProfile("anthropic", "claude-haiku-4-5");
  const o = buildPrompt(opus, { tool: "scan_sqli", code: SAMPLE_CODE });
  const h = buildPrompt(haiku, { tool: "scan_sqli", code: SAMPLE_CODE });
  assert.ok(
    o.system.length > h.system.length,
    `expected opus system (${o.system.length}) longer than haiku system (${h.system.length})`,
  );
});

test("haiku prompt contains literal 'Return ONLY this JSON'", () => {
  const haiku = getModelProfile("anthropic", "claude-haiku-4-5");
  const built = buildPrompt(haiku, { tool: "scan_sqli", code: SAMPLE_CODE });
  assert.ok(built.system.includes("Return ONLY this JSON"));
});

test("sonnet prompt contains JSON schema lines", () => {
  const sonnet = getModelProfile("anthropic", "claude-sonnet-4-6");
  const built = buildPrompt(sonnet, { tool: "scan_sqli", code: SAMPLE_CODE });
  assert.ok(built.system.includes("JSON schema") || built.system.includes("findings"));
  assert.ok(built.system.includes("\"severity\"") || built.system.includes("severity"));
});

test("all prompts include the file path when provided", () => {
  const filePath = "/repo/src/auth.ts";
  for (const id of ["claude-opus-4-5", "claude-sonnet-4-6", "claude-haiku-4-5"]) {
    const profile = getModelProfile("anthropic", id);
    const built = buildPrompt(profile, { tool: "scan_auth_logic", code: SAMPLE_CODE, filePath });
    assert.ok(built.user.includes(filePath), `expected file path in ${id} user prompt`);
  }
});

test("all prompts include the (possibly truncated) code in the user message", () => {
  for (const id of ["claude-opus-4-5", "claude-sonnet-4-6", "claude-haiku-4-5"]) {
    const profile = getModelProfile("anthropic", id);
    const built = buildPrompt(profile, { tool: "scan_xss", code: SAMPLE_CODE });
    assert.ok(built.user.includes(SAMPLE_CODE), `expected code in ${id} user prompt`);
  }
});

test("low-jsonReliability models get the strict-JSON enforcer appended even on opus tier", () => {
  // mistral:7b-instruct is haiku, but llama3.2:3b is haiku too — both low.
  // To test "even on opus tier", construct a synthetic opus-tier profile with low reliability.
  const base = getModelProfile("ollama", "mistral:7b-instruct");
  const synthetic = { ...base, tier: "opus" as const };
  const built = buildPrompt(synthetic, { tool: "scan_idor", code: SAMPLE_CODE });
  assert.ok(
    built.system.includes("STRICT OUTPUT REQUIREMENT"),
    "expected strict-JSON enforcer block in low-reliability opus prompt",
  );
});

test("low-jsonReliability haiku model gets strict-JSON enforcer", () => {
  const profile = getModelProfile("ollama", "llama3.2:3b");
  assert.equal(profile.jsonReliability, "low");
  const built = buildPrompt(profile, { tool: "scan_sqli", code: SAMPLE_CODE });
  assert.ok(built.system.includes("STRICT OUTPUT REQUIREMENT"));
});
