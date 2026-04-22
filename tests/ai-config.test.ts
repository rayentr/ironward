import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const scratch = mkdtempSync(join(tmpdir(), "ironward-test-"));
process.env.HOME = scratch;
process.env.USERPROFILE = scratch;

const { readConfig, writeConfig, deleteConfig, configPath, PROVIDERS, getProvider } = await import("../src/engines/ai-config.ts");
const { createClient, MissingApiKeyError } = await import("../src/engines/claude-client.ts");

test("PROVIDERS covers the five supported providers", () => {
  const ids = PROVIDERS.map((p) => p.id).sort();
  assert.deepEqual(ids, ["anthropic", "gemini", "groq", "ollama", "openai"]);
});

test("getProvider returns meta with defaults", () => {
  const ant = getProvider("anthropic");
  assert.ok(ant.requiresKey);
  assert.ok(ant.defaultModel.length > 0);
  const oll = getProvider("ollama");
  assert.equal(oll.requiresKey, false);
});

test("configPath lives under HOME/.ironward", () => {
  assert.ok(configPath().startsWith(scratch), `expected ${configPath()} to start with ${scratch}`);
  assert.ok(configPath().endsWith("config.json"));
});

test("readConfig returns null when no file exists", async () => {
  await deleteConfig();
  const cfg = await readConfig();
  assert.equal(cfg, null);
});

test("writeConfig + readConfig round-trip", async () => {
  await writeConfig({ provider: "anthropic", apiKey: "sk-ant-test", model: "claude-opus-4-5" });
  const cfg = await readConfig();
  assert.ok(cfg);
  assert.equal(cfg!.provider, "anthropic");
  assert.equal(cfg!.model, "claude-opus-4-5");
  assert.equal(cfg!.apiKey, "sk-ant-test");
  await deleteConfig();
});

test("readConfig rejects unknown provider", async () => {
  const fs = await import("node:fs/promises");
  await fs.mkdir(join(scratch, ".ironward"), { recursive: true });
  await fs.writeFile(configPath(), JSON.stringify({ provider: "bogus", model: "x" }));
  const cfg = await readConfig();
  assert.equal(cfg, null);
  await deleteConfig();
});

test("createClient throws MissingApiKeyError when non-ollama key is absent", () => {
  assert.throws(
    () => createClient({ provider: "anthropic", model: "claude-opus-4-5" } as any),
    MissingApiKeyError,
  );
  assert.throws(
    () => createClient({ provider: "openai", model: "gpt-4o" } as any),
    MissingApiKeyError,
  );
});

test("createClient dispatches to correct provider", () => {
  const ant = createClient({ provider: "anthropic", apiKey: "k", model: "claude-opus-4-5" });
  assert.equal(ant.provider, "anthropic");
  const oai = createClient({ provider: "openai", apiKey: "k", model: "gpt-4o" });
  assert.equal(oai.provider, "openai");
  const grok = createClient({ provider: "groq", apiKey: "k", model: "llama-3" });
  assert.equal(grok.provider, "groq");
  const gem = createClient({ provider: "gemini", apiKey: "k", model: "gemini-1.5-pro" });
  assert.equal(gem.provider, "gemini");
  const oll = createClient({ provider: "ollama", model: "llama3" });
  assert.equal(oll.provider, "ollama");
});

test("ollama createClient does not require a key", () => {
  assert.doesNotThrow(() => createClient({ provider: "ollama", model: "llama3" }));
});

process.on("exit", () => {
  try { rmSync(scratch, { recursive: true, force: true }); } catch {}
});
