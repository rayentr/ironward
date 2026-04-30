import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFile, rm } from "node:fs/promises";
import {
  loadConfig,
  saveConfig,
  updateConfigSection,
  redactConfig,
  findingFingerprint,
} from "../src/integrations/config.ts";

function tmpPath(): string {
  return join(tmpdir(), `ironward-cfg-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
}

test("config: loadConfig returns {} when file missing", async () => {
  const cfg = await loadConfig(tmpPath());
  assert.deepEqual(cfg, {});
});

test("config: saveConfig writes JSON and loadConfig reads it back", async () => {
  const p = tmpPath();
  try {
    await saveConfig({ slack: { webhookUrl: "https://hooks.slack.com/x" } }, p);
    const cfg = await loadConfig(p);
    assert.equal(cfg.slack?.webhookUrl, "https://hooks.slack.com/x");
  } finally {
    await rm(p, { force: true });
  }
});

test("config: updateConfigSection deep-merges into the named section", async () => {
  const p = tmpPath();
  try {
    await saveConfig({ slack: { webhookUrl: "https://hooks.slack.com/x" } }, p);
    await updateConfigSection("slack", { channel: "#sec", threshold: "critical" }, p);
    const cfg = await loadConfig(p);
    assert.equal(cfg.slack?.webhookUrl, "https://hooks.slack.com/x");
    assert.equal(cfg.slack?.channel, "#sec");
    assert.equal(cfg.slack?.threshold, "critical");
  } finally {
    await rm(p, { force: true });
  }
});

test("config: saved file is JSON-parseable and contains the value", async () => {
  const p = tmpPath();
  try {
    await saveConfig({ linear: { apiKey: "lin_api_secret_123" } }, p);
    const raw = await readFile(p, "utf8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.linear.apiKey, "lin_api_secret_123");
  } finally {
    await rm(p, { force: true });
  }
});

test("redactConfig: hides secrets in slack/linear/jira/email sections", () => {
  const r = redactConfig({
    slack: { webhookUrl: "https://hooks.slack.com/services/AAA/BBB/CCCDDDEEEFFF" },
    linear: { apiKey: "lin_api_supersecretkey1234567" },
    jira: { baseUrl: "https://co.atlassian.net", email: "u@co", apiToken: "tokenABCDEF12345", projectKey: "SEC" },
    email: { provider: "resend", apiKey: "re_supersecret_key", from: "x@y", to: ["z@y"] },
  });
  assert.ok(!r.slack?.webhookUrl?.includes("CCCDDDEEEFFF"));
  assert.ok(r.slack?.webhookUrl?.includes("***"));
  assert.ok(!r.linear?.apiKey?.includes("supersecret"));
  assert.ok(!r.jira?.apiToken?.includes("ABCDEF12345"));
  assert.ok(!r.email?.apiKey?.includes("supersecret"));
});

test("findingFingerprint: stable for same inputs, different for different inputs", () => {
  const a = findingFingerprint("repo", "src/x.ts", 42, "rule-id");
  const b = findingFingerprint("repo", "src/x.ts", 42, "rule-id");
  const c = findingFingerprint("repo", "src/x.ts", 43, "rule-id");
  assert.equal(a, b);
  assert.notEqual(a, c);
});
