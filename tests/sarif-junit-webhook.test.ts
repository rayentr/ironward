import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSarif, sarifLevelForSeverity, type NormalizedFinding } from "../src/engines/sarif.ts";
import { buildJunit } from "../src/engines/junit.ts";
import { buildWebhookPayload, postWebhook, type Poster } from "../src/engines/webhook.ts";

const sample: NormalizedFinding[] = [
  {
    ruleId: "aws_access_key",
    severity: "critical",
    title: "AWS access key ID",
    description: "AWS access key ID",
    file: "src/config.ts",
    line: 14,
    column: 1,
    tool: "scan_for_secrets",
  },
  {
    ruleId: "eval-call",
    severity: "high",
    title: "eval() call",
    description: "eval executes arbitrary code",
    file: "src/api.ts",
    line: 42,
    tool: "scan_code",
  },
];

// ──────────────────────────────────────────────────────────────
// SARIF
// ──────────────────────────────────────────────────────────────
test("sarifLevelForSeverity maps correctly", () => {
  assert.equal(sarifLevelForSeverity("critical"), "error");
  assert.equal(sarifLevelForSeverity("high"), "error");
  assert.equal(sarifLevelForSeverity("medium"), "warning");
  assert.equal(sarifLevelForSeverity("low"), "note");
  assert.equal(sarifLevelForSeverity("info"), "note");
});

test("buildSarif emits a schema-valid 2.1.0 document", () => {
  const sarif = buildSarif(sample, "1.6.0");
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.$schema.includes("sarif"));
  assert.equal(sarif.runs.length, 1);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "Ironward");
  assert.equal(run.tool.driver.version, "1.6.0");
  assert.equal(run.results.length, 2);
  assert.equal(run.results[0].ruleId, "aws_access_key");
  assert.equal(run.results[0].level, "error");
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, "src/config.ts");
  assert.equal(run.results[0].locations[0].physicalLocation.region!.startLine, 14);
});

test("buildSarif dedupes rules in the driver while keeping all results", () => {
  const many: NormalizedFinding[] = [
    { ...sample[0] },
    { ...sample[0], file: "src/other.ts", line: 5 },
    { ...sample[1] },
  ];
  const sarif = buildSarif(many, "1.6.0");
  assert.equal(sarif.runs[0].results.length, 3);
  // rules array contains each unique (tool, ruleId) once.
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id).sort();
  assert.deepEqual(ruleIds, ["aws_access_key", "eval-call"]);
});

test("buildSarif on empty findings emits an empty results array with the driver", () => {
  const sarif = buildSarif([], "1.6.0");
  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});

// ──────────────────────────────────────────────────────────────
// JUnit XML
// ──────────────────────────────────────────────────────────────
test("buildJunit emits well-formed XML with a testsuite per tool", () => {
  const xml = buildJunit(sample);
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<testsuites[^>]*tests="2"[^>]*failures="2"/);
  assert.match(xml, /<testsuite name="scan_for_secrets"/);
  assert.match(xml, /<testsuite name="scan_code"/);
  assert.match(xml, /<failure[^>]*type="critical"/);
});

test("buildJunit escapes XML special chars in descriptions", () => {
  const tricky: NormalizedFinding[] = [{
    ...sample[0],
    description: `<script>alert("x & y")</script>`,
    title: `<html>`,
  }];
  const xml = buildJunit(tricky);
  assert.match(xml, /&lt;script&gt;/);
  assert.match(xml, /&amp;/);
  assert.match(xml, /&quot;/);
  // Original < > characters must not appear inside element attribute/text bodies.
  assert.doesNotMatch(xml, /<script>alert/);
});

test("buildJunit emits a passing 'no findings' testcase when clean", () => {
  const xml = buildJunit([]);
  assert.match(xml, /<testsuites[^>]*tests="1"[^>]*failures="0"/);
  assert.match(xml, /name="no findings"/);
  assert.doesNotMatch(xml, /<failure/);
});

// ──────────────────────────────────────────────────────────────
// Webhook
// ──────────────────────────────────────────────────────────────
test("buildWebhookPayload computes counts correctly", () => {
  const p = buildWebhookPayload(sample, { version: "1.6.0", target: "./src" });
  assert.equal(p.source, "ironward");
  assert.equal(p.version, "1.6.0");
  assert.equal(p.summary.total, 2);
  assert.equal(p.summary.critical, 1);
  assert.equal(p.summary.high, 1);
});

test("postWebhook to a generic URL posts plain JSON", async () => {
  const calls: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
  const spy: Poster = async (url, body, headers) => {
    calls.push({ url, body, headers });
    return { ok: true, status: 200 };
  };
  const payload = buildWebhookPayload(sample, { version: "1.6.0", target: "src" });
  const r = await postWebhook("https://example.test/hook", payload, spy);
  assert.equal(r.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://example.test/hook");
  assert.equal(calls[0].headers["Content-Type"], "application/json");
  const parsed = JSON.parse(calls[0].body);
  assert.equal(parsed.source, "ironward");
  assert.equal(parsed.summary.total, 2);
});

test("postWebhook to hooks.slack.com emits Slack Block Kit payload", async () => {
  const calls: Array<{ body: string }> = [];
  const spy: Poster = async (_url, body) => {
    calls.push({ body });
    return { ok: true, status: 200 };
  };
  const payload = buildWebhookPayload(sample, { version: "1.6.0", target: "src" });
  await postWebhook("https://hooks.slack.com/services/T0/B0/abc", payload, spy);
  const parsed = JSON.parse(calls[0].body);
  assert.ok(parsed.text);
  assert.ok(Array.isArray(parsed.blocks));
  assert.ok(parsed.blocks.length > 0);
});

test("postWebhook reports non-2xx as failure", async () => {
  const spy: Poster = async () => ({
    ok: false,
    status: 500,
    text: async () => "boom",
  });
  const payload = buildWebhookPayload(sample, { version: "1.6.0", target: "src" });
  const r = await postWebhook("https://example.test/hook", payload, spy);
  assert.equal(r.ok, false);
  assert.equal(r.status, 500);
  assert.ok(r.error && r.error.includes("500"));
});

test("postWebhook catches network errors", async () => {
  const spy: Poster = async () => { throw new Error("ECONNREFUSED"); };
  const payload = buildWebhookPayload(sample, { version: "1.6.0", target: "src" });
  const r = await postWebhook("https://example.test/hook", payload, spy);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /ECONNREFUSED/);
});
