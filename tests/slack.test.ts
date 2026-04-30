import { test } from "node:test";
import assert from "node:assert/strict";
import {
  filterByThreshold,
  buildSlackMessage,
  buildSlackDigest,
  sendSlackAlert,
  type SlackMessageInput,
} from "../src/integrations/slack.ts";
import type { NormalizedFinding } from "../src/engines/sarif.ts";
import type { SlackConfig } from "../src/integrations/config.ts";

function f(
  severity: NormalizedFinding["severity"],
  ruleId: string,
  file = "src/api/auth.ts",
  line = 42,
  title = "SQL Injection",
): NormalizedFinding {
  return {
    ruleId,
    severity,
    title,
    description: `${title} found in ${file}`,
    file,
    line,
    tool: "scan_code",
  };
}

const sample: NormalizedFinding[] = [
  f("critical", "sqli-1", "src/api/auth.ts", 42, "SQL Injection"),
  f("high", "xss-1", "src/api/render.ts", 10, "XSS"),
  f("medium", "weak-crypto", "src/lib/crypto.ts", 5, "Weak Crypto"),
  f("low", "log-leak", "src/log.ts", 3, "Log Leak"),
  f("info", "todo", "src/todo.ts", 1, "TODO Marker"),
];

const baseInput: SlackMessageInput = {
  repo: "acme/widgets",
  scannedBy: "ironward-cli",
  scannedAt: new Date("2026-04-23T12:00:00Z"),
  findings: sample,
  reportUrl: "http://localhost:3737/runs/abc",
};

// ──────────────────────────────────────────────────────────────
// filterByThreshold
// ──────────────────────────────────────────────────────────────
test("filterByThreshold('high') keeps critical+high only", () => {
  const out = filterByThreshold(sample, "high");
  assert.equal(out.length, 2);
  assert.ok(out.every((x) => x.severity === "critical" || x.severity === "high"));
});

test("filterByThreshold('all') keeps everything", () => {
  const out = filterByThreshold(sample, "all");
  assert.equal(out.length, sample.length);
});

test("filterByThreshold(undefined) defaults to 'high'", () => {
  const out = filterByThreshold(sample, undefined);
  assert.equal(out.length, 2);
});

test("filterByThreshold('critical') keeps only critical", () => {
  const out = filterByThreshold(sample, "critical");
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, "critical");
});

// ──────────────────────────────────────────────────────────────
// buildSlackMessage
// ──────────────────────────────────────────────────────────────
test("buildSlackMessage returns an object with a blocks array", () => {
  const msg = buildSlackMessage(baseInput, "high") as { blocks: unknown[] };
  assert.ok(Array.isArray(msg.blocks));
  assert.ok(msg.blocks.length > 0);
});

test("buildSlackMessage includes the repo name in a section", () => {
  const msg = buildSlackMessage(baseInput, "high") as { blocks: unknown[] };
  const json = JSON.stringify(msg);
  assert.ok(json.includes("acme/widgets"), "expected repo name in payload");
  // Header is the alert title
  const header = msg.blocks.find(
    (b: any) => b.type === "header",
  ) as { text: { text: string } } | undefined;
  assert.ok(header && header.text.text.includes("Ironward Security Alert"));
});

test("buildSlackMessage truncates to top 5 findings", () => {
  const many: NormalizedFinding[] = Array.from({ length: 12 }, (_, i) =>
    f("critical", `r-${i}`, `src/file${i}.ts`, i + 1, `Issue ${i}`),
  );
  const msg = buildSlackMessage(
    { ...baseInput, findings: many },
    "high",
  ) as { blocks: any[] };
  // Count section blocks that look like finding rows (text contains a backtick path)
  const findingSections = msg.blocks.filter(
    (b) =>
      b.type === "section" &&
      b.text?.type === "mrkdwn" &&
      typeof b.text.text === "string" &&
      /`src\/file\d+\.ts:\d+`/.test(b.text.text),
  );
  assert.equal(findingSections.length, 5);
});

test("buildSlackMessage produces an 'all clear' message when 0 findings >= threshold", () => {
  const onlyLow: NormalizedFinding[] = [f("low", "x"), f("info", "y")];
  const msg = buildSlackMessage(
    { ...baseInput, findings: onlyLow },
    "high",
  ) as { blocks: any[] };
  const text = JSON.stringify(msg);
  assert.ok(text.includes("All clear"));
  assert.ok(text.includes("acme/widgets"));
});

// ──────────────────────────────────────────────────────────────
// buildSlackDigest
// ──────────────────────────────────────────────────────────────
test("buildSlackDigest includes the score delta with a + sign when up", () => {
  const msg = buildSlackDigest({
    repo: "acme/widgets",
    newFindings: 3,
    byCriticalUnresolved: 1,
    fixedThisWeek: 4,
    scoreCurrent: 87,
    scorePrevious: 80,
  }) as { blocks: unknown[] };
  const text = JSON.stringify(msg);
  assert.ok(text.includes("+7"), "expected +7 delta");
  assert.ok(text.includes("87/100"));
  assert.ok(text.includes("acme/widgets"));
});

test("buildSlackDigest includes the score delta with a - sign when down", () => {
  const msg = buildSlackDigest({
    repo: "acme/widgets",
    newFindings: 3,
    byCriticalUnresolved: 1,
    fixedThisWeek: 4,
    scoreCurrent: 70,
    scorePrevious: 85,
  }) as { blocks: unknown[] };
  const text = JSON.stringify(msg);
  assert.ok(text.includes("-15"), "expected -15 delta");
});

// ──────────────────────────────────────────────────────────────
// sendSlackAlert (with mocked fetchImpl)
// ──────────────────────────────────────────────────────────────
function mockFetch(
  response: { ok: boolean; status: number } = { ok: true, status: 200 },
) {
  let calls = 0;
  const impl: any = async () => {
    calls++;
    return { ok: response.ok, status: response.status };
  };
  return { impl: impl as typeof fetch, get calls() { return calls; } };
}

test("sendSlackAlert does NOT call the network when no findings >= threshold", async () => {
  const cfg: SlackConfig = { webhookUrl: "https://hooks.slack.com/services/X/Y/Z", threshold: "high" };
  const onlyLow: NormalizedFinding[] = [f("low", "x"), f("info", "y")];
  const m = mockFetch();
  const res = await sendSlackAlert(cfg, { ...baseInput, findings: onlyLow }, m.impl);
  assert.deepEqual(res, { ok: true, sent: 0 });
  assert.equal(m.calls, 0);
});

test("sendSlackAlert calls the network exactly once when there are findings", async () => {
  const cfg: SlackConfig = { webhookUrl: "https://hooks.slack.com/services/X/Y/Z", threshold: "high" };
  const m = mockFetch({ ok: true, status: 200 });
  const res = await sendSlackAlert(cfg, baseInput, m.impl);
  assert.equal(m.calls, 1);
  assert.equal(res.ok, true);
  assert.equal(res.sent, 2); // critical + high
});

test("sendSlackAlert returns { ok: false, error } when fetchImpl rejects (graceful)", async () => {
  const cfg: SlackConfig = { webhookUrl: "https://hooks.slack.com/services/X/Y/Z", threshold: "high" };
  const failing: any = async () => {
    throw new Error("ENOTFOUND");
  };
  const res = await sendSlackAlert(cfg, baseInput, failing);
  assert.equal(res.ok, false);
  assert.ok(res.error && res.error.includes("ENOTFOUND"));
  assert.equal(res.sent, 2);
});

test("sendSlackAlert returns { ok: false, status: 500 } when webhook returns 500", async () => {
  const cfg: SlackConfig = { webhookUrl: "https://hooks.slack.com/services/X/Y/Z", threshold: "high" };
  const m = mockFetch({ ok: false, status: 500 });
  const res = await sendSlackAlert(cfg, baseInput, m.impl);
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
  assert.equal(res.sent, 2);
  assert.equal(m.calls, 1);
});
