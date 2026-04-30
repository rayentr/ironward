import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildDigestSubject,
  buildDigestHtml,
  sendDigestEmail,
  type DigestData,
} from "../src/integrations/email.ts";
import type { NormalizedFinding } from "../src/engines/sarif.ts";
import type { EmailConfig } from "../src/integrations/config.ts";

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

const baseDigest: DigestData = {
  repo: "acme/widgets",
  scoreCurrent: 78,
  scorePrevious: 70,
  newFindings: 5,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  topUnresolved: [
    f("critical", "sqli-1", "src/api/auth.ts", 42, "SQL Injection"),
    f("high", "xss-1", "src/api/render.ts", 10, "Reflected XSS"),
  ],
  filesWithMostIssues: [
    { file: "src/api/auth.ts", count: 4 },
    { file: "src/api/render.ts", count: 2 },
  ],
};

// ───────────────────────────────────────────────
// buildDigestSubject
// ───────────────────────────────────────────────
test("buildDigestSubject — 3 critical", () => {
  const subj = buildDigestSubject({
    ...baseDigest,
    bySeverity: { critical: 3, high: 1, medium: 0, low: 0, info: 0 },
  });
  assert.equal(subj, "Ironward Weekly: 3 critical issues");
});

test("buildDigestSubject — 0 critical, 5 high", () => {
  const subj = buildDigestSubject({
    ...baseDigest,
    bySeverity: { critical: 0, high: 5, medium: 0, low: 0, info: 0 },
  });
  assert.equal(subj, "Ironward Weekly: 5 high-severity issues");
});

test("buildDigestSubject — 0 issues", () => {
  const subj = buildDigestSubject({
    ...baseDigest,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });
  assert.equal(subj, "Ironward Weekly: All clear");
});

// ───────────────────────────────────────────────
// buildDigestHtml
// ───────────────────────────────────────────────
test("buildDigestHtml includes the score, deltas, and top findings", () => {
  const html = buildDigestHtml({
    ...baseDigest,
    scoreCurrent: 82,
    scorePrevious: 70,
    bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
  });
  assert.match(html, /<svg|<html|<table/);
  assert.ok(html.includes("82"), "expected current score in HTML");
  assert.ok(html.includes("+12"), "expected positive delta in HTML");
  assert.ok(html.includes("SQL Injection"), "expected top finding title in HTML");
  assert.ok(html.includes("src/api/auth.ts"), "expected top finding file in HTML");
  assert.ok(html.includes("acme/widgets"), "expected repo in HTML");
  // Default dashboard URL
  assert.ok(html.includes("http://localhost:3737"), "expected default dashboard URL");
});

test("buildDigestHtml includes negative delta with - sign when score drops", () => {
  const html = buildDigestHtml({
    ...baseDigest,
    scoreCurrent: 60,
    scorePrevious: 80,
  });
  assert.ok(html.includes("-20"), "expected -20 delta in HTML");
});

// ───────────────────────────────────────────────
// sendDigestEmail (mocked fetch)
// ───────────────────────────────────────────────
function mockFetch(response: { ok: boolean; status: number; jsonBody?: unknown } = { ok: true, status: 200 }) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl: any = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: response.ok,
      status: response.status,
      json: async () => response.jsonBody ?? {},
    };
  };
  return { impl: impl as typeof fetch, calls };
}

const cfg: EmailConfig = {
  provider: "resend",
  apiKey: "re_test_abcdef",
  from: "alerts@example.com",
  to: ["dev@example.com", "sec@example.com"],
};

test("sendDigestEmail posts to Resend with correct headers and body shape", async () => {
  const m = mockFetch({ ok: true, status: 200, jsonBody: { id: "msg_123" } });
  const res = await sendDigestEmail(
    cfg,
    {
      ...baseDigest,
      bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    },
    m.impl,
  );
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(res.id, "msg_123");

  assert.equal(m.calls.length, 1);
  const call = m.calls[0];
  assert.equal(call.url, "https://api.resend.com/emails");
  assert.equal((call.init as any).method, "POST");

  const headers = (call.init as any).headers as Record<string, string>;
  assert.equal(headers["authorization"], "Bearer re_test_abcdef");
  assert.equal(headers["content-type"], "application/json");

  const body = JSON.parse((call.init as any).body as string);
  assert.equal(body.from, "alerts@example.com");
  assert.deepEqual(body.to, ["dev@example.com", "sec@example.com"]);
  assert.ok(typeof body.subject === "string" && body.subject.startsWith("Ironward Weekly"));
  assert.ok(typeof body.html === "string" && body.html.length > 0);
});

test("sendDigestEmail returns { ok: false, error } when fetchImpl rejects", async () => {
  const failing: any = async () => {
    throw new Error("ENOTFOUND api.resend.com");
  };
  const res = await sendDigestEmail(cfg, baseDigest, failing);
  assert.equal(res.ok, false);
  assert.ok(res.error && res.error.includes("ENOTFOUND"));
});

test("sendDigestEmail returns { ok: false, status: 401 } when API returns 401", async () => {
  const m = mockFetch({ ok: false, status: 401 });
  const res = await sendDigestEmail(cfg, baseDigest, m.impl);
  assert.equal(res.ok, false);
  assert.equal(res.status, 401);
});
