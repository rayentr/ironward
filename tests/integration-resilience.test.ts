/**
 * Failure-mode coverage for the four outbound integrations:
 *   - Slack (webhook)
 *   - Linear (GraphQL)
 *   - Jira  (REST v3)
 *   - Email (Resend)
 *
 * Sister suites (slack.test.ts, issue-integrations.test.ts, email.test.ts)
 * already cover the happy paths. This file exercises the *unhappy* paths —
 * DNS failure, timeout-ish behavior, 4xx/5xx status codes, dedup races, and
 * payload edge cases — and locks in current graceful-degradation behavior so
 * regressions surface immediately.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { NormalizedFinding } from "../src/engines/sarif.ts";
import { sendSlackAlert, type SlackMessageInput } from "../src/integrations/slack.ts";
import {
  HttpLinearClient,
  reportFindingToLinear,
  type LinearClient,
} from "../src/integrations/linear.ts";
import {
  HttpJiraClient,
  reportFindingToJira,
  type JiraClient,
} from "../src/integrations/jira.ts";
import { sendDigestEmail, type DigestData } from "../src/integrations/email.ts";
import { buildIssue } from "../src/integrations/issue-template.ts";
import type {
  SlackConfig,
  LinearConfig,
  JiraConfig,
  EmailConfig,
} from "../src/integrations/config.ts";

// ──────────────────────────────────────────────────────────────────────────
// Mock fetch helpers
// ──────────────────────────────────────────────────────────────────────────

function rejectingFetch(error: Error): typeof fetch {
  return (async () => {
    throw error;
  }) as unknown as typeof fetch;
}

function statusFetch(status: number, body = ""): typeof fetch {
  return (async () =>
    ({
      ok: status < 400,
      status,
      text: async () => body,
      json: async () => {
        try {
          return JSON.parse(body);
        } catch {
          throw new Error("not JSON");
        }
      },
    } as Response)) as unknown as typeof fetch;
}

/**
 * Fetch that resolves only after `delayMs`. If the caller passes an AbortSignal
 * we honor it (rejecting with "aborted"); otherwise this simulates a hung
 * upstream that the caller cannot cancel.
 */
function slowFetch(delayMs: number): typeof fetch {
  return ((_url: string, init?: RequestInit) =>
    new Promise((resolve, reject) => {
      const signal = init?.signal;
      const t = setTimeout(
        () =>
          resolve({
            ok: true,
            status: 200,
            text: async () => "{}",
            json: async () => ({}),
          } as Response),
        delayMs,
      );
      if (signal) {
        signal.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new Error("aborted"));
        });
      }
    })) as unknown as typeof fetch;
}

// ──────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────

const sampleFinding: NormalizedFinding = {
  ruleId: "sql-string-concat",
  severity: "critical",
  title: "SQL Injection",
  description: "User input concatenated into SQL string",
  file: "src/api/login.ts",
  line: 42,
  tool: "scan_code",
};

const slackInput: SlackMessageInput = {
  repo: "acme/widgets",
  scannedBy: "ironward-cli",
  scannedAt: new Date("2026-04-23T12:00:00Z"),
  findings: [sampleFinding],
  reportUrl: "http://localhost:3737/runs/abc",
};

const slackCfg: SlackConfig = {
  webhookUrl: "https://hooks.slack.com/services/X/Y/Z",
  threshold: "high",
};

const linearCfg: LinearConfig = {
  apiKey: "lin_test",
  teamId: "team_1",
  threshold: "high",
};

const jiraCfg: JiraConfig = {
  baseUrl: "https://example.atlassian.net",
  email: "me@example.com",
  apiToken: "tok_x",
  projectKey: "SEC",
};

const emailCfg: EmailConfig = {
  provider: "resend",
  apiKey: "re_test_abcdef",
  from: "alerts@example.com",
  to: ["dev@example.com"],
};

const baseDigest: DigestData = {
  repo: "acme/widgets",
  scoreCurrent: 78,
  scorePrevious: 70,
  newFindings: 5,
  bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
  topUnresolved: [sampleFinding],
  filesWithMostIssues: [{ file: "src/api/login.ts", count: 1 }],
};

function mockLinearClient(over: Partial<LinearClient> = {}): LinearClient {
  return {
    findExistingByFingerprint: async () => null,
    createIssue: async () => ({
      id: "iss_1",
      identifier: "SEC-1",
      url: "https://linear.app/team/issue/SEC-1",
    }),
    listTeams: async () => [],
    ...over,
  };
}

function mockJiraClient(over: Partial<JiraClient> = {}): JiraClient {
  return {
    findExistingByFingerprint: async () => null,
    createIssue: async () => ({
      id: "10001",
      key: "SEC-1",
      self: "https://example.atlassian.net/rest/api/3/issue/10001",
    }),
    ...over,
  };
}

// ══════════════════════════════════════════════════════════════════════════
// GROUP 1 — Slack: network failure modes
// ══════════════════════════════════════════════════════════════════════════

test("slack: DNS / connection refused returns ok:false with error, never throws", async () => {
  // WHY: a mistyped webhook host or pinned-down corp DNS shouldn't crash a scan.
  const res = await sendSlackAlert(
    slackCfg,
    slackInput,
    rejectingFetch(new Error("ENOTFOUND hooks.slack.com")),
  );
  assert.equal(res.ok, false);
  assert.ok(res.error && res.error.includes("ENOTFOUND"), "error should surface DNS reason");
  assert.equal(res.sent, 1, "sent count still reflects what was attempted");
});

// WHY: regression test for the v2.7.0 fix — postSlackMessage now uses an AbortController
// with a 10s default timeout. A slow upstream that hangs past the timeout should return
// { ok: false, error: "timeout" } instead of stalling the scan forever.
test(
  "slack: slow upstream beyond timeout returns ok:false with error 'timeout'",
  { timeout: 5000 },
  async () => {
    const { postSlackMessage } = await import("../src/integrations/slack.ts");
    // slowFetch resolves at 2000ms; we set the post timeout to 200ms, so abort fires first.
    const res = await postSlackMessage("https://hooks.slack.com/x", { test: 1 }, slowFetch(2000), 200);
    assert.equal(res.ok, false);
    assert.equal(res.error, "timeout");
  },
);

test("slack: HTTP 429 Too Many Requests returns ok:false with status", async () => {
  // WHY: rate-limit responses must surface so callers can back off.
  const res = await sendSlackAlert(slackCfg, slackInput, statusFetch(429, "rate limited"));
  assert.equal(res.ok, false);
  assert.equal(res.status, 429);
  assert.equal(res.sent, 1);
});

test("slack: HTTP 500 server error returns ok:false with status", async () => {
  // WHY: Slack's edge can flap; a 500 is not a code bug — surface it cleanly.
  const res = await sendSlackAlert(slackCfg, slackInput, statusFetch(500, "internal"));
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
  assert.equal(res.sent, 1);
});

test("slack: HTTP 401 on rotated webhook returns ok:false with status", async () => {
  // WHY: the webhook silently rotated and we want to surface the rejection cleanly
  // so an operator can re-issue it instead of finding silence in their alert channel.
  const res = await sendSlackAlert(
    slackCfg,
    slackInput,
    statusFetch(401, "Invalid webhook URL"),
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, 401);
  assert.equal(res.sent, 1);
});

// ══════════════════════════════════════════════════════════════════════════
// GROUP 2 — Linear: network + auth + dedup
// ══════════════════════════════════════════════════════════════════════════

test("linear: HttpLinearClient.createIssue returns null on rejected fetch", async () => {
  // WHY: a transport-layer reject (DNS, conn reset) must NOT bubble out of the client.
  const client = new HttpLinearClient({
    apiKey: "lin_test",
    fetchImpl: rejectingFetch(new Error("ECONNREFUSED")),
  });
  const r = await client.createIssue({ teamId: "t1", title: "x", description: "y" });
  assert.equal(r, null);
});

test("linear: HttpLinearClient.createIssue returns null on 401", async () => {
  // WHY: bad / revoked token should not throw — caller decides how to alert.
  const client = new HttpLinearClient({
    apiKey: "lin_bad",
    fetchImpl: statusFetch(401, "Unauthorized"),
  });
  const r = await client.createIssue({ teamId: "t1", title: "x", description: "y" });
  assert.equal(r, null);
});

test("linear: HttpLinearClient.createIssue returns null on 500", async () => {
  // WHY: Linear is occasionally degraded; the caller's scan should keep going.
  const client = new HttpLinearClient({
    apiKey: "lin_test",
    fetchImpl: statusFetch(500, "internal"),
  });
  const r = await client.createIssue({ teamId: "t1", title: "x", description: "y" });
  assert.equal(r, null);
});

test("linear: reportFindingToLinear with missing apiKey -> not-configured", async () => {
  // WHY: an empty apiKey in config must short-circuit cleanly (re-asserted from happy-path suite).
  const cfg = { apiKey: "", teamId: "team_1" } as LinearConfig;
  const r = await reportFindingToLinear(cfg, sampleFinding, "myrepo", mockLinearClient());
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "not-configured");
});

test("linear: dedup — same fingerprint twice -> created then duplicate", async () => {
  // WHY: scans run on every commit. Without dedup the tracker would fill with
  // duplicates of the same vulnerability.
  let calls = 0;
  const client = mockLinearClient({
    findExistingByFingerprint: async () => {
      calls++;
      // First call: nothing exists yet. Second: pretend the issue we just created is now found.
      return calls === 1 ? null : { id: "iss_x", identifier: "SEC-7" };
    },
  });
  const first = await reportFindingToLinear(linearCfg, sampleFinding, "myrepo", client);
  const second = await reportFindingToLinear(linearCfg, sampleFinding, "myrepo", client);
  assert.equal(first.outcome, "created");
  assert.equal(second.outcome, "duplicate");
  assert.ok(second.url && second.url.includes("SEC-7"));
});

test("linear: dedup — same rule, different file -> both created (distinct fingerprints)", async () => {
  // WHY: the same SQLi rule firing in two different files = two real issues to fix.
  let createCalls = 0;
  const client = mockLinearClient({
    findExistingByFingerprint: async () => null, // never a match
    createIssue: async () => {
      createCalls++;
      return {
        id: `iss_${createCalls}`,
        identifier: `SEC-${createCalls}`,
        url: `https://linear.app/team/issue/SEC-${createCalls}`,
      };
    },
  });
  const a = await reportFindingToLinear(
    linearCfg,
    { ...sampleFinding, file: "src/api/login.ts" },
    "myrepo",
    client,
  );
  const b = await reportFindingToLinear(
    linearCfg,
    { ...sampleFinding, file: "src/api/signup.ts" },
    "myrepo",
    client,
  );
  assert.equal(a.outcome, "created");
  assert.equal(b.outcome, "created");
  assert.equal(createCalls, 2);
});

test("linear: createIssue returns null -> outcome 'error'", async () => {
  // WHY: if the GraphQL mutation succeeds at the HTTP layer but issueCreate.success
  // is false, the high-level reporter should expose this as a real error.
  const client = mockLinearClient({ createIssue: async () => null });
  const r = await reportFindingToLinear(linearCfg, sampleFinding, "myrepo", client);
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "error");
  assert.match(r.error ?? "", /no issue/);
});

test("linear: GraphQL error response from HttpLinearClient -> createIssue returns null", async () => {
  // WHY: Linear can return HTTP 200 with a top-level errors array (e.g. auth
  // rejected at the GraphQL layer). The client treats `errors[]` as failure.
  const errBody = JSON.stringify({ errors: [{ message: "Unauthorized" }] });
  const client = new HttpLinearClient({
    apiKey: "lin_test",
    fetchImpl: statusFetch(200, errBody),
  });
  const r = await client.createIssue({ teamId: "t1", title: "x", description: "y" });
  assert.equal(r, null);
});

// ══════════════════════════════════════════════════════════════════════════
// GROUP 3 — Jira: network + auth + dedup
// ══════════════════════════════════════════════════════════════════════════

test("jira: HttpJiraClient.createIssue returns null on rejected fetch", async () => {
  // WHY: same graceful contract as Linear — transport errors stay inside the client.
  const client = new HttpJiraClient({
    baseUrl: "https://example.atlassian.net",
    email: "me@example.com",
    apiToken: "tok_x",
    fetchImpl: rejectingFetch(new Error("ETIMEDOUT")),
  });
  const r = await client.createIssue({
    projectKey: "SEC",
    summary: "x",
    description: "y",
    issueType: "Bug",
  });
  assert.equal(r, null);
});

test("jira: HttpJiraClient.createIssue returns null on 403 Forbidden", async () => {
  // WHY: 401 is covered in the happy-path suite. 403 is the "auth ok but token
  // lacks `write:issues` scope" case — common when the token is project-scoped.
  const client = new HttpJiraClient({
    baseUrl: "https://example.atlassian.net",
    email: "me@example.com",
    apiToken: "tok_x",
    fetchImpl: statusFetch(403, "Forbidden"),
  });
  const r = await client.createIssue({
    projectKey: "SEC",
    summary: "x",
    description: "y",
    issueType: "Bug",
  });
  assert.equal(r, null);
});

test("jira: HttpJiraClient.findExistingByFingerprint returns null on 403", async () => {
  // WHY: dedup search must fail closed (return null = no dup found) rather than
  // throw — otherwise we'd block creation on a search that never works.
  const client = new HttpJiraClient({
    baseUrl: "https://example.atlassian.net",
    email: "me@example.com",
    apiToken: "tok_x",
    fetchImpl: statusFetch(403, "Forbidden"),
  });
  const r = await client.findExistingByFingerprint("SEC", "fp_abc");
  assert.equal(r, null);
});

test("jira: dedup with mock client — same fingerprint -> 'duplicate'", async () => {
  // WHY: end-to-end dedup contract — when search hits, we don't POST a new issue.
  let createCalls = 0;
  const client = mockJiraClient({
    findExistingByFingerprint: async () => ({ key: "SEC-9", id: "9000" }),
    createIssue: async () => {
      createCalls++;
      return { id: "x", key: "SEC-X", self: "x" };
    },
  });
  const r = await reportFindingToJira(jiraCfg, sampleFinding, "myrepo", client);
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "duplicate");
  assert.equal(createCalls, 0, "createIssue must not be called when duplicate exists");
  assert.ok(r.url && r.url.endsWith("/browse/SEC-9"));
});

test("jira: createIssue rejects -> outcome 'error', error surfaced", async () => {
  // WHY: a thrown error inside a custom JiraClient impl must still produce a
  // structured outcome, not a leaked exception.
  const client = mockJiraClient({
    createIssue: async () => {
      throw new Error("network down");
    },
  });
  const r = await reportFindingToJira(jiraCfg, sampleFinding, "myrepo", client);
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "error");
  assert.match(r.error ?? "", /network down/);
});

// ══════════════════════════════════════════════════════════════════════════
// GROUP 4 — Email (Resend): network + status
// ══════════════════════════════════════════════════════════════════════════

test("email: rejected fetch returns ok:false with error, never throws", async () => {
  // WHY: a weekly digest job must not crash the scheduler if Resend is down.
  const res = await sendDigestEmail(
    emailCfg,
    baseDigest,
    rejectingFetch(new Error("ENOTFOUND api.resend.com")),
  );
  assert.equal(res.ok, false);
  assert.ok(res.error && res.error.includes("ENOTFOUND"));
});

test("email: 401 (bad API key) returns ok:false with status", async () => {
  // WHY: a rotated/revoked Resend key should surface as a clear status, not silence.
  const res = await sendDigestEmail(emailCfg, baseDigest, statusFetch(401, "Unauthorized"));
  assert.equal(res.ok, false);
  assert.equal(res.status, 401);
});

test("email: 422 validation error returns ok:false with status", async () => {
  // WHY: Resend returns 422 for things like a misconfigured `from` domain.
  // Operators need the status to know it's a config issue, not a transient error.
  const res = await sendDigestEmail(
    emailCfg,
    baseDigest,
    statusFetch(422, '{"name":"validation_error"}'),
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, 422);
});

test("email: 500 server error returns ok:false with status", async () => {
  // WHY: upstream provider blip — caller should retry on a schedule, not crash.
  const res = await sendDigestEmail(emailCfg, baseDigest, statusFetch(500, "internal"));
  assert.equal(res.ok, false);
  assert.equal(res.status, 500);
});

// ══════════════════════════════════════════════════════════════════════════
// GROUP 5 — Payload edge cases (issue-template)
// ══════════════════════════════════════════════════════════════════════════

test("buildIssue: finding with no exploit data still has all sections", () => {
  // WHY: scanners that don't enrich findings (e.g. dep-intel without LLM) must
  // still produce a valid, complete issue body — not crash on missing fields.
  const t = buildIssue({ ...sampleFinding, exploit: undefined });
  assert.match(t.bodyMarkdown, /## Vulnerability/);
  assert.match(t.bodyMarkdown, /## Severity/);
  assert.match(t.bodyMarkdown, /## References/);
  // Remediation + PoC fall back to default strings rather than empty code blocks.
  assert.match(t.bodyMarkdown, /no proof-of-concept available/);
  assert.match(t.bodyMarkdown, /see rule remediation guidance/);
  // Rule id is always referenced even without exploit metadata.
  assert.match(t.bodyMarkdown, /sql-string-concat/);
});

// WHY: regression test for the v2.7.0 fix — buildIssue now caps body length at 45k chars
// (safely under Linear's ~50k and Jira's ~32k limits) and appends a truncation notice.
test("buildIssue: 60,000 char description is truncated to <= 45,000 with a notice", () => {
  const huge = "X".repeat(60_000);
  const t = buildIssue({ ...sampleFinding, description: huge });
  assert.ok(t.bodyMarkdown.length <= 45_000,
    `expected body <= 45000 chars, got ${t.bodyMarkdown.length}`);
  assert.ok(t.bodyMarkdown.includes("[...truncated for API limits"),
    `expected truncation notice in body`);
});

test("buildIssue: small descriptions are NOT truncated (no notice)", () => {
  // WHY: lock in that the truncation only fires on outsized inputs.
  const t = buildIssue({ ...sampleFinding, description: "Short and sweet." });
  assert.ok(!t.bodyMarkdown.includes("[...truncated for API limits"),
    `truncation notice should NOT appear for small bodies`);
});

test("buildIssue: special characters in file path (spaces, unicode, emoji)", () => {
  // WHY: real repos have spaces, non-ASCII, and emojis in paths (esp. monorepos
  // that vendor third-party assets). buildIssue must not crash or emit `undefined`.
  const weirdPath = "src/some folder/файл🚨.ts";
  const t = buildIssue({ ...sampleFinding, file: weirdPath });
  assert.ok(t.title.includes(weirdPath), "title should include the weird path");
  assert.ok(t.bodyMarkdown.includes(weirdPath), "body should include the weird path");
  assert.ok(!t.title.includes("undefined"), "title must not contain literal 'undefined'");
  assert.ok(!t.bodyMarkdown.includes("undefined"), "body must not contain literal 'undefined'");
});

test("buildIssue: ruleId with special characters does not break Markdown", () => {
  // WHY: rule ids include version suffixes (v2.0) and dashes; Markdown escaping
  // of backticks is the only structural risk and we confirm a clean inline-code wrap.
  const ruleId = "sql-string-concat-v2.0";
  const t = buildIssue({ ...sampleFinding, ruleId });
  assert.ok(t.bodyMarkdown.includes(ruleId), "body should include the special rule id");
  assert.match(t.bodyMarkdown, /Ironward rule: `sql-string-concat-v2\.0`/);
});

test("buildIssue: every severity maps to the expected Linear + Jira priority", () => {
  // WHY: severity → priority is the contract trackers rely on for routing.
  // Drift here silently misroutes every alert.
  const cases: Array<[NormalizedFinding["severity"], string, string]> = [
    ["critical", "Urgent", "Highest"],
    ["high", "High", "High"],
    ["medium", "Medium", "Medium"],
    ["low", "Low", "Low"],
    ["info", "Low", "Low"],
  ];
  for (const [sev, linearLabel, jiraName] of cases) {
    const t = buildIssue({ ...sampleFinding, severity: sev });
    assert.equal(t.priorityLabel, linearLabel, `linear label for ${sev}`);
    assert.equal(t.jiraPriorityName, jiraName, `jira name for ${sev}`);
  }
});
