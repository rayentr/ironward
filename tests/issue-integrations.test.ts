import { test } from "node:test";
import assert from "node:assert/strict";
import type { NormalizedFinding } from "../src/engines/sarif.ts";
import { buildIssue, linearPriorityNumber } from "../src/integrations/issue-template.ts";
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
import type { LinearConfig, JiraConfig } from "../src/integrations/config.ts";

// ──────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────
function makeFinding(
  overrides: Partial<NormalizedFinding> = {},
): NormalizedFinding {
  return {
    ruleId: "sql-injection",
    severity: "critical",
    title: "SQL injection via string concatenation",
    description: "User input is concatenated into a SQL query.",
    file: "src/api/users.ts",
    line: 42,
    tool: "scan_code",
    exploit: {
      title: "SQL injection",
      poc: "curl -X POST /api/users -d \"id=1' OR '1'='1\"",
      impact: "Full database read",
      cvss: 9.1,
      cvssVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      owasp: "A03:2021 — Injection",
      cwe: "CWE-89",
      remediation: "Use parameterised queries.",
      references: ["https://owasp.org/sqli"],
    },
    ...overrides,
  };
}

// ──────────────────────────────────────────────────────────────
// Issue template
// ──────────────────────────────────────────────────────────────
test("buildIssue title starts with [SECURITY] and includes file path", () => {
  const t = buildIssue(makeFinding());
  assert.ok(t.title.startsWith("[SECURITY] "));
  assert.ok(t.title.includes("src/api/users.ts"));
});

test("buildIssue Markdown body contains all expected sections", () => {
  const t = buildIssue(makeFinding());
  assert.match(t.bodyMarkdown, /## Vulnerability/);
  assert.match(t.bodyMarkdown, /## Severity/);
  assert.match(t.bodyMarkdown, /## How an attacker exploits this/);
  assert.match(t.bodyMarkdown, /## Fix/);
  assert.match(t.bodyMarkdown, /## References/);
  assert.match(t.bodyMarkdown, /Ironward rule: `sql-injection`/);
  assert.match(t.bodyMarkdown, /CVSS 9\.1/);
  assert.match(t.bodyMarkdown, /OWASP: A03:2021/);
});

test("buildIssue uses fallback strings when finding has no exploit", () => {
  const t = buildIssue(makeFinding({ exploit: undefined }));
  assert.match(t.bodyMarkdown, /no proof-of-concept available/);
  assert.match(t.bodyMarkdown, /see rule remediation guidance/);
  assert.match(t.bodyMarkdown, /CVSS —/);
  // References still includes the rule id even without exploit metadata.
  assert.match(t.bodyMarkdown, /Ironward rule: `sql-injection`/);
});

test("buildIssue maps severity to Linear and Jira priority for all 5 levels", () => {
  const cases: Array<[NormalizedFinding["severity"], string, string]> = [
    ["critical", "Urgent", "Highest"],
    ["high", "High", "High"],
    ["medium", "Medium", "Medium"],
    ["low", "Low", "Low"],
    ["info", "Low", "Low"],
  ];
  for (const [sev, linear, jira] of cases) {
    const t = buildIssue(makeFinding({ severity: sev }));
    assert.equal(t.priorityLabel, linear, `linear for ${sev}`);
    assert.equal(t.jiraPriorityName, jira, `jira for ${sev}`);
  }
});

test("buildIssue Jira markup uses h2. and {code} instead of Markdown", () => {
  const t = buildIssue(makeFinding());
  assert.match(t.bodyJiraMarkup, /h2\. Vulnerability/);
  assert.match(t.bodyJiraMarkup, /h2\. Severity/);
  assert.match(t.bodyJiraMarkup, /h2\. How an attacker exploits this/);
  assert.match(t.bodyJiraMarkup, /h2\. Fix/);
  assert.match(t.bodyJiraMarkup, /\{code\}/);
  // Markdown fences must NOT appear in the Jira variant.
  assert.doesNotMatch(t.bodyJiraMarkup, /^## /m);
  assert.doesNotMatch(t.bodyJiraMarkup, /```/);
});

test("buildIssue labels include security + severity + extras", () => {
  const t = buildIssue(makeFinding({ severity: "high" }), { extraLabels: ["team-backend"] });
  assert.deepEqual(t.labels, ["security", "high", "team-backend"]);
});

test("linearPriorityNumber maps all four labels", () => {
  assert.equal(linearPriorityNumber("Urgent"), 1);
  assert.equal(linearPriorityNumber("High"), 2);
  assert.equal(linearPriorityNumber("Medium"), 3);
  assert.equal(linearPriorityNumber("Low"), 4);
});

// ──────────────────────────────────────────────────────────────
// Linear: high-level reporter
// ──────────────────────────────────────────────────────────────
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

test("reportFindingToLinear: below-threshold for medium when threshold is high", async () => {
  const cfg: LinearConfig = { apiKey: "lin_x", teamId: "team_1", threshold: "high" };
  const r = await reportFindingToLinear(
    cfg,
    makeFinding({ severity: "medium" }),
    "myrepo",
    mockLinearClient(),
  );
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "below-threshold");
});

test("reportFindingToLinear: not-configured when apiKey is missing", async () => {
  const cfg = { apiKey: "", teamId: "team_1" } as LinearConfig;
  const r = await reportFindingToLinear(cfg, makeFinding(), "myrepo", mockLinearClient());
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "not-configured");
});

test("reportFindingToLinear: duplicate when fingerprint already exists", async () => {
  const cfg: LinearConfig = { apiKey: "lin_x", teamId: "team_1", threshold: "critical" };
  const client = mockLinearClient({
    findExistingByFingerprint: async () => ({ id: "iss_5", identifier: "SEC-5" }),
  });
  const r = await reportFindingToLinear(cfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "duplicate");
  assert.ok(r.url && r.url.includes("SEC-5"));
});

test("reportFindingToLinear: created when client.createIssue succeeds", async () => {
  const cfg: LinearConfig = { apiKey: "lin_x", teamId: "team_1" };
  let received: { teamId: string; title: string; description: string } | null = null;
  const client = mockLinearClient({
    createIssue: async (input) => {
      received = input;
      return { id: "iss_2", identifier: "SEC-2", url: "https://linear.app/team/issue/SEC-2" };
    },
  });
  const r = await reportFindingToLinear(cfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "created");
  assert.equal(r.url, "https://linear.app/team/issue/SEC-2");
  assert.ok(received);
  assert.equal(received!.teamId, "team_1");
  assert.ok(received!.title.startsWith("[SECURITY]"));
  assert.match(received!.description, /ironward-fingerprint:/);
});

test("reportFindingToLinear: error when client.createIssue rejects", async () => {
  const cfg: LinearConfig = { apiKey: "lin_x", teamId: "team_1" };
  const client = mockLinearClient({
    createIssue: async () => {
      throw new Error("boom");
    },
  });
  const r = await reportFindingToLinear(cfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "error");
  assert.match(r.error ?? "", /boom/);
});

test("HttpLinearClient.createIssue returns null on rejected fetch (graceful)", async () => {
  const fetchImpl = (async () => {
    throw new Error("ECONNREFUSED");
  }) as unknown as typeof fetch;
  const client = new HttpLinearClient({ apiKey: "lin_x", fetchImpl });
  const result = await client.createIssue({
    teamId: "t1",
    title: "x",
    description: "y",
  });
  assert.equal(result, null);
});

test("HttpLinearClient.findExistingByFingerprint returns null on non-ok response", async () => {
  const fetchImpl = (async () =>
    new Response("nope", { status: 500 })) as unknown as typeof fetch;
  const client = new HttpLinearClient({ apiKey: "lin_x", fetchImpl });
  const result = await client.findExistingByFingerprint("abc123");
  assert.equal(result, null);
});

test("HttpLinearClient sends the apiKey verbatim in Authorization header", async () => {
  let captured: { url: string; init?: RequestInit } | null = null;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    captured = { url, init };
    return new Response(JSON.stringify({ data: { teams: { nodes: [] } } }), { status: 200 });
  }) as unknown as typeof fetch;
  const client = new HttpLinearClient({ apiKey: "lin_secret_token", fetchImpl });
  await client.listTeams();
  assert.ok(captured);
  const headers = (captured!.init?.headers ?? {}) as Record<string, string>;
  assert.equal(headers.Authorization, "lin_secret_token");
  assert.equal(headers["Content-Type"], "application/json");
});

// ──────────────────────────────────────────────────────────────
// Jira: high-level reporter
// ──────────────────────────────────────────────────────────────
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

const baseJiraCfg: JiraConfig = {
  baseUrl: "https://example.atlassian.net",
  email: "me@example.com",
  apiToken: "tok_x",
  projectKey: "SEC",
};

test("reportFindingToJira: below-threshold for medium when threshold is high", async () => {
  const r = await reportFindingToJira(
    { ...baseJiraCfg, threshold: "high" },
    makeFinding({ severity: "medium" }),
    "myrepo",
    mockJiraClient(),
  );
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "below-threshold");
});

test("reportFindingToJira: not-configured when apiToken is missing", async () => {
  const cfg = { ...baseJiraCfg, apiToken: "" };
  const r = await reportFindingToJira(cfg, makeFinding(), "myrepo", mockJiraClient());
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "not-configured");
});

test("reportFindingToJira: duplicate when fingerprint already exists", async () => {
  const client = mockJiraClient({
    findExistingByFingerprint: async () => ({ key: "SEC-9", id: "9000" }),
  });
  const r = await reportFindingToJira(baseJiraCfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "duplicate");
  assert.equal(r.key, "SEC-9");
  assert.ok(r.url && r.url.endsWith("/browse/SEC-9"));
});

test("reportFindingToJira: created when client.createIssue succeeds", async () => {
  let received: {
    projectKey: string;
    summary: string;
    description: string;
    priority?: string;
  } | null = null;
  const client = mockJiraClient({
    createIssue: async (input) => {
      received = input;
      return {
        id: "10002",
        key: "SEC-2",
        self: "https://example.atlassian.net/rest/api/3/issue/10002",
      };
    },
  });
  const r = await reportFindingToJira(baseJiraCfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, true);
  assert.equal(r.outcome, "created");
  assert.equal(r.key, "SEC-2");
  assert.equal(r.url, "https://example.atlassian.net/browse/SEC-2");
  assert.ok(received);
  assert.equal(received!.projectKey, "SEC");
  assert.equal(received!.priority, "Highest"); // critical → Highest
  assert.match(received!.description, /ironward-fingerprint:/);
  assert.match(received!.description, /h2\. Vulnerability/);
});

test("reportFindingToJira: error when client.createIssue rejects", async () => {
  const client = mockJiraClient({
    createIssue: async () => {
      throw new Error("network down");
    },
  });
  const r = await reportFindingToJira(baseJiraCfg, makeFinding(), "myrepo", client);
  assert.equal(r.ok, false);
  assert.equal(r.outcome, "error");
  assert.match(r.error ?? "", /network down/);
});

test("HttpJiraClient.createIssue returns null on 401 response", async () => {
  const fetchImpl = (async () =>
    new Response("Unauthorized", { status: 401 })) as unknown as typeof fetch;
  const client = new HttpJiraClient({
    baseUrl: "https://example.atlassian.net",
    email: "me@example.com",
    apiToken: "tok_x",
    fetchImpl,
  });
  const r = await client.createIssue({
    projectKey: "SEC",
    summary: "x",
    description: "y",
    issueType: "Bug",
  });
  assert.equal(r, null);
});

test("HttpJiraClient sends Basic auth header derived from email:token", async () => {
  let captured: { url: string; init?: RequestInit } | null = null;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    captured = { url, init };
    return new Response(JSON.stringify({ issues: [] }), { status: 200 });
  }) as unknown as typeof fetch;
  const client = new HttpJiraClient({
    baseUrl: "https://example.atlassian.net",
    email: "me@example.com",
    apiToken: "tok_x",
    fetchImpl,
  });
  await client.findExistingByFingerprint("SEC", "fp123");
  assert.ok(captured);
  const headers = (captured!.init?.headers ?? {}) as Record<string, string>;
  const expected = "Basic " + Buffer.from("me@example.com:tok_x", "utf8").toString("base64");
  assert.equal(headers.Authorization, expected);
  assert.match(captured!.url, /\/rest\/api\/3\/search\?jql=/);
});
