/**
 * Jira REST API v3 client + high-level reporter.
 *
 * Auth is HTTP Basic with `email:apiToken` base64-encoded.
 * Issues are deduplicated by embedding `[ironward-fingerprint:{fp}]` in the
 * description and searching for it via JQL `text ~ "..."`.
 */

import type { NormalizedFinding } from "../engines/sarif.js";
import type { JiraConfig } from "./config.js";
import { findingFingerprint } from "./config.js";
import { buildIssue } from "./issue-template.js";

export interface JiraClient {
  findExistingByFingerprint(
    projectKey: string,
    fingerprint: string,
  ): Promise<{ key: string; id: string } | null>;
  createIssue(input: {
    projectKey: string;
    summary: string;
    description: string;
    issueType: string;
    priority?: "Highest" | "High" | "Medium" | "Low";
    labels?: string[];
  }): Promise<{ key: string; id: string; self: string } | null>;
}

export interface CreateJiraIssueResult {
  ok: boolean;
  outcome: "created" | "duplicate" | "below-threshold" | "not-configured" | "error";
  key?: string;
  url?: string;
  error?: string;
}

export function jiraFingerprintMarker(fp: string): string {
  return `[ironward-fingerprint:${fp}]`;
}

export function meetsJiraThreshold(
  severity: NormalizedFinding["severity"],
  threshold: JiraConfig["threshold"] | undefined,
): boolean {
  const t = threshold ?? "high";
  if (t === "critical") return severity === "critical";
  if (t === "high") return severity === "critical" || severity === "high";
  return severity === "critical" || severity === "high";
}

function basicAuthHeader(email: string, apiToken: string): string {
  const raw = `${email}:${apiToken}`;
  // Buffer is always available in Node ≥20.
  const b64 = Buffer.from(raw, "utf8").toString("base64");
  return `Basic ${b64}`;
}

/**
 * Wrap plain text in the minimal Atlassian Document Format envelope so the
 * REST v3 endpoint accepts it. We pass through a single text node to keep
 * markup characters (h2., {code}) intact for visual inspection.
 */
function adfFromText(text: string): unknown {
  return {
    type: "doc",
    version: 1,
    content: [
      {
        type: "paragraph",
        content: [{ type: "text", text }],
      },
    ],
  };
}

export class HttpJiraClient implements JiraClient {
  private readonly baseUrl: string;
  private readonly auth: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: {
    baseUrl: string;
    email: string;
    apiToken: string;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
  }) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.auth = basicAuthHeader(opts.email, opts.apiToken);
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<T | null> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: this.auth,
          Accept: "application/json",
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      if (!res.ok) return null;
      // Some Jira endpoints return 204 No Content.
      if (res.status === 204) return null;
      return (await res.json()) as T;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async findExistingByFingerprint(
    projectKey: string,
    fingerprint: string,
  ): Promise<{ key: string; id: string } | null> {
    const marker = jiraFingerprintMarker(fingerprint);
    const jql = `project = "${projectKey}" AND text ~ "${marker}"`;
    const url = `/rest/api/3/search?jql=${encodeURIComponent(jql)}&maxResults=1&fields=summary`;
    const data = await this.request<{ issues: Array<{ key: string; id: string }> }>("GET", url);
    const hit = data?.issues?.[0];
    return hit ? { key: hit.key, id: hit.id } : null;
  }

  async createIssue(input: {
    projectKey: string;
    summary: string;
    description: string;
    issueType: string;
    priority?: "Highest" | "High" | "Medium" | "Low";
    labels?: string[];
  }): Promise<{ key: string; id: string; self: string } | null> {
    const fields: Record<string, unknown> = {
      project: { key: input.projectKey },
      summary: input.summary,
      description: adfFromText(input.description),
      issuetype: { name: input.issueType },
    };
    if (input.priority) fields.priority = { name: input.priority };
    if (input.labels && input.labels.length > 0) fields.labels = input.labels;

    const data = await this.request<{ id: string; key: string; self: string }>(
      "POST",
      "/rest/api/3/issue",
      { fields },
    );
    return data ?? null;
  }
}

export async function reportFindingToJira(
  cfg: JiraConfig,
  finding: NormalizedFinding,
  repo: string,
  client?: JiraClient,
): Promise<CreateJiraIssueResult> {
  if (!cfg || !cfg.baseUrl || !cfg.email || !cfg.apiToken || !cfg.projectKey) {
    return { ok: false, outcome: "not-configured" };
  }
  if (!meetsJiraThreshold(finding.severity, cfg.threshold)) {
    return { ok: true, outcome: "below-threshold" };
  }

  const fp = finding.fingerprint ?? findingFingerprint(repo, finding.file, finding.line, finding.ruleId);
  const c =
    client ??
    new HttpJiraClient({
      baseUrl: cfg.baseUrl,
      email: cfg.email,
      apiToken: cfg.apiToken,
    });

  try {
    const existing = await c.findExistingByFingerprint(cfg.projectKey, fp);
    if (existing) {
      const url = `${cfg.baseUrl.replace(/\/+$/, "")}/browse/${existing.key}`;
      return { ok: true, outcome: "duplicate", key: existing.key, url };
    }

    const tmpl = buildIssue(finding);
    // Embed the fingerprint marker in plain text so JQL `text ~` finds it.
    const description = `${tmpl.bodyJiraMarkup}\n\n${jiraFingerprintMarker(fp)}`;

    const created = await c.createIssue({
      projectKey: cfg.projectKey,
      summary: tmpl.title,
      description,
      issueType: cfg.issueType ?? "Bug",
      priority: tmpl.jiraPriorityName,
      labels: tmpl.labels,
    });
    if (!created) {
      return { ok: false, outcome: "error", error: "createIssue returned null" };
    }
    const url = `${cfg.baseUrl.replace(/\/+$/, "")}/browse/${created.key}`;
    return { ok: true, outcome: "created", key: created.key, url };
  } catch (err) {
    return {
      ok: false,
      outcome: "error",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
