/**
 * Linear GraphQL client + high-level reporter.
 *
 * Graceful by design — `reportFindingToLinear` never throws and always returns
 * a structured outcome so callers can log it without try/catch noise.
 */

import type { NormalizedFinding } from "../engines/sarif.js";
import type { LinearConfig } from "./config.js";
import { findingFingerprint } from "./config.js";
import { buildIssue, linearPriorityNumber } from "./issue-template.js";

const LINEAR_ENDPOINT = "https://api.linear.app/graphql";

export interface LinearClient {
  /** Returns issues searchable by an Ironward fingerprint stored in the description. Used for dedup. */
  findExistingByFingerprint(fingerprint: string): Promise<{ id: string; identifier: string } | null>;
  createIssue(input: {
    teamId: string;
    title: string;
    description: string;
    labels?: string[];
    priority?: number;     // 1=Urgent, 2=High, 3=Medium, 4=Low
    projectId?: string;
    assigneeId?: string | null;
  }): Promise<{ id: string; identifier: string; url: string } | null>;
  listTeams(): Promise<Array<{ id: string; name: string; key: string }>>;
}

export interface CreateLinearIssueResult {
  ok: boolean;
  /** "created" | "duplicate" | "below-threshold" | "not-configured" | "error" */
  outcome: string;
  url?: string;
  error?: string;
}

export function fingerprintMarker(fp: string): string {
  return `<!-- ironward-fingerprint:${fp} -->`;
}

/** True when a finding's severity meets/exceeds the configured threshold. */
export function meetsLinearThreshold(
  severity: NormalizedFinding["severity"],
  threshold: LinearConfig["threshold"] | undefined,
): boolean {
  const t = threshold ?? "high";
  if (t === "critical") return severity === "critical";
  if (t === "high") return severity === "critical" || severity === "high";
  // "both" treated as critical+high (the only documented values).
  return severity === "critical" || severity === "high";
}

interface LinearGqlResponse<T> {
  data?: T;
  errors?: Array<{ message: string }>;
}

export class HttpLinearClient implements LinearClient {
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly endpoint: string;

  constructor(opts: {
    apiKey: string;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    endpoint?: string;
  }) {
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.endpoint = opts.endpoint ?? LINEAR_ENDPOINT;
  }

  private async gql<T>(query: string, variables: Record<string, unknown>): Promise<T | null> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // Linear bearer keys are sent as the raw key, no "Bearer " prefix.
          Authorization: this.apiKey,
        },
        body: JSON.stringify({ query, variables }),
        signal: ctrl.signal,
      });
      if (!res.ok) return null;
      const json = (await res.json()) as LinearGqlResponse<T>;
      if (json.errors && json.errors.length > 0) return null;
      return json.data ?? null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async findExistingByFingerprint(
    fingerprint: string,
  ): Promise<{ id: string; identifier: string } | null> {
    const marker = fingerprintMarker(fingerprint);
    const query = `query Search($needle: String!) {
      issues(filter: { description: { contains: $needle } }, first: 1) {
        nodes { id identifier }
      }
    }`;
    const data = await this.gql<{ issues: { nodes: Array<{ id: string; identifier: string }> } }>(
      query,
      { needle: marker },
    );
    const node = data?.issues?.nodes?.[0];
    return node ? { id: node.id, identifier: node.identifier } : null;
  }

  async createIssue(input: {
    teamId: string;
    title: string;
    description: string;
    labels?: string[];
    priority?: number;
    projectId?: string;
    assigneeId?: string | null;
  }): Promise<{ id: string; identifier: string; url: string } | null> {
    const mutation = `mutation Create($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url }
      }
    }`;
    const payload: Record<string, unknown> = {
      teamId: input.teamId,
      title: input.title,
      description: input.description,
    };
    if (input.priority != null) payload.priority = input.priority;
    if (input.projectId) payload.projectId = input.projectId;
    if (input.assigneeId) payload.assigneeId = input.assigneeId;
    if (input.labels && input.labels.length > 0) payload.labelIds = input.labels;

    const data = await this.gql<{
      issueCreate: { success: boolean; issue: { id: string; identifier: string; url: string } | null };
    }>(mutation, { input: payload });
    if (!data?.issueCreate?.success || !data.issueCreate.issue) return null;
    return data.issueCreate.issue;
  }

  async listTeams(): Promise<Array<{ id: string; name: string; key: string }>> {
    const query = `query Teams { teams(first: 50) { nodes { id name key } } }`;
    const data = await this.gql<{ teams: { nodes: Array<{ id: string; name: string; key: string }> } }>(
      query,
      {},
    );
    return data?.teams?.nodes ?? [];
  }
}

/**
 * High-level: pick threshold, dedup by fingerprint, create issue.
 * Graceful — returns ok:false on error, never throws.
 */
export async function reportFindingToLinear(
  cfg: LinearConfig,
  finding: NormalizedFinding,
  repo: string,
  client?: LinearClient,
): Promise<CreateLinearIssueResult> {
  if (!cfg || !cfg.apiKey) {
    return { ok: false, outcome: "not-configured" };
  }
  if (!cfg.teamId) {
    return { ok: false, outcome: "not-configured" };
  }
  if (!meetsLinearThreshold(finding.severity, cfg.threshold)) {
    return { ok: true, outcome: "below-threshold" };
  }

  const fp = finding.fingerprint ?? findingFingerprint(repo, finding.file, finding.line, finding.ruleId);
  const c = client ?? new HttpLinearClient({ apiKey: cfg.apiKey });

  try {
    const existing = await c.findExistingByFingerprint(fp);
    if (existing) {
      return {
        ok: true,
        outcome: "duplicate",
        url: `https://linear.app/issue/${existing.identifier}`,
      };
    }

    const tmpl = buildIssue(finding, { extraLabels: cfg.label ? [cfg.label] : [] });
    const description = `${tmpl.bodyMarkdown}\n\n${fingerprintMarker(fp)}`;

    const created = await c.createIssue({
      teamId: cfg.teamId,
      title: tmpl.title,
      description,
      priority: linearPriorityNumber(tmpl.priorityLabel),
      projectId: cfg.projectId,
      assigneeId: cfg.assigneeId ?? null,
    });
    if (!created) {
      return { ok: false, outcome: "error", error: "issueCreate returned no issue" };
    }
    return { ok: true, outcome: "created", url: created.url };
  } catch (err) {
    return {
      ok: false,
      outcome: "error",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
