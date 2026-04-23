import type { NormalizedFinding } from "./sarif.js";

export interface WebhookPayload {
  source: "ironward";
  version: string;
  target: string;
  timestamp: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: NormalizedFinding[];
}

/** Lightweight fetcher abstraction so tests can inject a spy. */
export type Poster = (
  url: string,
  body: string,
  headers: Record<string, string>,
) => Promise<{ ok: boolean; status: number; text?: () => Promise<string> }>;

export const defaultPoster: Poster = async (url, body, headers) => {
  const res = await fetch(url, { method: "POST", body, headers });
  return { ok: res.ok, status: res.status, text: () => res.text() };
};

function severityCounts(findings: NormalizedFinding[]) {
  const counts = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity in counts) (counts as any)[f.severity]++;
  }
  return counts;
}

function isSlackWebhook(url: string): boolean {
  return /^https:\/\/hooks\.slack\.com\//.test(url);
}

function renderSlackBlocks(payload: WebhookPayload): unknown {
  const { summary, target, findings } = payload;
  const status = summary.critical + summary.high > 0 ? "🚨 *Critical/high findings*" : summary.total > 0 ? "⚠️ *Findings present*" : "✅ *Clean*";
  const topFindings = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 10)
    .map((f) => `• *[${f.severity.toUpperCase()}]* \`${f.file}:${f.line}\` — ${f.title}`)
    .join("\n") || "(no critical/high findings)";

  return {
    text: `Ironward ${status}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `${status} on *${target}*` } },
      { type: "section", fields: [
        { type: "mrkdwn", text: `*Total*\n${summary.total}` },
        { type: "mrkdwn", text: `*Critical*\n${summary.critical}` },
        { type: "mrkdwn", text: `*High*\n${summary.high}` },
        { type: "mrkdwn", text: `*Medium*\n${summary.medium}` },
      ]},
      ...(findings.length > 0 ? [{ type: "section", text: { type: "mrkdwn", text: topFindings.slice(0, 2800) } }] : []),
      { type: "context", elements: [{ type: "mrkdwn", text: `ironward v${payload.version} · ${payload.timestamp}` }] },
    ],
  };
}

export async function postWebhook(
  url: string,
  payload: WebhookPayload,
  poster: Poster = defaultPoster,
): Promise<{ ok: boolean; status: number; error?: string }> {
  const body = isSlackWebhook(url) ? JSON.stringify(renderSlackBlocks(payload)) : JSON.stringify(payload);
  const headers = { "Content-Type": "application/json", "User-Agent": `ironward/${payload.version}` };
  try {
    const res = await poster(url, body, headers);
    if (!res.ok) {
      const text = res.text ? await res.text().catch(() => "") : "";
      return { ok: false, status: res.status, error: `HTTP ${res.status}: ${text.slice(0, 200)}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  }
}

export function buildWebhookPayload(
  findings: NormalizedFinding[],
  opts: { version: string; target: string },
): WebhookPayload {
  return {
    source: "ironward",
    version: opts.version,
    target: opts.target,
    timestamp: new Date().toISOString(),
    summary: severityCounts(findings),
    findings,
  };
}
