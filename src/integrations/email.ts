/**
 * Resend transactional email client + weekly digest builder for Ironward.
 *
 * The Resend API key lives only inside the closure of a single call and is
 * never logged or persisted by this module.
 */

import type { NormalizedFinding } from "../engines/sarif.js";
import type { EmailConfig } from "./config.js";

export interface DigestData {
  repo: string;
  scoreCurrent: number;
  scorePrevious: number;
  newFindings: number;
  bySeverity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  topUnresolved: NormalizedFinding[]; // Pass top 5 already-sorted
  filesWithMostIssues: Array<{ file: string; count: number }>;
  dashboardUrl?: string; // default "http://localhost:3737"
}

export interface SendEmailResult {
  ok: boolean;
  status?: number;
  id?: string;
  error?: string;
}

const SEVERITY_COLORS: Record<"critical" | "high" | "medium" | "low" | "info", string> = {
  critical: "#b71c1c",
  high: "#e65100",
  medium: "#f9a825",
  low: "#1565c0",
  info: "#616161",
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function buildDigestSubject(d: DigestData): string {
  const sev = d.bySeverity ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  if (sev.critical > 0) {
    return `Ironward Weekly: ${sev.critical} critical issue${sev.critical === 1 ? "" : "s"}`;
  }
  if (sev.high > 0) {
    return `Ironward Weekly: ${sev.high} high-severity issue${sev.high === 1 ? "" : "s"}`;
  }
  if (sev.medium > 0) {
    return `Ironward Weekly: ${sev.medium} medium-severity issue${sev.medium === 1 ? "" : "s"}`;
  }
  if (sev.low > 0) {
    return `Ironward Weekly: ${sev.low} low-severity issue${sev.low === 1 ? "" : "s"}`;
  }
  if (sev.info > 0) {
    return `Ironward Weekly: ${sev.info} informational item${sev.info === 1 ? "" : "s"}`;
  }
  return "Ironward Weekly: All clear";
}

function severityBadge(sev: "critical" | "high" | "medium" | "low" | "info", count: number): string {
  const color = SEVERITY_COLORS[sev];
  return `<span style="display:inline-block;padding:4px 10px;margin:2px;border-radius:12px;background:${color};color:#fff;font-size:12px;font-weight:600;font-family:Arial,sans-serif">${escapeHtml(sev)}: ${count}</span>`;
}

export function buildDigestHtml(d: DigestData): string {
  const dashboardUrl = d.dashboardUrl ?? "http://localhost:3737";
  const diff = d.scoreCurrent - d.scorePrevious;
  const sign = diff >= 0 ? "+" : "-";
  const trendColor = diff >= 0 ? "#2e7d32" : "#c62828";

  const severityRow = (["critical", "high", "medium", "low", "info"] as const)
    .map((s) => severityBadge(s, d.bySeverity?.[s] ?? 0))
    .join("");

  const topFindingsList = d.topUnresolved.length
    ? `<ul style="padding-left:20px;margin:8px 0;color:#212121;font-family:Arial,sans-serif;font-size:14px">
        ${d.topUnresolved
          .slice(0, 5)
          .map((f) => {
            const c = SEVERITY_COLORS[f.severity];
            return `<li style="margin:6px 0">
              <span style="color:${c};font-weight:600;text-transform:uppercase;font-size:11px">[${escapeHtml(f.severity)}]</span>
              <code style="background:#f5f5f5;padding:1px 4px;border-radius:3px;font-size:12px">${escapeHtml(f.file)}:${f.line}</code>
              — ${escapeHtml(f.title)}
            </li>`;
          })
          .join("")}
      </ul>`
    : `<p style="color:#616161;font-family:Arial,sans-serif;font-size:14px;margin:8px 0">No unresolved findings.</p>`;

  const filesList = d.filesWithMostIssues.length
    ? `<ul style="padding-left:20px;margin:8px 0;color:#212121;font-family:Arial,sans-serif;font-size:14px">
        ${d.filesWithMostIssues
          .slice(0, 5)
          .map(
            (f) =>
              `<li style="margin:4px 0"><code style="background:#f5f5f5;padding:1px 4px;border-radius:3px;font-size:12px">${escapeHtml(f.file)}</code> — ${f.count} issue${f.count === 1 ? "" : "s"}</li>`,
          )
          .join("")}
      </ul>`
    : `<p style="color:#616161;font-family:Arial,sans-serif;font-size:14px;margin:8px 0">No files to report.</p>`;

  return `<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#fafafa;font-family:Arial,sans-serif">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fafafa;padding:24px 0">
      <tr>
        <td align="center">
          <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e0e0e0;padding:24px">
            <tr>
              <td>
                <h1 style="margin:0 0 8px 0;font-size:22px;color:#212121">Ironward Weekly Digest</h1>
                <p style="margin:0 0 24px 0;color:#616161;font-size:14px">Repository: <strong>${escapeHtml(d.repo)}</strong></p>

                <h2 style="margin:0 0 8px 0;font-size:16px;color:#212121">Security score</h2>
                <p style="margin:0 0 16px 0;font-size:14px;color:#212121">
                  <strong style="font-size:28px">${d.scoreCurrent}</strong>/100
                  <span style="margin-left:12px;color:${trendColor};font-weight:600">${sign}${Math.abs(diff)} from last week</span>
                </p>

                <h2 style="margin:16px 0 8px 0;font-size:16px;color:#212121">New findings (${d.newFindings})</h2>
                <p style="margin:0 0 16px 0">${severityRow}</p>

                <h2 style="margin:16px 0 8px 0;font-size:16px;color:#212121">Top unresolved findings</h2>
                ${topFindingsList}

                <h2 style="margin:16px 0 8px 0;font-size:16px;color:#212121">Files with most issues</h2>
                ${filesList}

                <table cellpadding="0" cellspacing="0" style="margin:24px 0 8px 0">
                  <tr>
                    <td style="background:#1565c0;border-radius:6px">
                      <a href="${escapeHtml(dashboardUrl)}" style="display:inline-block;padding:12px 22px;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;font-family:Arial,sans-serif">View dashboard</a>
                    </td>
                  </tr>
                </table>

                <p style="margin:24px 0 0 0;color:#9e9e9e;font-size:12px">Generated by Ironward.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

/** Posts a digest email to the Resend API. Graceful: never throws. */
export async function sendDigestEmail(
  cfg: EmailConfig,
  d: DigestData,
  fetchImpl: typeof fetch = fetch,
): Promise<SendEmailResult> {
  const subject = buildDigestSubject(d);
  const html = buildDigestHtml(d);

  const body = {
    from: cfg.from,
    to: cfg.to,
    subject,
    html,
  };

  try {
    const res = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      return { ok: false, status: res.status };
    }
    let id: string | undefined;
    try {
      const parsed = (await res.json()) as { id?: string };
      id = parsed?.id;
    } catch {
      // body may not be JSON in some edge cases — non-fatal
    }
    return { ok: true, status: res.status, id };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
