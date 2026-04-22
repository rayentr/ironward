import { readFile } from "node:fs/promises";
import { scanText, severityRank, type Finding, type Severity } from "../engines/secret-engine.js";

export interface ScanSecretsInput {
  files?: Array<{ path: string; content: string }>;
  paths?: string[];
  content?: string;
  context?: "pre-commit" | "on-save" | "on-demand";
}

export interface FileReport {
  path: string;
  findings: Finding[];
}

export interface ScanSecretsOutput {
  files: FileReport[];
  summary: {
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    blocked: boolean;
  };
}

const SKIP_EXT = new Set([".lock", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".tar", ".gz"]);

function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot >= 0 && SKIP_EXT.has(lower.slice(dot))) return true;
  if (lower.includes("/node_modules/") || lower.includes("/.git/") || lower.includes("/dist/")) return true;
  return false;
}

export async function runScanSecrets(input: ScanSecretsInput): Promise<ScanSecretsOutput> {
  const reports: FileReport[] = [];

  if (input.content && !input.files && !input.paths) {
    reports.push({ path: "<inline>", findings: await scanText(input.content) });
  }

  if (input.files) {
    for (const f of input.files) {
      if (shouldSkip(f.path)) continue;
      reports.push({ path: f.path, findings: await scanText(f.content, f.path) });
    }
  }

  if (input.paths) {
    for (const p of input.paths) {
      if (shouldSkip(p)) continue;
      try {
        const content = await readFile(p, "utf8");
        reports.push({ path: p, findings: await scanText(content, p) });
      } catch (err) {
        reports.push({
          path: p,
          findings: [],
        });
      }
    }
  }

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) {
    for (const f of r.findings) {
      bySeverity[f.severity]++;
      total++;
    }
  }

  const blocked = input.context === "pre-commit" && (bySeverity.critical > 0 || bySeverity.high > 0);

  return {
    files: reports,
    summary: {
      totalFindings: total,
      bySeverity,
      blocked,
    },
  };
}

export function formatReport(out: ScanSecretsOutput): string {
  const { summary, files } = out;
  const lines: string[] = [];
  if (summary.totalFindings === 0) {
    lines.push("No secrets detected. All scanned files are clean.");
    return lines.join("\n");
  }
  lines.push(
    `Found ${summary.totalFindings} potential secret${summary.totalFindings === 1 ? "" : "s"} ` +
      `(${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ` +
      `${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
  );
  if (summary.blocked) lines.push("BLOCKED: pre-commit scan has critical/high findings.");
  lines.push("");

  for (const file of files) {
    if (file.findings.length === 0) continue;
    lines.push(`${file.path}`);
    const sorted = [...file.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.line - b.line,
    );
    for (const f of sorted) {
      lines.push(`  [${f.severity.toUpperCase()}] L${f.line}:${f.column}  ${f.type}  ${f.redacted}`);
      lines.push(`      ${f.description}`);
      lines.push(`      fix: ${f.fix}`);
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
