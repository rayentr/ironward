import { readFile } from "node:fs/promises";
import { scanCodeRules, severityRank, type CodeFinding, type CodeSeverity } from "../engines/code-rules.js";

export interface ScanCodeInput {
  files?: Array<{ path: string; content: string }>;
  paths?: string[];
  content?: string;
}

export interface ScanCodeFileReport {
  path: string;
  findings: CodeFinding[];
}

export interface ScanCodeOutput {
  files: ScanCodeFileReport[];
  summary: {
    totalFindings: number;
    bySeverity: Record<CodeSeverity, number>;
    filesScanned: number;
  };
}

const SKIP_EXT = new Set([
  ".lock", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".tar", ".gz",
  ".mp3", ".mp4", ".mov", ".webm",
]);

function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot >= 0 && SKIP_EXT.has(lower.slice(dot))) return true;
  const skipDirs = ["node_modules", ".git", "dist", "build", ".next", ".turbo", ".venv", "venv"];
  for (const d of skipDirs) {
    if (lower.startsWith(`${d}/`) || lower.includes(`/${d}/`)) return true;
  }
  return false;
}

export async function runScanCode(input: ScanCodeInput): Promise<ScanCodeOutput> {
  const reports: ScanCodeFileReport[] = [];

  if (input.content && !input.files && !input.paths) {
    reports.push({ path: "<inline>", findings: scanCodeRules(input.content) });
  }
  if (input.files) {
    for (const f of input.files) {
      if (shouldSkip(f.path)) continue;
      reports.push({ path: f.path, findings: scanCodeRules(f.content) });
    }
  }
  if (input.paths) {
    for (const p of input.paths) {
      if (shouldSkip(p)) continue;
      try {
        const content = await readFile(p, "utf8");
        reports.push({ path: p, findings: scanCodeRules(content) });
      } catch {
        /* unreadable — skip */
      }
    }
  }

  const bySeverity: Record<CodeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) {
    bySeverity[f.severity]++;
    total++;
  }

  return {
    files: reports,
    summary: {
      totalFindings: total,
      bySeverity,
      filesScanned: reports.length,
    },
  };
}

export function formatCodeReport(out: ScanCodeOutput): string {
  const { summary, files } = out;
  const lines: string[] = [];
  if (summary.totalFindings === 0) {
    lines.push(`scan_code: no issues across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"}.`);
    return lines.join("\n");
  }
  lines.push(
    `scan_code: ${summary.totalFindings} finding${summary.totalFindings === 1 ? "" : "s"} ` +
      `across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"} ` +
      `(${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ` +
      `${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
  );
  lines.push("");

  for (const file of files) {
    if (file.findings.length === 0) continue;
    const sorted = [...file.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.line - b.line,
    );
    lines.push(file.path);
    for (const f of sorted) {
      lines.push(`  [${f.severity.toUpperCase()}] L${f.line}:${f.column}  ${f.title}  (${f.ruleId})`);
      lines.push(`      why: ${f.rationale}`);
      lines.push(`      fix: ${f.fix}`);
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
