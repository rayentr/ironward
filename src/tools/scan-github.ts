import { readFile } from "node:fs/promises";
import { GITHUB_RULES, type GithubRule, type GithubSeverity } from "../engines/github-rules.js";

export interface GithubFinding {
  ruleId: string;
  severity: GithubSeverity;
  category: GithubRule["category"];
  title: string;
  line: number;
  rationale: string;
  fix: string;
  snippet: string;
}

export interface ScanGithubFileReport {
  path: string;
  findings: GithubFinding[];
}

export interface ScanGithubInput {
  files?: Array<{ path: string; content: string }>;
  paths?: string[];
}

export interface ScanGithubOutput {
  files: ScanGithubFileReport[];
  summary: {
    filesScanned: number;
    totalFindings: number;
    bySeverity: Record<GithubSeverity, number>;
  };
}

/** Return true if `path` (or `content` heuristics) indicate a GitHub Actions workflow file. */
export function detectGithubWorkflow(path: string, content?: string): boolean {
  const p = path.replace(/\\/g, "/").toLowerCase();
  if (/\.github\/workflows\/[^/]+\.(?:yml|yaml)$/.test(p)) return true;
  if (!content) return false;

  // Content heuristic: look for `on:` or `jobs:` at column 0 AND a `runs-on:` / `uses:` elsewhere.
  let hasTopLevel = false;
  let hasJobKey = false;
  for (const line of content.split("\n")) {
    if (/^on:\s*(?:\[|$|#)/.test(line) || /^jobs:\s*$/.test(line)) hasTopLevel = true;
    if (/^\s+runs-on:\s*/.test(line) || /^\s+uses:\s*/.test(line)) hasJobKey = true;
    if (hasTopLevel && hasJobKey) return true;
  }
  return false;
}

function lineFromIndex(content: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

function snippetAt(content: string, idx: number): string {
  const start = content.lastIndexOf("\n", idx) + 1;
  const end = content.indexOf("\n", idx);
  const line = content.slice(start, end === -1 ? undefined : end).trim();
  return line.length > 180 ? line.slice(0, 179) + "…" : line;
}

export function scanGithubWorkflow(content: string): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const rule of GITHUB_RULES) {
    if (rule.absence) {
      if (!rule.re.test(content)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          line: 1,
          rationale: rule.rationale,
          fix: rule.fix,
          snippet: "",
        });
      }
      continue;
    }
    const re = new RegExp(rule.re.source, rule.re.flags.includes("g") ? rule.re.flags : rule.re.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        category: rule.category,
        title: rule.title,
        line: lineFromIndex(content, m.index),
        rationale: rule.rationale,
        fix: rule.fix,
        snippet: snippetAt(content, m.index),
      });
      if (!re.global) break;
      // Avoid zero-width infinite loops.
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}

export async function runScanGithub(input: ScanGithubInput): Promise<ScanGithubOutput> {
  const reports: ScanGithubFileReport[] = [];

  const gather = (path: string, content: string) => {
    if (!detectGithubWorkflow(path, content)) return;
    const findings = scanGithubWorkflow(content);
    reports.push({ path, findings });
  };

  if (input.files) {
    for (const f of input.files) gather(f.path, f.content);
  }
  if (input.paths) {
    for (const p of input.paths) {
      try {
        const content = await readFile(p, "utf8");
        gather(p, content);
      } catch { /* ignore unreadable */ }
    }
  }

  const bySeverity: Record<GithubSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) { total++; bySeverity[f.severity]++; }

  return {
    files: reports,
    summary: { filesScanned: reports.length, totalFindings: total, bySeverity },
  };
}

export function formatGithubReport(out: ScanGithubOutput): string {
  const { summary, files } = out;
  if (summary.filesScanned === 0) return "No GitHub Actions workflow files found.";
  const lines: string[] = [];
  lines.push(
    summary.totalFindings === 0
      ? `scan_github: no issues across ${summary.filesScanned} workflow${summary.filesScanned === 1 ? "" : "s"}.`
      : `scan_github: ${summary.totalFindings} findings across ${summary.filesScanned} workflow${summary.filesScanned === 1 ? "" : "s"} (${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
  );
  lines.push("");
  for (const file of files) {
    if (file.findings.length === 0) continue;
    lines.push(`${file.path}`);
    for (const f of file.findings) {
      lines.push(`  [${f.severity.toUpperCase()}] L${f.line}  ${f.title}  (${f.ruleId})`);
      if (f.snippet) lines.push(`      ${f.snippet}`);
      lines.push(`      why: ${f.rationale}`);
      lines.push(`      fix: ${f.fix}`);
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
