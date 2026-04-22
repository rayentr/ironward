import { readFile } from "node:fs/promises";
import { INFRA_RULES, type InfraRule, type InfraSeverity, type InfraFileKind } from "../engines/infra-rules.js";

export interface InfraFinding {
  ruleId: string;
  severity: InfraSeverity;
  category: InfraRule["category"];
  title: string;
  line: number;
  rationale: string;
  fix: string;
  snippet: string;
}

export interface ScanInfraFileReport {
  path: string;
  kind: InfraFileKind;
  findings: InfraFinding[];
}

export interface ScanInfraInput {
  files?: Array<{ path: string; content: string; kind?: InfraFileKind }>;
  paths?: string[];
}

export interface ScanInfraOutput {
  files: ScanInfraFileReport[];
  summary: {
    filesScanned: number;
    totalFindings: number;
    bySeverity: Record<InfraSeverity, number>;
  };
}

export function detectInfraKind(path: string, content: string): InfraFileKind | null {
  const lower = path.toLowerCase();
  if (lower.endsWith(".tf") || lower.endsWith(".tf.json")) return "terraform";
  if ((lower.endsWith(".yml") || lower.endsWith(".yaml") || lower.endsWith(".json")) &&
      (/AWSTemplateFormatVersion/.test(content) ||
       (/"Resources"\s*:/.test(content) && /"Type"\s*:\s*"AWS::/.test(content)) ||
       (/Resources\s*:/m.test(content) && /Type\s*:\s*AWS::/m.test(content)))) {
    return "cloudformation";
  }
  return null;
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

export function scanInfraFile(content: string, kind: InfraFileKind): InfraFinding[] {
  const findings: InfraFinding[] = [];
  for (const rule of INFRA_RULES) {
    if (!rule.appliesTo.includes(kind)) continue;
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
    const seen = new Set<number>();
    while ((m = re.exec(content)) !== null) {
      if (seen.has(m.index)) break;
      seen.add(m.index);
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
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}

export async function runScanInfra(input: ScanInfraInput): Promise<ScanInfraOutput> {
  const reports: ScanInfraFileReport[] = [];

  const gather = async (path: string, content: string, kind?: InfraFileKind) => {
    const resolved = kind ?? detectInfraKind(path, content);
    if (!resolved) return;
    const findings = scanInfraFile(content, resolved);
    reports.push({ path, kind: resolved, findings });
  };

  if (input.files) for (const f of input.files) await gather(f.path, f.content, f.kind);
  if (input.paths) {
    for (const p of input.paths) {
      try {
        const content = await readFile(p, "utf8");
        await gather(p, content);
      } catch { /* ignore */ }
    }
  }

  const bySeverity: Record<InfraSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) { total++; bySeverity[f.severity]++; }

  return { files: reports, summary: { filesScanned: reports.length, totalFindings: total, bySeverity } };
}

export function formatInfraReport(out: ScanInfraOutput): string {
  const { summary, files } = out;
  if (summary.filesScanned === 0) return "No Terraform or CloudFormation files found.";
  const lines: string[] = [];
  lines.push(
    summary.totalFindings === 0
      ? `scan_infra: no issues across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"}.`
      : `scan_infra: ${summary.totalFindings} findings across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"} (${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
  );
  lines.push("");
  for (const file of files) {
    if (file.findings.length === 0) continue;
    lines.push(`${file.path}  (${file.kind})`);
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
