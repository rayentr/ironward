import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { DOCKER_RULES, type DockerRule, type DockerSeverity } from "../engines/docker-rules.js";

export type DockerFileKind = "dockerfile" | "compose";

export interface DockerFinding {
  ruleId: string;
  severity: DockerSeverity;
  category: DockerRule["category"];
  title: string;
  line: number;
  rationale: string;
  fix: string;
  snippet: string;
}

export interface ScanDockerFileReport {
  path: string;
  kind: DockerFileKind;
  findings: DockerFinding[];
}

export interface ScanDockerInput {
  files?: Array<{ path: string; content: string; kind?: DockerFileKind }>;
  paths?: string[];
}

export interface ScanDockerOutput {
  files: ScanDockerFileReport[];
  summary: {
    filesScanned: number;
    totalFindings: number;
    bySeverity: Record<DockerSeverity, number>;
  };
}

export function detectKind(path: string, content: string): DockerFileKind | null {
  const name = basename(path).toLowerCase();
  if (name === "dockerfile" || name.startsWith("dockerfile.") || name.endsWith(".dockerfile")) return "dockerfile";
  if (name === "docker-compose.yml" || name === "docker-compose.yaml" ||
      name === "compose.yml" || name === "compose.yaml" ||
      /^docker-compose\.[a-z0-9.-]+\.ya?ml$/.test(name)) {
    return "compose";
  }
  // Heuristic fallback by first line.
  const firstNonComment = content.split("\n").find((l) => l.trim() && !l.trim().startsWith("#"));
  if (firstNonComment) {
    if (/^\s*FROM\s+\S+/i.test(firstNonComment)) return "dockerfile";
    if (/^\s*(?:version|services|networks|volumes)\s*:/i.test(firstNonComment)) return "compose";
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

export function scanDockerfile(content: string, kind: DockerFileKind): DockerFinding[] {
  const findings: DockerFinding[] = [];
  for (const rule of DOCKER_RULES) {
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
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}

export async function runScanDocker(input: ScanDockerInput): Promise<ScanDockerOutput> {
  const reports: ScanDockerFileReport[] = [];

  const gather = async (path: string, content: string, kind?: DockerFileKind) => {
    const resolved = kind ?? detectKind(path, content);
    if (!resolved) return;
    const findings = scanDockerfile(content, resolved);
    reports.push({ path, kind: resolved, findings });
  };

  if (input.files) {
    for (const f of input.files) await gather(f.path, f.content, f.kind);
  }
  if (input.paths) {
    for (const p of input.paths) {
      try {
        const content = await readFile(p, "utf8");
        await gather(p, content);
      } catch { /* ignore unreadable */ }
    }
  }

  const bySeverity: Record<DockerSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) { total++; bySeverity[f.severity]++; }

  return {
    files: reports,
    summary: { filesScanned: reports.length, totalFindings: total, bySeverity },
  };
}

export function formatDockerReport(out: ScanDockerOutput): string {
  const { summary, files } = out;
  if (summary.filesScanned === 0) return "No Dockerfile or docker-compose files found.";
  const lines: string[] = [];
  lines.push(
    summary.totalFindings === 0
      ? `scan_docker: no issues across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"}.`
      : `scan_docker: ${summary.totalFindings} findings across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"} (${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
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
