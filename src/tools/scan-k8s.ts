import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { K8S_RULES, type K8sRule, type K8sSeverity } from "../engines/k8s-rules.js";

export interface K8sFinding {
  ruleId: string;
  severity: K8sSeverity;
  category: K8sRule["category"];
  title: string;
  line: number;
  rationale: string;
  fix: string;
  snippet: string;
}

export interface ScanK8sFileReport {
  path: string;
  findings: K8sFinding[];
}

export interface ScanK8sInput {
  files?: Array<{ path: string; content: string }>;
  paths?: string[];
}

export interface ScanK8sOutput {
  files: ScanK8sFileReport[];
  summary: {
    filesScanned: number;
    totalFindings: number;
    bySeverity: Record<K8sSeverity, number>;
  };
}

const K8S_KIND_RE = /^kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Service|Ingress|ConfigMap|Secret|ServiceAccount|Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|CustomResourceDefinition)\b/m;
const K8S_APIVERSION_RE = /^apiVersion\s*:\s*(?:v1|apps\/|batch\/|networking\.k8s\.io\/|rbac\.authorization\.k8s\.io\/|policy\/|autoscaling\/)/m;

const WORKLOAD_KIND_RE = /^kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)\b/m;
const CONTAINERS_RE = /^\s*containers\s*:/m;

export function detectK8s(path: string, content: string): boolean {
  const name = basename(path).toLowerCase();
  if (!(name.endsWith(".yaml") || name.endsWith(".yml"))) return false;
  if (K8S_KIND_RE.test(content)) return true;
  if (K8S_APIVERSION_RE.test(content)) return true;
  return false;
}

function hasPodSpec(content: string): boolean {
  return WORKLOAD_KIND_RE.test(content) || CONTAINERS_RE.test(content);
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

/**
 * Scans a single K8s manifest and returns all findings, sorted by line.
 * Absence-rules that target PodSpec fields only fire when the manifest contains
 * a workload kind or a `containers:` block — otherwise they are suppressed.
 */
export function scanK8sManifest(content: string): K8sFinding[] {
  const findings: K8sFinding[] = [];
  const isWorkload = hasPodSpec(content);

  // ── Special composite rule: k8s-run-as-root ──
  // Fires if:
  //   (a) there is an explicit `runAsUser: 0`, OR
  //   (b) this is a workload and `runAsNonRoot: true` is absent.
  if (isWorkload) {
    const runAsUserZero = /^\s*runAsUser\s*:\s*0\b/m.exec(content);
    const runAsNonRoot = /^\s*runAsNonRoot\s*:\s*true\b/m.test(content);
    const rule = K8S_RULES.find((r) => r.id === "k8s-run-as-root");
    if (rule) {
      if (runAsUserZero) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          line: lineFromIndex(content, runAsUserZero.index),
          rationale: rule.rationale,
          fix: rule.fix,
          snippet: snippetAt(content, runAsUserZero.index),
        });
      } else if (!runAsNonRoot) {
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
    }
  }

  for (const rule of K8S_RULES) {
    // The composite run-as-root rule is handled above.
    if (rule.id === "k8s-run-as-root") continue;

    // Gate PodSpec-only rules on files that actually have a PodSpec.
    if (!isWorkload && rule.appliesTo.includes("workload")) continue;

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
      if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width
    }
  }

  return findings.sort((a, b) => a.line - b.line);
}

export async function runScanK8s(input: ScanK8sInput): Promise<ScanK8sOutput> {
  const reports: ScanK8sFileReport[] = [];

  const gather = (path: string, content: string) => {
    if (!detectK8s(path, content)) return;
    const findings = scanK8sManifest(content);
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

  const bySeverity: Record<K8sSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) { total++; bySeverity[f.severity]++; }

  return {
    files: reports,
    summary: { filesScanned: reports.length, totalFindings: total, bySeverity },
  };
}

export function formatK8sReport(out: ScanK8sOutput): string {
  const { summary, files } = out;
  if (summary.filesScanned === 0) return "No Kubernetes manifests found.";
  const lines: string[] = [];
  lines.push(
    summary.totalFindings === 0
      ? `scan_k8s: no issues across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"}.`
      : `scan_k8s: ${summary.totalFindings} findings across ${summary.filesScanned} file${summary.filesScanned === 1 ? "" : "s"} (${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.medium} medium, ${summary.bySeverity.low} low).`,
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
