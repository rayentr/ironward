/**
 * Shared issue body template used by both Linear and Jira reporters.
 *
 * Produces a consistent layout across trackers so that triagers can recognise
 * an Ironward-filed issue at a glance regardless of where it lands.
 */

import type { NormalizedFinding } from "../engines/sarif.js";

export type LinearPriorityLabel = "Urgent" | "High" | "Medium" | "Low";
export type JiraPriorityName = "Highest" | "High" | "Medium" | "Low";

export interface IssueTemplate {
  title: string;
  bodyMarkdown: string;
  bodyJiraMarkup: string;
  priorityLabel: LinearPriorityLabel;
  jiraPriorityName: JiraPriorityName;
  labels: string[];
}

const SEVERITY_EMOJI: Record<NormalizedFinding["severity"], string> = {
  critical: "[CRITICAL]",
  high: "[HIGH]",
  medium: "[MEDIUM]",
  low: "[LOW]",
  info: "[INFO]",
};

const LINEAR_PRIORITY: Record<NormalizedFinding["severity"], LinearPriorityLabel> = {
  critical: "Urgent",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Low",
};

const JIRA_PRIORITY: Record<NormalizedFinding["severity"], JiraPriorityName> = {
  critical: "Highest",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Low",
};

function severityHeader(finding: NormalizedFinding): string {
  const emoji = SEVERITY_EMOJI[finding.severity];
  const cvss = finding.exploit?.cvss != null ? finding.exploit.cvss.toFixed(1) : "—";
  return `${emoji} ${finding.severity.toUpperCase()} — CVSS ${cvss}`;
}

function buildMarkdown(finding: NormalizedFinding): string {
  const ex = finding.exploit;
  const poc = ex?.poc?.trim() ? ex.poc : "(no proof-of-concept available — see rule rationale)";
  const fix = ex?.remediation?.trim() ? ex.remediation : "(see rule remediation guidance)";

  const refLines: string[] = [];
  if (ex?.owasp) refLines.push(`- OWASP: ${ex.owasp}`);
  if (ex?.cwe) refLines.push(`- ${ex.cwe}`);
  refLines.push(`- Ironward rule: \`${finding.ruleId}\``);
  if (ex?.references?.length) {
    for (const r of ex.references) refLines.push(`- ${r}`);
  }

  return [
    `## Vulnerability`,
    `${finding.description}`,
    `Location: \`${finding.file}:${finding.line}\``,
    ``,
    `## Severity`,
    severityHeader(finding),
    ``,
    `## How an attacker exploits this`,
    "```",
    poc,
    "```",
    ``,
    `## Fix`,
    "```",
    fix,
    "```",
    ``,
    `## References`,
    ...refLines,
  ].join("\n");
}

function buildJiraMarkup(finding: NormalizedFinding): string {
  const ex = finding.exploit;
  const poc = ex?.poc?.trim() ? ex.poc : "(no proof-of-concept available — see rule rationale)";
  const fix = ex?.remediation?.trim() ? ex.remediation : "(see rule remediation guidance)";

  const refLines: string[] = [];
  if (ex?.owasp) refLines.push(`* OWASP: ${ex.owasp}`);
  if (ex?.cwe) refLines.push(`* ${ex.cwe}`);
  refLines.push(`* Ironward rule: {{${finding.ruleId}}}`);
  if (ex?.references?.length) {
    for (const r of ex.references) refLines.push(`* ${r}`);
  }

  return [
    `h2. Vulnerability`,
    `${finding.description}`,
    `Location: {{${finding.file}:${finding.line}}}`,
    ``,
    `h2. Severity`,
    severityHeader(finding),
    ``,
    `h2. How an attacker exploits this`,
    `{code}`,
    poc,
    `{code}`,
    ``,
    `h2. Fix`,
    `{code}`,
    fix,
    `{code}`,
    ``,
    `h2. References`,
    ...refLines,
  ].join("\n");
}

// Truncation cap used for both Markdown and Jira-markup bodies.
// Linear's hard limit is ~50k chars and Jira's is ~32k. 45k is a safety margin under both
// minus space for the truncation notice.
const MAX_BODY_CHARS = 45_000;
const TRUNCATION_NOTICE = "\n\n[...truncated for API limits. Full report: ironward scan .]";

function capBody(body: string): string {
  if (body.length <= MAX_BODY_CHARS) return body;
  return body.slice(0, MAX_BODY_CHARS - TRUNCATION_NOTICE.length) + TRUNCATION_NOTICE;
}

export function buildIssue(
  finding: NormalizedFinding,
  opts?: { extraLabels?: string[] },
): IssueTemplate {
  const ruleTitle = finding.title || finding.ruleId;
  const title = `[SECURITY] ${ruleTitle} in ${finding.file}`;
  const bodyMarkdown = capBody(buildMarkdown(finding));
  const bodyJiraMarkup = capBody(buildJiraMarkup(finding));
  const priorityLabel = LINEAR_PRIORITY[finding.severity];
  const jiraPriorityName = JIRA_PRIORITY[finding.severity];
  const labels = ["security", finding.severity, ...(opts?.extraLabels ?? [])];
  return { title, bodyMarkdown, bodyJiraMarkup, priorityLabel, jiraPriorityName, labels };
}

/** Linear priority enum values: 1=Urgent, 2=High, 3=Medium, 4=Low. */
export function linearPriorityNumber(label: LinearPriorityLabel): 1 | 2 | 3 | 4 {
  switch (label) {
    case "Urgent": return 1;
    case "High": return 2;
    case "Medium": return 3;
    case "Low": return 4;
  }
}
