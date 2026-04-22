import { getClaudeClient, extractJson, type ClaudeClient } from "../engines/claude-client.js";
import { findSqlSuspects, type SqlSuspect } from "../engines/sql-prefilter.js";

export interface ScanSqliInput {
  code: string;
  language?: string;
  path?: string;
  model?: string;
}

export type SqliSeverity = "critical" | "high" | "medium" | "low";

export interface SqliFinding {
  name: string;
  severity: SqliSeverity;
  line: number | null;
  description: string;
  exploit: string;
  fix: string;
  fixedCode?: string;
}

export interface ScanSqliOutput {
  analyzed: boolean;
  reason?: string;
  model?: string;
  suspects: SqlSuspect[];
  findings: SqliFinding[];
  summary: string;
}

export const DEFAULT_SQLI_MODEL = process.env.SECUREMCP_SQL_MODEL ?? "claude-sonnet-4-5";

const SYSTEM_PROMPT = `You are a senior application-security engineer performing a focused code review for SQL injection and related query-construction defects.

Scope:
- Classic SQL injection via string concatenation, template literals, f-strings, %-formatting, str.format, sprintf.
- ORM raw / unsafeRaw / queryRaw / $queryRaw / knex.raw / sequelize.query with interpolated input.
- Second-order injection (untrusted data stored, then concatenated into a query later).
- Queries built from user input that would bypass parameterization (dynamic identifiers, ORDER BY injection).
- NoSQL injection that mirrors SQL patterns (Mongo $where, query object built from req.body).

Out of scope here (other tools own these):
- XSS, CSRF, auth logic, secrets, vulnerable dependencies.

A regex pre-filter has flagged likely query-construction sites; they are passed to you under "Suspects". Use them to focus, but you MAY flag additional issues or dismiss false positives with a justification.

Output format — return ONLY a single JSON object, no prose, no markdown fences:
{
  "findings": [
    {
      "name": "Short name",
      "severity": "critical" | "high" | "medium" | "low",
      "line": <integer line number or null>,
      "description": "Two or three sentences explaining the defect.",
      "exploit": "Concrete attacker payload or HTTP request.",
      "fix": "Two or three sentences describing the correct remediation.",
      "fixedCode": "Minimal corrected snippet, <= 8 lines, same language."
    }
  ],
  "summary": "One sentence overall assessment."
}

Rules:
- Empty "findings" array if code is safe.
- Prefer parameterized queries in the fix; identifier allow-lists for dynamic table/column names.
- Do not flag queries that are clearly parameterized.`;

interface ClaudeSqliResponse {
  findings?: Array<Partial<SqliFinding>>;
  summary?: string;
}

export async function runScanSqli(
  input: ScanSqliInput,
  client?: ClaudeClient,
): Promise<ScanSqliOutput> {
  const code = input.code ?? "";
  if (!code.trim()) {
    return { analyzed: false, reason: "empty input", suspects: [], findings: [], summary: "No code provided." };
  }

  const suspects = findSqlSuspects(code);
  if (suspects.length === 0) {
    return {
      analyzed: false,
      reason: "no SQL query-construction patterns detected",
      suspects: [],
      findings: [],
      summary: "Pre-filter found no concatenated or interpolated query construction; skipped deep analysis.",
    };
  }

  const language = input.language ?? "code";
  const model = input.model ?? DEFAULT_SQLI_MODEL;
  const suspectBlock = suspects
    .map((s, i) => `  ${i + 1}. L${s.line} — ${s.reason}\n     ${s.snippet}`)
    .join("\n");

  const user = `Language: ${language}${input.path ? `\nFile: ${input.path}` : ""}

Suspects (from pre-filter):
${suspectBlock}

Full source:
\`\`\`${language}
${code}
\`\`\``;

  const api = client ?? getClaudeClient();
  const raw = await api.analyze({
    model,
    system: SYSTEM_PROMPT,
    user,
    maxTokens: 2048,
    temperature: 0,
  });

  const parsed = extractJson<ClaudeSqliResponse>(raw);
  const findings: SqliFinding[] = (parsed.findings ?? []).map((f) => ({
    name: String(f.name ?? "Unnamed SQL injection finding"),
    severity: (f.severity as SqliSeverity) ?? "medium",
    line: typeof f.line === "number" ? f.line : null,
    description: String(f.description ?? ""),
    exploit: String(f.exploit ?? ""),
    fix: String(f.fix ?? ""),
    fixedCode: f.fixedCode ? String(f.fixedCode) : undefined,
  }));

  return {
    analyzed: true,
    model,
    suspects,
    findings,
    summary: String(parsed.summary ?? (findings.length === 0 ? "No injection issues detected." : "")),
  };
}

export function formatSqliReport(out: ScanSqliOutput): string {
  if (!out.analyzed) return out.summary;
  const lines: string[] = [];
  lines.push(`SQLi review via ${out.model} — ${out.suspects.length} suspect${out.suspects.length === 1 ? "" : "s"}, ${out.findings.length} confirmed.`);
  lines.push("");
  if (out.findings.length === 0) {
    lines.push("No confirmed SQL injection defects. Pre-filter suspects reviewed:");
    for (const s of out.suspects) lines.push(`  L${s.line}: ${s.reason}`);
    if (out.summary) lines.push(`\nSummary: ${out.summary}`);
    return lines.join("\n");
  }
  for (const f of out.findings) {
    lines.push(`[${f.severity.toUpperCase()}]${f.line !== null ? ` L${f.line}` : ""}  ${f.name}`);
    lines.push(`  What: ${f.description}`);
    lines.push(`  Exploit: ${f.exploit}`);
    lines.push(`  Fix: ${f.fix}`);
    if (f.fixedCode) {
      lines.push("  Fixed code:");
      for (const fl of f.fixedCode.split("\n")) lines.push(`    ${fl}`);
    }
    lines.push("");
  }
  if (out.summary) lines.push(`Summary: ${out.summary}`);
  return lines.join("\n").trimEnd();
}
