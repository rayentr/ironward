import { getClaudeClient, extractJson, type ClaudeClient } from "../engines/claude-client.js";
import {
  findIdorSuspects,
  ownershipHintCount,
  type IdorSuspect,
} from "../engines/idor-prefilter.js";

export interface ScanIdorInput {
  code: string;
  language?: string;
  path?: string;
  model?: string;
}

export type IdorSeverity = "critical" | "high" | "medium" | "low";

export interface IdorFinding {
  name: string;
  kind:
    | "missing_ownership"
    | "horizontal_escalation"
    | "mass_assignment"
    | "predictable_id"
    | "unprotected_admin"
    | "role_from_input"
    | "other";
  severity: IdorSeverity;
  line: number | null;
  description: string;
  exploit: string;
  fix: string;
  fixedCode?: string;
}

export interface ScanIdorOutput {
  analyzed: boolean;
  reason?: string;
  model?: string;
  suspects: IdorSuspect[];
  ownershipHintCount: number;
  findings: IdorFinding[];
  summary: string;
}

export const DEFAULT_IDOR_MODEL = process.env.IRONWARD_IDOR_MODEL ?? "claude-opus-4-5";

const SYSTEM_PROMPT = `You are a senior application-security engineer specializing in broken access control (OWASP A01) — the #1 category of web vulnerabilities.

Scope for this scan:
- **Missing ownership check** — a handler fetches a resource by ID from the request, and nothing in the flow verifies the requester owns (or is authorized to access) that resource.
- **Horizontal privilege escalation** — user A can read/modify user B's data by changing an ID in the URL, query, or body.
- **Mass assignment / overposting** — the handler spreads \`req.body\` (or equivalent) into an update, allowing an attacker to set fields that should be server-controlled (role, tenantId, credits, isAdmin, price, …).
- **Predictable / sequential IDs** — resources addressed by incrementing integers rather than unguessable UUIDs/opaque tokens.
- **Unprotected admin routes** — endpoints that perform privileged actions without a role check or with a role read from user input.
- **Role-from-input** — authorization decisions made on a flag that the client controls (header, body field).

Out of scope — other tools own these:
- SQL injection, XSS, hardcoded secrets, auth mechanism bugs (JWT validation, session fixation).

A regex pre-filter has surfaced suspicious sites under "Suspects". These are starting points — the real defect is often what is MISSING (an ownership filter that should be in the query).

You will also be told how many ownership-hint patterns the pre-filter saw in the file (e.g. \`userId: req.user.id\`, \`@login_required\`). A low hint count plus a suspect is a strong signal.

Reasoning rules:
- Trace the full request flow for each suspect. Ask: "Who is the user, and where is it verified they are allowed to touch THIS specific resource?"
- A login check (authentication) is not an ownership check (authorization). \`@login_required\` alone does not make an endpoint safe.
- Return an empty array if the code is safe. Don't invent defects.

Output format — return ONLY a single JSON object, no prose, no markdown fences:
{
  "findings": [
    {
      "name": "Short name (e.g. 'IDOR on PATCH /orders/:id — any authenticated user can modify any order')",
      "kind": "missing_ownership" | "horizontal_escalation" | "mass_assignment" | "predictable_id" | "unprotected_admin" | "role_from_input" | "other",
      "severity": "critical" | "high" | "medium" | "low",
      "line": <integer or null>,
      "description": "Two or three sentences on the missing check and the data flow.",
      "exploit": "Concrete attacker action: HTTP request + what they gain.",
      "fix": "Two or three sentences describing the correct authorization predicate.",
      "fixedCode": "Minimal corrected snippet, <= 8 lines, same language."
    }
  ],
  "summary": "One sentence overall assessment."
}`;

interface ClaudeIdorResponse {
  findings?: Array<Partial<IdorFinding>>;
  summary?: string;
}

export async function runScanIdor(
  input: ScanIdorInput,
  client?: ClaudeClient,
): Promise<ScanIdorOutput> {
  const code = input.code ?? "";
  if (!code.trim()) {
    return {
      analyzed: false,
      reason: "empty input",
      suspects: [],
      ownershipHintCount: 0,
      findings: [],
      summary: "No code provided.",
    };
  }

  const suspects = findIdorSuspects(code);
  const hints = ownershipHintCount(code);

  if (suspects.length === 0) {
    return {
      analyzed: false,
      reason: "no data-access patterns detected",
      suspects: [],
      ownershipHintCount: hints,
      findings: [],
      summary: "Pre-filter found no resource-by-ID fetches or admin routes; skipped deep analysis.",
    };
  }

  const language = input.language ?? "code";
  const model = input.model ?? DEFAULT_IDOR_MODEL;
  const suspectBlock = suspects
    .map((s, i) => `  ${i + 1}. L${s.line} — ${s.reason}\n     ${s.snippet}`)
    .join("\n");

  const user = `Language: ${language}${input.path ? `\nFile: ${input.path}` : ""}
Ownership-hint patterns observed in file: ${hints}

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

  const parsed = extractJson<ClaudeIdorResponse>(raw);
  const findings: IdorFinding[] = (parsed.findings ?? []).map((f) => ({
    name: String(f.name ?? "Unnamed access-control finding"),
    kind: (f.kind as IdorFinding["kind"]) ?? "other",
    severity: (f.severity as IdorSeverity) ?? "medium",
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
    ownershipHintCount: hints,
    findings,
    summary: String(
      parsed.summary ?? (findings.length === 0 ? "No access-control defects detected." : ""),
    ),
  };
}

export function formatIdorReport(out: ScanIdorOutput): string {
  if (!out.analyzed) return out.summary;
  const lines: string[] = [];
  lines.push(
    `IDOR review via ${out.model} — ${out.suspects.length} suspect${
      out.suspects.length === 1 ? "" : "s"
    }, ${out.ownershipHintCount} ownership hint${out.ownershipHintCount === 1 ? "" : "s"}, ${
      out.findings.length
    } confirmed.`,
  );
  lines.push("");
  if (out.findings.length === 0) {
    lines.push("No confirmed access-control defects. Pre-filter suspects reviewed:");
    for (const s of out.suspects) lines.push(`  L${s.line}: ${s.reason}`);
    if (out.summary) lines.push(`\nSummary: ${out.summary}`);
    return lines.join("\n");
  }
  for (const f of out.findings) {
    lines.push(
      `[${f.severity.toUpperCase()}] [${f.kind}]${f.line !== null ? ` L${f.line}` : ""}  ${f.name}`,
    );
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
