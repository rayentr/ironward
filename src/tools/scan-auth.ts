import { getClaudeClient, extractJson, type ClaudeClient } from "../engines/claude-client.js";

export interface ScanAuthInput {
  code: string;
  language?: string;
  path?: string;
  model?: string;
}

export type AuthSeverity = "critical" | "high" | "medium" | "low";

export interface AuthFinding {
  name: string;
  severity: AuthSeverity;
  line: number | null;
  description: string;
  exploit: string;
  fix: string;
  fixedCode?: string;
}

export interface ScanAuthOutput {
  analyzed: boolean;
  reason?: string;
  model?: string;
  findings: AuthFinding[];
  summary: string;
}

const AUTH_KEYWORDS = [
  "login",
  "logout",
  "signin",
  "signup",
  "session",
  "cookie",
  "jwt",
  "token",
  "bearer",
  "authenticate",
  "authorize",
  "authoriz",
  "authz",
  "authn",
  "password",
  "credential",
  "permission",
  "role",
  "isadmin",
  "is_admin",
  "currentuser",
  "current_user",
  "req.user",
  "request.user",
  "getuser",
  "requireauth",
  "require_auth",
  "middleware",
  "guard",
  "ownership",
  "owner_id",
  "ownerid",
  "userid",
  "user_id",
];

function looksAuthRelated(code: string): boolean {
  const lower = code.toLowerCase();
  return AUTH_KEYWORDS.some((k) => lower.includes(k));
}

export const DEFAULT_AUTH_MODEL = process.env.SECUREMCP_AUTH_MODEL ?? "claude-opus-4-5";

const SYSTEM_PROMPT = `You are a senior application-security engineer performing a focused code review for authentication and authorization defects.

Scope:
- Backwards auth checks (e.g. \`if (user)\` when the intent is \`if (!user)\`)
- Missing ownership / tenancy checks (resource fetched by ID with no check that the caller owns it)
- Privilege-escalation paths (role comparison bugs, admin flags trusted from user input)
- Auth middleware that can be bypassed (registered after the route it is meant to protect, skipped on error paths, conditional on env flags)
- JWT validation gaps (no signature verification, alg=none accepted, audience/issuer unchecked, expiration unchecked)
- Session fixation / unsafe session handling (session id from user input, not rotated after login)
- Password-reset flaws (no token expiry, token guessable, plaintext passwords stored)

Out of scope — do NOT flag these here, they are handled by other tools:
- SQL injection, XSS, CSRF, input sanitization
- Hardcoded secrets
- Vulnerable dependencies

Output format — return ONLY a single JSON object, no prose, no markdown fences:
{
  "findings": [
    {
      "name": "Short name (e.g. 'Missing ownership check on order endpoint')",
      "severity": "critical" | "high" | "medium" | "low",
      "line": <integer line number of the primary defect, or null>,
      "description": "Two or three sentences explaining the defect in plain English.",
      "exploit": "Concrete attacker step-by-step. Name the HTTP request, parameter, or flow.",
      "fix": "Two or three sentences describing the correct behavior and how to get there.",
      "fixedCode": "Minimal corrected snippet, <= 8 lines, same language as the input."
    }
  ],
  "summary": "One sentence overall assessment."
}

Rules:
- Return an empty "findings" array if the code is safe.
- Be precise. Do not invent defects. If unsure, omit.
- Reason about the full request lifecycle, not individual lines in isolation.`;

interface ClaudeAuthResponse {
  findings?: Array<Partial<AuthFinding>>;
  summary?: string;
}

export async function runScanAuth(
  input: ScanAuthInput,
  client: ClaudeClient = getClaudeClient(),
): Promise<ScanAuthOutput> {
  const code = input.code ?? "";
  if (!code.trim()) {
    return { analyzed: false, reason: "empty input", findings: [], summary: "No code provided." };
  }
  if (!looksAuthRelated(code)) {
    return {
      analyzed: false,
      reason: "no auth-related keywords detected",
      findings: [],
      summary: "Code does not reference authentication or authorization; skipped deep analysis.",
    };
  }

  const language = input.language ?? "code";
  const model = input.model ?? DEFAULT_AUTH_MODEL;
  const user = `Language: ${language}${input.path ? `\nFile: ${input.path}` : ""}

\`\`\`${language}
${code}
\`\`\``;

  const raw = await client.analyze({
    model,
    system: SYSTEM_PROMPT,
    user,
    maxTokens: 2048,
    temperature: 0,
  });

  const parsed = extractJson<ClaudeAuthResponse>(raw);
  const findings: AuthFinding[] = (parsed.findings ?? []).map((f) => ({
    name: String(f.name ?? "Unnamed auth finding"),
    severity: (f.severity as AuthSeverity) ?? "medium",
    line: typeof f.line === "number" ? f.line : null,
    description: String(f.description ?? ""),
    exploit: String(f.exploit ?? ""),
    fix: String(f.fix ?? ""),
    fixedCode: f.fixedCode ? String(f.fixedCode) : undefined,
  }));

  return {
    analyzed: true,
    model,
    findings,
    summary: String(parsed.summary ?? (findings.length === 0 ? "No auth issues detected." : "")),
  };
}

export function formatAuthReport(out: ScanAuthOutput): string {
  if (!out.analyzed) return out.summary;
  if (out.findings.length === 0) return `No auth-logic issues found.\n${out.summary}`;
  const lines: string[] = [];
  lines.push(`Auth review via ${out.model} — ${out.findings.length} issue${out.findings.length === 1 ? "" : "s"}.`);
  lines.push("");
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
