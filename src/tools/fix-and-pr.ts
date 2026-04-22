import { createHash } from "node:crypto";
import { getClaudeClient, extractJson, type ClaudeClient } from "../engines/claude-client.js";
import {
  GitHubRestClient,
  parseRepoSlug,
  type GitHubClient,
} from "../engines/github-client.js";

export interface FixFinding {
  name: string;
  description?: string;
  exploit?: string;
  fix?: string;
  severity?: string;
  line?: number | null;
  tool?: string;
}

export interface FileInput {
  path: string;
  content: string;
}

export interface FixAndPrInput {
  repo: string;
  finding: FixFinding;
  filePath?: string;
  fileContent?: string;
  files?: Array<{ path: string; content?: string }>;
  language?: string;
  branchName?: string;
  baseBranch?: string;
  commitMessage?: string;
  model?: string;
  dryRun?: boolean;
  skipValidation?: boolean;
  maxValidationAttempts?: number;
}

export interface FixedFileReport {
  path: string;
  originalContent: string;
  fixedContent: string;
  changed: boolean;
  existingSha?: string;
}

export interface ValidationResult {
  passed: boolean;
  residual: string[];
}

export interface Validator {
  validate(files: FileInput[], finding: FixFinding): Promise<ValidationResult>;
}

export interface FixAndPrOutput {
  dryRun: boolean;
  branch?: string;
  commitMessage: string;
  prTitle: string;
  prBody: string;
  files: FixedFileReport[];
  validation?: { attempts: number; passed: boolean; residual: string[] };
  prUrl?: string;
  prNumber?: number;
  notes: string[];
  originalContent?: string;
  fixedContent?: string;
}

export const DEFAULT_FIX_MODEL = process.env.IRONWARD_FIX_MODEL ?? "claude-opus-4-5";

const OWASP_LINKS: Record<string, string> = {
  scan_for_secrets:
    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
  scan_sqli: "https://owasp.org/Top10/A03_2021-Injection/",
  scan_xss: "https://owasp.org/Top10/A03_2021-Injection/",
  scan_idor: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
  scan_auth_logic: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
  scan_deps: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  scan_url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
};

const SYSTEM_PROMPT = `You are a senior application-security engineer producing a minimal, surgical fix for a known security defect. The fix may span one or more files.

Rules:
- Change the minimum code necessary to fix the specific finding described.
- Preserve every unrelated line exactly — comments, blank lines, imports, formatting.
- Do not refactor, rename, reorder, or "improve" unrelated code.
- Do not add new dependencies unless absolutely required; if you must, explain in the summary.
- If a file does NOT need changes, return it with its original content unchanged.
- If you are unsure how to fix safely, return every file unchanged and explain why in the summary.

Output format — return ONLY a single JSON object, no prose, no markdown fences:
{
  "fixed_files": [
    { "path": "<same path as input>", "content": "<the full updated file contents as a string>" }
  ],
  "summary": "One sentence on what you changed across all files and why."
}`;

const RETRY_SYSTEM_PROMPT = `${SYSTEM_PROMPT}

The previous attempt did not fully remediate the finding. Pay closer attention to the validation residual listed in the user message and eliminate the root cause.`;

interface ClaudeFixResponse {
  fixed_files?: Array<{ path?: string; content?: string }>;
  fixedFiles?: Array<{ path?: string; content?: string }>;
  fixed_content?: string;
  fixedContent?: string;
  summary?: string;
}

function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function shortHash(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 7);
}

function normalizeInputFiles(input: FixAndPrInput): Array<{ path: string; content?: string }> {
  if (input.files && input.files.length > 0) {
    return input.files.map((f) => ({ path: f.path, content: f.content }));
  }
  if (input.filePath) {
    return [{ path: input.filePath, content: input.fileContent }];
  }
  throw new Error("Provide either `files: [{path, content}]` or `filePath` + optional `fileContent`.");
}

function buildUserPrompt(
  finding: FixFinding,
  language: string,
  files: Array<{ path: string; content: string }>,
  retryContext?: { attempt: number; residual: string[] },
): string {
  const header = [
    `Language: ${language}`,
    `Finding (tool: ${finding.tool ?? "unspecified"}, severity: ${finding.severity ?? "unspecified"}):`,
    `Name: ${finding.name}`,
    finding.description ? `Description: ${finding.description}` : "",
    finding.exploit ? `Exploit: ${finding.exploit}` : "",
    finding.fix ? `Guidance: ${finding.fix}` : "",
    finding.line != null ? `Primary line: ${finding.line}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const fileBlocks = files
    .map(
      (f) =>
        `--- FILE: ${f.path} ---\n\`\`\`${language}\n${f.content}\n\`\`\``,
    )
    .join("\n\n");

  if (retryContext) {
    const residual = retryContext.residual.join("\n  - ");
    return `${header}

This is retry attempt ${retryContext.attempt}. Validation residual after the last fix:
  - ${residual}

Files to (re-)fix:

${fileBlocks}`;
  }

  return `${header}

Files to fix:

${fileBlocks}`;
}

function parseFixResponse(
  raw: string,
  requestedPaths: string[],
): { files: Array<{ path: string; content: string }>; summary: string } {
  const parsed = extractJson<ClaudeFixResponse>(raw);
  const summary = parsed.summary ?? "";
  const arr = parsed.fixed_files ?? parsed.fixedFiles;
  if (Array.isArray(arr) && arr.length > 0) {
    const files = arr
      .filter((f) => typeof f.path === "string" && typeof f.content === "string")
      .map((f) => ({ path: f.path as string, content: f.content as string }));
    return { files, summary };
  }
  const single = parsed.fixed_content ?? parsed.fixedContent;
  if (typeof single === "string" && single.length > 0 && requestedPaths.length === 1) {
    return { files: [{ path: requestedPaths[0], content: single }], summary };
  }
  throw new Error("Model did not return fixed_files.");
}

async function fetchMissingFileContents(
  requested: Array<{ path: string; content?: string }>,
  owner: string,
  repo: string,
  baseBranch: string,
  gh: GitHubClient,
  notes: string[],
): Promise<Array<FileInput & { existingSha?: string }>> {
  const out: Array<FileInput & { existingSha?: string }> = [];
  for (const f of requested) {
    if (f.content !== undefined) {
      out.push({ path: f.path, content: f.content });
      continue;
    }
    const fetched = await gh.getFile(owner, repo, f.path, baseBranch);
    notes.push(
      `Fetched ${f.path} from ${owner}/${repo}@${baseBranch} (sha ${fetched.sha?.slice(0, 7)}).`,
    );
    out.push({ path: f.path, content: fetched.content, existingSha: fetched.sha });
  }
  return out;
}

function buildPrBody(
  finding: FixFinding,
  summary: string,
  model: string,
  fileCount: number,
  validation?: FixAndPrOutput["validation"],
): string {
  const owaspLink = finding.tool ? OWASP_LINKS[finding.tool] : undefined;
  const sev = finding.severity ? ` (${finding.severity})` : "";
  const filesLine = fileCount > 1 ? `\nFiles changed: ${fileCount}` : "";
  const validationLine = validation
    ? `\nValidation: ${validation.passed ? "passed" : "residual findings remain — see below"} after ${validation.attempts} attempt${validation.attempts === 1 ? "" : "s"}.`
    : "";
  const sections = [
    `## Vulnerability${sev}`,
    finding.description ?? finding.name,
    owaspLink ? `\nReference: [${finding.tool} · OWASP](${owaspLink})` : "",
    filesLine,
    "",
    finding.exploit ? `## How it was exploitable\n${finding.exploit}\n` : "",
    `## How this PR fixes it`,
    summary,
    validationLine,
    validation && !validation.passed && validation.residual.length
      ? `\n<details><summary>Residual findings</summary>\n\n- ${validation.residual.join("\n- ")}\n\n</details>`
      : "",
    "",
    `_Generated by Ironward \`fix_and_pr\` using \`${model}\`. Review carefully before merging._`,
  ].filter(Boolean);
  return sections.join("\n");
}

export async function runFixAndPr(
  input: FixAndPrInput,
  deps: { claude?: ClaudeClient; github?: GitHubClient; validator?: Validator } = {},
): Promise<FixAndPrOutput> {
  const { owner, repo } = parseRepoSlug(input.repo);
  const language = input.language ?? "code";
  const model = input.model ?? DEFAULT_FIX_MODEL;
  const dryRun = input.dryRun ?? false;
  const skipValidation = input.skipValidation ?? false;
  const maxAttempts = Math.max(1, Math.min(3, input.maxValidationAttempts ?? 2));
  const notes: string[] = [];

  const requested = normalizeInputFiles(input);
  const anyContentMissing = requested.some((f) => f.content === undefined);

  let baseBranch = input.baseBranch;
  const needsGithub = anyContentMissing || !baseBranch || !dryRun;
  const gh: GitHubClient | null = deps.github ?? (needsGithub ? new GitHubRestClient() : null);

  if (anyContentMissing || !baseBranch) {
    if (!gh) throw new Error("GitHub client required when file content or base branch is missing.");
    if (!baseBranch) baseBranch = await gh.getDefaultBranch(owner, repo);
  }

  const originalFiles: Array<FileInput & { existingSha?: string }> = await (async () => {
    if (anyContentMissing) {
      if (!gh || !baseBranch) throw new Error("Unreachable");
      return fetchMissingFileContents(requested, owner, repo, baseBranch, gh, notes);
    }
    return requested.map((f) => ({ path: f.path, content: f.content as string }));
  })();

  const claude = deps.claude ?? getClaudeClient();

  let fixedPairs: Array<{ path: string; content: string }> = [];
  let summary = "";
  let validation: FixAndPrOutput["validation"];
  let residual: string[] = [];

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const prompt = buildUserPrompt(
      input.finding,
      language,
      originalFiles.map((f) => ({ path: f.path, content: f.content })),
      attempt > 1 ? { attempt, residual } : undefined,
    );
    const raw = await claude.analyze({
      model,
      system: attempt > 1 ? RETRY_SYSTEM_PROMPT : SYSTEM_PROMPT,
      user: prompt,
      maxTokens: 4096,
      temperature: 0,
    });
    const parsed = parseFixResponse(raw, originalFiles.map((f) => f.path));
    fixedPairs = parsed.files;
    summary = parsed.summary || `Fix: ${input.finding.name}`;

    if (skipValidation || !deps.validator) {
      validation = undefined;
      break;
    }
    const v = await deps.validator.validate(
      fixedPairs.map((f) => ({ path: f.path, content: f.content })),
      input.finding,
    );
    residual = v.residual;
    validation = { attempts: attempt, passed: v.passed, residual: v.residual };
    if (v.passed) break;
    if (attempt < maxAttempts) {
      notes.push(`Attempt ${attempt} validation failed; retrying.`);
    }
  }

  const reports: FixedFileReport[] = originalFiles.map((orig) => {
    const fixed = fixedPairs.find((f) => f.path === orig.path);
    const fixedContent = fixed ? fixed.content : orig.content;
    return {
      path: orig.path,
      originalContent: orig.content,
      fixedContent,
      changed: fixedContent !== orig.content,
      existingSha: orig.existingSha,
    };
  });

  const changedCount = reports.filter((r) => r.changed).length;
  if (changedCount === 0) {
    notes.push("Model returned no changes across all files; no PR will be opened.");
  }

  const branch =
    input.branchName ??
    `ironward/fix-${slug(input.finding.name)}-${shortHash(
      reports.map((r) => r.originalContent).join("\n---\n") + input.finding.name,
    )}`;
  const commitMessage =
    input.commitMessage ?? `fix(security): ${input.finding.name.slice(0, 72)}`;
  const prTitle = commitMessage;
  const prBody = buildPrBody(input.finding, summary, model, reports.length, validation);

  const out: FixAndPrOutput = {
    dryRun,
    branch: dryRun ? undefined : branch,
    commitMessage,
    prTitle,
    prBody,
    files: reports,
    validation,
    notes,
  };
  if (reports.length === 1) {
    out.originalContent = reports[0].originalContent;
    out.fixedContent = reports[0].fixedContent;
  }

  if (dryRun) {
    out.notes.push("Dry run — no branch or PR created.");
    return out;
  }
  if (changedCount === 0) return out;
  if (validation && !validation.passed) {
    out.notes.push("Validation did not pass after retries — refusing to open PR. Use `skipValidation: true` to override.");
    return out;
  }

  if (!gh) throw new Error("GitHub client required to open PR.");
  if (!baseBranch) baseBranch = await gh.getDefaultBranch(owner, repo);
  await gh.createBranch(owner, repo, branch, baseBranch);
  for (const r of reports) {
    if (!r.changed) continue;
    await gh.upsertFile(owner, repo, branch, r.path, r.fixedContent, commitMessage, r.existingSha);
  }
  const pr = await gh.createPullRequest(owner, repo, {
    title: prTitle,
    body: prBody,
    head: branch,
    base: baseBranch,
  });
  out.prUrl = pr.url;
  out.prNumber = pr.number;
  out.notes.push(`PR #${pr.number} opened: ${pr.url}`);
  return out;
}

export function formatFixReport(out: FixAndPrOutput): string {
  const lines: string[] = [];
  if (out.dryRun) lines.push("Dry run — fix proposed, not submitted.");
  lines.push(`Commit: ${out.commitMessage}`);
  if (out.branch) lines.push(`Branch: ${out.branch}`);
  if (out.prUrl) lines.push(`PR: ${out.prUrl}`);
  const changed = out.files.filter((f) => f.changed);
  lines.push(
    `Files: ${out.files.length} total, ${changed.length} changed${
      changed.length ? ` — ${changed.map((f) => f.path).join(", ")}` : ""
    }`,
  );
  if (out.validation) {
    lines.push(
      `Validation: ${out.validation.passed ? "passed" : "failed"} after ${out.validation.attempts} attempt${
        out.validation.attempts === 1 ? "" : "s"
      }${out.validation.residual.length ? ` — residual: ${out.validation.residual.join("; ")}` : ""}`,
    );
  }
  for (const n of out.notes) lines.push(`- ${n}`);
  return lines.join("\n");
}
