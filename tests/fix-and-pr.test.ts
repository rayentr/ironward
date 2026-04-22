import { test } from "node:test";
import assert from "node:assert/strict";
import { runFixAndPr, type Validator } from "../src/tools/fix-and-pr.ts";
import type { ClaudeClient, ClaudeRequest } from "../src/engines/claude-client.ts";
import type {
  GitHubClient,
  CreatePullRequestOpts,
  CreatedPullRequest,
} from "../src/engines/github-client.ts";
import { parseRepoSlug } from "../src/engines/github-client.ts";

function makeClaude(responses: string[], calls: ClaudeRequest[] = []): ClaudeClient {
  let i = 0;
  return {
    async analyze(req: ClaudeRequest) {
      calls.push(req);
      return responses[i++] ?? responses[responses.length - 1];
    },
  };
}

interface GhCall {
  type: string;
  args: unknown[];
}

function makeGithub(
  overrides: Partial<{
    defaultBranch: string;
    file: { content: string; sha: string };
    filesByPath: Record<string, { content: string; sha: string }>;
    prResult: CreatedPullRequest;
  }> = {},
): { client: GitHubClient; calls: GhCall[] } {
  const calls: GhCall[] = [];
  const defaultBranch = overrides.defaultBranch ?? "main";
  const file = overrides.file ?? { content: "original contents\n", sha: "abc1234" };
  const byPath = overrides.filesByPath ?? {};
  const prResult = overrides.prResult ?? { url: "https://github.com/o/r/pull/42", number: 42 };
  const client: GitHubClient = {
    async getDefaultBranch(owner, repo) {
      calls.push({ type: "getDefaultBranch", args: [owner, repo] });
      return defaultBranch;
    },
    async getFile(owner, repo, path, ref) {
      calls.push({ type: "getFile", args: [owner, repo, path, ref] });
      const entry = byPath[path] ?? file;
      return { path, content: entry.content, sha: entry.sha };
    },
    async createBranch(owner, repo, branch, fromRef) {
      calls.push({ type: "createBranch", args: [owner, repo, branch, fromRef] });
    },
    async upsertFile(owner, repo, branch, path, content, message, sha) {
      calls.push({ type: "upsertFile", args: [owner, repo, branch, path, content, message, sha] });
    },
    async createPullRequest(owner, repo, opts: CreatePullRequestOpts) {
      calls.push({ type: "createPullRequest", args: [owner, repo, opts] });
      return prResult;
    },
  };
  return { client, calls };
}

function passingValidator(): Validator {
  return { async validate() { return { passed: true, residual: [] }; } };
}
function failingValidator(residual = ["still broken"]): Validator {
  return { async validate() { return { passed: false, residual }; } };
}

test("parseRepoSlug accepts 'owner/repo' and strips .git suffix", () => {
  assert.deepEqual(parseRepoSlug("anthropic/ironward"), { owner: "anthropic", repo: "ironward" });
  assert.deepEqual(parseRepoSlug("acme/thing.git"), { owner: "acme", repo: "thing" });
  assert.throws(() => parseRepoSlug("not-a-slug"));
});

test("dry run: single-file legacy shape still works", async () => {
  const calls: ClaudeRequest[] = [];
  const claude = makeClaude(
    [JSON.stringify({ fixed_content: "patched\n", summary: "Replaced X with Y." })],
    calls,
  );
  const { client: github, calls: ghCalls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      filePath: "src/app.js",
      finding: { name: "SQLi in /login", severity: "critical", tool: "scan_sqli" },
      dryRun: true,
    },
    { claude, github },
  );
  assert.equal(out.dryRun, true);
  assert.equal(out.fixedContent, "patched\n");
  assert.equal(out.files.length, 1);
  assert.equal(out.files[0].changed, true);
  assert.ok(!ghCalls.some((c) => c.type === "createBranch"));
  assert.ok(calls[0].user.includes("scan_sqli"));
});

test("live run: multi-file input opens ONE PR with both files committed", async () => {
  const claude = makeClaude([
    JSON.stringify({
      fixed_files: [
        { path: "src/middleware/auth.ts", content: "// fixed middleware\n" },
        { path: "src/routes/user.ts", content: "// fixed route\n" },
      ],
      summary: "Middleware registered before route; ownership check added.",
    }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      finding: {
        name: "Middleware registered after route",
        severity: "high",
        tool: "scan_auth_logic",
      },
      files: [
        { path: "src/middleware/auth.ts", content: "// old mw\n" },
        { path: "src/routes/user.ts", content: "// old route\n" },
      ],
      baseBranch: "main",
    },
    { claude, github },
  );
  assert.equal(out.files.length, 2);
  assert.ok(out.files.every((f) => f.changed));
  assert.equal(out.prNumber, 42);
  const upserts = calls.filter((c) => c.type === "upsertFile");
  assert.equal(upserts.length, 2, "one upsert per changed file");
  const prCalls = calls.filter((c) => c.type === "createPullRequest");
  assert.equal(prCalls.length, 1, "one PR for both files");
});

test("validation: retries once when first fix still fails the scanner", async () => {
  const calls: ClaudeRequest[] = [];
  const claude = makeClaude(
    [
      JSON.stringify({ fixed_files: [{ path: "a.js", content: "attempt1\n" }], summary: "try 1" }),
      JSON.stringify({ fixed_files: [{ path: "a.js", content: "attempt2\n" }], summary: "try 2" }),
    ],
    calls,
  );
  let validationCall = 0;
  const validator: Validator = {
    async validate(files) {
      validationCall++;
      if (validationCall === 1) return { passed: false, residual: ["still broken"] };
      return { passed: true, residual: [] };
    },
  };
  const { client: github, calls: ghCalls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [{ path: "a.js", content: "orig\n" }],
      finding: { name: "IDOR", tool: "scan_idor", severity: "high" },
      baseBranch: "main",
    },
    { claude, github, validator },
  );
  assert.equal(calls.length, 2, "should call Claude twice");
  assert.equal(out.validation?.passed, true);
  assert.equal(out.validation?.attempts, 2);
  assert.equal(out.files[0].fixedContent, "attempt2\n");
  assert.equal(out.prNumber, 42);
  // Retry hint should make it into the second prompt.
  assert.ok(calls[1].user.includes("retry attempt 2"));
  assert.ok(calls[1].user.includes("still broken"));
  assert.ok(ghCalls.some((c) => c.type === "createPullRequest"));
});

test("validation: refuses to open PR if all attempts fail", async () => {
  const claude = makeClaude([
    JSON.stringify({ fixed_files: [{ path: "a.js", content: "still bad\n" }], summary: "x" }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [{ path: "a.js", content: "orig\n" }],
      finding: { name: "XSS", tool: "scan_xss" },
      baseBranch: "main",
    },
    { claude, github, validator: failingValidator(["sink remains"]) },
  );
  assert.equal(out.validation?.passed, false);
  assert.equal(out.prUrl, undefined);
  assert.ok(out.notes.some((n) => n.includes("Validation did not pass")));
  assert.ok(!calls.some((c) => c.type === "createPullRequest"));
});

test("validation: skipValidation bypasses the loop", async () => {
  const claudeCalls: ClaudeRequest[] = [];
  const claude = makeClaude(
    [JSON.stringify({ fixed_files: [{ path: "a.js", content: "fixed\n" }], summary: "ok" })],
    claudeCalls,
  );
  const { client: github } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [{ path: "a.js", content: "orig\n" }],
      finding: { name: "x" },
      baseBranch: "main",
      skipValidation: true,
    },
    { claude, github, validator: failingValidator() },
  );
  assert.equal(claudeCalls.length, 1, "only one Claude call when validation skipped");
  assert.equal(out.validation, undefined);
  assert.equal(out.prNumber, 42);
});

test("fetches only the files whose content is missing", async () => {
  const claude = makeClaude([
    JSON.stringify({
      fixed_files: [
        { path: "a.js", content: "A fixed\n" },
        { path: "b.js", content: "B fixed\n" },
      ],
      summary: "x",
    }),
  ]);
  const { client: github, calls } = makeGithub({
    filesByPath: { "b.js": { content: "B orig\n", sha: "bbb" } },
  });
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [
        { path: "a.js", content: "A orig\n" },
        { path: "b.js" }, // content omitted → must be fetched
      ],
      finding: { name: "Mixed" },
    },
    { claude, github },
  );
  const fetches = calls.filter((c) => c.type === "getFile");
  assert.equal(fetches.length, 1);
  assert.equal((fetches[0].args as unknown[])[2], "b.js");
  assert.equal(out.files.length, 2);
  const upserts = calls.filter((c) => c.type === "upsertFile");
  assert.equal(upserts.length, 2);
});

test("PR body includes OWASP link when finding.tool is known", async () => {
  const claude = makeClaude([
    JSON.stringify({ fixed_files: [{ path: "a.ts", content: "fixed\n" }], summary: "Added owner filter." }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [{ path: "a.ts", content: "orig\n" }],
      finding: {
        name: "IDOR on invoice endpoint",
        severity: "critical",
        tool: "scan_idor",
        description: "Missing ownership check",
        exploit: "Change :id to read any invoice",
      },
      baseBranch: "main",
    },
    { claude, github },
  );
  const pr = calls.find((c) => c.type === "createPullRequest")!;
  const body = (pr.args as unknown[])[2] as CreatePullRequestOpts;
  assert.match(body.body, /A01_2021-Broken_Access_Control/);
  assert.match(body.body, /How it was exploitable/);
  assert.match(body.body, /critical/i);
});

test("skips PR creation when model returns every file unchanged", async () => {
  const claude = makeClaude([
    JSON.stringify({ fixed_files: [{ path: "a.js", content: "orig\n" }], summary: "no change" }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      files: [{ path: "a.js", content: "orig\n" }],
      finding: { name: "False positive" },
      baseBranch: "main",
    },
    { claude, github },
  );
  assert.equal(out.originalContent, out.fixedContent);
  assert.equal(out.files[0].changed, false);
  assert.equal(out.prUrl, undefined);
  assert.ok(!calls.some((c) => c.type === "createBranch"));
  assert.ok(out.notes.some((n) => n.includes("no changes")));
});

test("throws when the model returns neither fixed_files nor fixed_content", async () => {
  const claude = makeClaude([JSON.stringify({ summary: "oops" })]);
  const { client: github } = makeGithub();
  await assert.rejects(
    runFixAndPr(
      {
        repo: "o/r",
        filePath: "x.js",
        fileContent: "x",
        baseBranch: "main",
        finding: { name: "X" },
      },
      { claude, github },
    ),
    /did not return fixed_files/i,
  );
});

test("inline fileContent + baseBranch + dryRun needs no GitHub calls", async () => {
  const claude = makeClaude([
    JSON.stringify({ fixed_content: "fixed\n", summary: "done" }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      filePath: "x.ts",
      finding: { name: "Thing" },
      fileContent: "orig\n",
      baseBranch: "main",
      dryRun: true,
    },
    { claude, github },
  );
  assert.equal(out.dryRun, true);
  assert.equal(out.fixedContent, "fixed\n");
  assert.equal(calls.length, 0);
});

test("tolerates markdown-fenced JSON response", async () => {
  const wrapped = "```json\n" + JSON.stringify({ fixed_content: "OK\n", summary: "done" }) + "\n```";
  const claude = makeClaude([wrapped]);
  const { client: github } = makeGithub();
  const out = await runFixAndPr(
    { repo: "o/r", filePath: "x.js", finding: { name: "x" }, fileContent: "orig\n", baseBranch: "main", dryRun: true },
    { claude, github },
  );
  assert.equal(out.fixedContent, "OK\n");
});

test("branch name and PR title honor custom overrides", async () => {
  const claude = makeClaude([
    JSON.stringify({ fixed_files: [{ path: "x.ts", content: "fixed\n" }], summary: "d" }),
  ]);
  const { client: github, calls } = makeGithub();
  const out = await runFixAndPr(
    {
      repo: "o/r",
      filePath: "x.ts",
      fileContent: "orig\n",
      baseBranch: "develop",
      branchName: "custom/branch",
      commitMessage: "sec: my custom commit",
      finding: { name: "My fix" },
    },
    { claude, github, validator: passingValidator() },
  );
  assert.equal(out.branch, "custom/branch");
  assert.equal(out.commitMessage, "sec: my custom commit");
  const prCall = calls.find((c) => c.type === "createPullRequest")!;
  const opts = (prCall.args as unknown[])[2] as CreatePullRequestOpts;
  assert.equal(opts.head, "custom/branch");
  assert.equal(opts.base, "develop");
});
