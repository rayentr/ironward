import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cliPath = join(process.cwd(), "dist", "bin.js");

function runCli(args: string[], cwd: string): { code: number; stdout: string; stderr: string } {
  const res = spawnSync("node", [cliPath, ...args], {
    encoding: "utf8",
    cwd,
    timeout: 15000,
    env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@e", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@e" },
  });
  return { code: res.status ?? 1, stdout: res.stdout, stderr: res.stderr };
}

function git(args: string[], cwd: string): void {
  const res = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@e", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@e" },
  });
  if (res.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
}

async function setupRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "iw-diff-"));
  git(["init", "-q"], dir);
  git(["config", "commit.gpgsign", "false"], dir);
  return dir;
}

test("diff: not in a git repo exits 2 with a clear error", async () => {
  // WHY: invoking diff outside a repo should fail loudly, not silently scan nothing.
  const dir = await mkdtemp(join(tmpdir(), "iw-diff-nogit-"));
  try {
    const r = runCli(["diff", "main"], dir);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /not in a git repository/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: invalid git ref exits 2 with a clear error", async () => {
  // WHY: typos like `mian` or unknown branches should be surfaced, not silently treated as empty diff.
  const dir = await setupRepo();
  try {
    await writeFile(join(dir, "x.js"), "const a = 1;\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "init"], dir);
    const r = runCli(["diff", "this-ref-does-not-exist"], dir);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /invalid git ref/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: clean change reports no findings and exits 0", async () => {
  // WHY: most diffs are clean — the command must not exit non-zero on safe code.
  const dir = await setupRepo();
  try {
    await writeFile(join(dir, "x.js"), "const a = 1;\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "init"], dir);
    await writeFile(join(dir, "x.js"), "const a = 2;\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "tweak"], dir);
    const r = runCli(["diff", "HEAD~1"], dir);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /(No new or resolved security findings|0 file)/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: NEW finding introduced in a modified file is reported", async () => {
  // WHY: this is the headline use case — surface what the PR introduced.
  const dir = await setupRepo();
  try {
    // Base version: clean
    await writeFile(join(dir, "api.js"), "function ok() { return 1; }\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "base"], dir);
    // HEAD version: introduces an SSRF
    await writeFile(
      join(dir, "api.js"),
      "app.get('/proxy', (req, res) => fetch(req.body.url));\n",
    );
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "add ssrf"], dir);
    const r = runCli(["diff", "HEAD~1"], dir);
    // Should exit 1 (high-severity new finding) or 0 if the rule isn't classified.
    assert.match(r.stdout, /NEW findings/);
    assert.match(r.stdout, /ssrf|SSRF|fetch/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: pre-existing finding in unchanged file is NOT reported", async () => {
  // WHY: noise from old issues outside the diff defeats the purpose of `diff`.
  // The command must only show what THIS change introduced.
  const dir = await setupRepo();
  try {
    // Base: file with an SSRF
    await writeFile(
      join(dir, "old.js"),
      "app.get('/proxy', (req, res) => fetch(req.body.url));\n",
    );
    await writeFile(join(dir, "other.js"), "const a = 1;\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "base"], dir);
    // HEAD: only modifies other.js with a clean change
    await writeFile(join(dir, "other.js"), "const a = 2;\n");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "unrelated"], dir);
    const r = runCli(["diff", "HEAD~1"], dir);
    // The pre-existing SSRF in old.js is NOT in the diff, must NOT show up
    assert.ok(!r.stdout.includes("old.js"), `old.js should not appear in diff output: ${r.stdout}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: deleted file's findings show as RESOLVED", async () => {
  // WHY: deleting a vulnerable file is the simplest fix; surfacing it as resolved
  // helps reviewers understand the security delta of the PR.
  const dir = await setupRepo();
  try {
    await writeFile(
      join(dir, "vuln.js"),
      "app.get('/proxy', (req, res) => fetch(req.body.url));\n",
    );
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "vuln"], dir);
    git(["rm", "-q", "vuln.js"], dir);
    git(["commit", "-q", "-m", "remove vuln"], dir);
    const r = runCli(["diff", "HEAD~1"], dir);
    assert.match(r.stdout, /Resolved findings/);
    assert.match(r.stdout, /file deleted/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff: no positional arg exits 2 with usage", async () => {
  // WHY: bare `ironward diff` should not silently scan everything.
  const dir = await setupRepo();
  try {
    await writeFile(join(dir, "a.js"), "const a = 1;");
    git(["add", "."], dir);
    git(["commit", "-q", "-m", "init"], dir);
    const r = runCli(["diff"], dir);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /Usage:/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

void mkdir;
