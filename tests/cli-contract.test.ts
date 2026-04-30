// CLI behavior contracts — these protect the user-facing surface area.
// Each test spawns the built CLI in a subprocess (matches how users invoke
// `ironward` from a shell or CI script).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const cliPath = join(repoRoot, "dist", "bin.js");

interface RunOpts {
  cwd?: string;
  input?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

function run(args: string[], opts: RunOpts = {}) {
  return spawnSync("node", [cliPath, ...args], {
    encoding: "utf8",
    cwd: opts.cwd ?? process.cwd(),
    input: opts.input,
    env: { ...process.env, NO_COLOR: "1", ...(opts.env ?? {}) },
    timeout: opts.timeoutMs ?? 30000,
  });
}

// Reusable tmp dir helpers
async function withTmpFile<T>(
  files: Array<{ name: string; content: string }>,
  fn: (dir: string, paths: string[]) => Promise<T>,
): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "ironward-cli-"));
  try {
    const paths: string[] = [];
    for (const f of files) {
      const p = join(dir, f.name);
      await writeFile(p, f.content, "utf8");
      paths.push(p);
    }
    return await fn(dir, paths);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const VULN_CONTENT = "function handler(req: any) {\n  return eval(req.body.code);\n}\n";
const CLEAN_CONTENT = "export function add(a: number, b: number): number { return a + b; }\n";

// ─────────────────────────────────────────────────────────────────────────
// Exit codes
// ─────────────────────────────────────────────────────────────────────────

test("cli: --version exits 0", () => {
  // WHY: --version is the most common smoke-test invocation. A non-zero
  // exit here breaks every CI install check and version probe.
  const res = run(["--version"]);
  assert.equal(res.status, 0, `expected exit 0, got ${res.status}; stderr=${res.stderr}`);
});

test("cli: --help exits 0", () => {
  // WHY: --help must succeed so wrappers (man-page generators, doc tools)
  // can capture help text without retry logic.
  const res = run(["--help"]);
  assert.equal(res.status, 0, `expected exit 0, got ${res.status}; stderr=${res.stderr}`);
});

test("cli: unknown subcommand exits 2", () => {
  // WHY: distinguishes user error (exit 2) from a successful no-op (exit 0)
  // and a real failure (exit 1). Shell scripts rely on the convention.
  const res = run(["definitely-not-a-real-command"]);
  assert.equal(res.status, 2, `expected exit 2, got ${res.status}; stderr=${res.stderr}`);
});

test("cli: scan-secrets with no path exits 2 with usage error on stderr", () => {
  // WHY: missing required arg is user error. The diagnostic must reach
  // stderr (not stdout) so it doesn't pollute pipelines that consume
  // `--format json` from stdout.
  const res = run(["scan-secrets"]);
  assert.equal(res.status, 2, `expected exit 2, got ${res.status}`);
  assert.match(res.stderr, /no paths|usage|provided/i);
});

test("cli: scan-secrets on a nonexistent path exits 0 (no files scanned)", () => {
  // WHY: globbing a nonexistent path during CI on a pristine checkout is a
  // common case. A 0-file scan is "I scanned successfully and found
  // nothing" — not an error.
  const res = run(["scan-secrets", "/nonexistent/path/that/does/not/exist"]);
  assert.equal(res.status, 0, `expected exit 0, got ${res.status}; stderr=${res.stderr}`);
});

test("cli: scan-code on a clean file exits 0", async () => {
  // WHY: clean-scan-exit-0 is the contract pre-commit hooks rely on. A
  // false positive flipping this to non-zero blocks every commit.
  await withTmpFile([{ name: "clean.ts", content: CLEAN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-code", p]);
    assert.equal(res.status, 0, `expected exit 0, got ${res.status}; stdout=${res.stdout}; stderr=${res.stderr}`);
  });
});

test("cli: scan-code on a vulnerable file exits non-zero", async () => {
  // WHY: findings must surface as a non-zero exit so CI pipelines fail.
  // Anything in {1, 2} is acceptable — exact code is documented but the
  // contract is "non-zero on findings".
  await withTmpFile([{ name: "vuln.ts", content: VULN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-code", p]);
    assert.notEqual(res.status, 0, `expected non-zero exit; got 0. stdout=${res.stdout}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// --help content
// ─────────────────────────────────────────────────────────────────────────

test("cli: --help mentions scan, scan-code, scan-deps", () => {
  // WHY: the discoverable surface area. If any of these vanish from --help
  // users won't know they exist — broken docs are broken product.
  const res = run(["--help"]);
  assert.match(res.stdout, /\bscan\b/);
  assert.match(res.stdout, /scan-code/);
  assert.match(res.stdout, /scan-deps/);
});

test("cli: --help mentions key flags", () => {
  // WHY: documents that --format, --exploit, --offline, --full, --behavior
  // are first-class flags. Removing one without updating help leads to
  // silent UX breakage.
  const res = run(["--help"]);
  assert.match(res.stdout, /--format/);
  assert.match(res.stdout, /--exploit/);
  assert.match(res.stdout, /--offline/);
  assert.match(res.stdout, /--full/);
  assert.match(res.stdout, /--behavior/);
});

test("cli: --help mentions doctor, init, benchmark (v2.5.0 commands)", () => {
  // WHY: the v2.5.0 release added these commands; if the help banner
  // forgets to list them they become invisible.
  const res = run(["--help"]);
  assert.match(res.stdout, /\bdoctor\b/);
  assert.match(res.stdout, /\binit\b/);
  assert.match(res.stdout, /\bbenchmark\b/);
});

// ─────────────────────────────────────────────────────────────────────────
// --version format
// ─────────────────────────────────────────────────────────────────────────

test("cli: --version output is semver", () => {
  // WHY: tooling parses the version string; anything other than X.Y.Z (no
  // leading 'v', no build metadata in this position) breaks version checks.
  const res = run(["--version"]);
  assert.equal(res.status, 0);
  assert.match(res.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("cli: --version matches package.json version", async () => {
  // WHY: catches the classic "bumped package.json but forgot to rebuild"
  // mistake before it reaches npm.
  const pkgRaw = await readFile(join(repoRoot, "package.json"), "utf8");
  const pkg = JSON.parse(pkgRaw) as { version: string };
  const res = run(["--version"]);
  assert.equal(res.stdout.trim(), pkg.version, `--version mismatch: cli="${res.stdout.trim()}" pkg="${pkg.version}"`);
});

// ─────────────────────────────────────────────────────────────────────────
// --format json validity
// ─────────────────────────────────────────────────────────────────────────

test("cli: scan-secrets --format json produces valid JSON", async () => {
  // WHY: downstream consumers (CI scripts, dashboards) JSON.parse stdout.
  // A stray banner line would silently break every integration.
  await withTmpFile([{ name: "clean.ts", content: CLEAN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-secrets", p, "--format", "json"]);
    assert.equal(res.status, 0, `expected exit 0; stderr=${res.stderr}`);
    let parsed: unknown;
    assert.doesNotThrow(() => { parsed = JSON.parse(res.stdout); }, "stdout must parse as JSON");
    assert.ok(parsed && typeof parsed === "object");
  });
});

test("cli: scan-secrets --format json reports tool=scan_for_secrets", async () => {
  // WHY: pinning the `tool` field lets multi-scanner dashboards route
  // results without parsing the full schema.
  await withTmpFile([{ name: "clean.ts", content: CLEAN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-secrets", p, "--format", "json"]);
    const parsed = JSON.parse(res.stdout) as { tool?: string };
    assert.equal(parsed.tool, "scan_for_secrets");
  });
});

test("cli: scan-code --format json has files array", async () => {
  // WHY: the per-file breakdown is the primary consumer surface of the
  // JSON output. Removing the `files` key (or renaming it) is a breaking
  // change to every dashboard.
  await withTmpFile([{ name: "vuln.ts", content: VULN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-code", p, "--format", "json"]);
    const parsed = JSON.parse(res.stdout) as { files?: unknown[] };
    assert.ok(Array.isArray(parsed.files), "expected `files` array in JSON output");
    assert.ok(parsed.files!.length >= 1, "expected at least one file entry");
  });
});

// ─────────────────────────────────────────────────────────────────────────
// --format sarif validity
// ─────────────────────────────────────────────────────────────────────────

test("cli: scan-code --format sarif produces a valid SARIF skeleton", async () => {
  // WHY: GitHub's codeql-action/upload-sarif rejects malformed SARIF
  // outright. $schema and runs[].results are required by the spec.
  await withTmpFile([{ name: "vuln.ts", content: VULN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-code", p, "--format", "sarif"]);
    const parsed = JSON.parse(res.stdout) as {
      $schema?: string;
      runs?: Array<{ results?: unknown[] }>;
    };
    assert.ok(parsed.$schema, "missing $schema");
    assert.ok(Array.isArray(parsed.runs), "missing runs[]");
    assert.ok(parsed.runs!.length >= 1, "runs[] is empty");
    assert.ok(Array.isArray(parsed.runs![0].results), "runs[0].results is not an array");
  });
});

test("cli: SARIF tool driver is named Ironward", async () => {
  // WHY: GitHub Security tab groups results by tool name. Renaming the
  // driver would split historical findings into a new bucket.
  await withTmpFile([{ name: "vuln.ts", content: VULN_CONTENT }], async (_dir, [p]) => {
    const res = run(["scan-code", p, "--format", "sarif"]);
    const parsed = JSON.parse(res.stdout) as {
      runs: Array<{ tool: { driver: { name: string } } }>;
    };
    assert.equal(parsed.runs[0].tool.driver.name, "Ironward");
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Stderr discipline
// ─────────────────────────────────────────────────────────────────────────

test("cli: --help writes to stdout (not stderr)", () => {
  // WHY: `ironward --help | less` should work. Help on stderr would
  // bypass the pipe and break terminal-based docs workflows.
  const res = run(["--help"]);
  assert.ok(res.stdout.length > 0, "--help produced no stdout");
  // Stderr may legitimately have warnings (e.g. node deprecation notices),
  // but help text itself must be on stdout.
  assert.match(res.stdout, /ironward|scan/i);
});

test("cli: missing-arg error message is on stderr (not stdout)", () => {
  // WHY: text-format error to stderr lets a JSON consumer keep reading
  // stdout without choking on an unexpected non-JSON line.
  const res = run(["scan-secrets"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /no paths|provided|usage/i, "error must appear on stderr");
});

// ─────────────────────────────────────────────────────────────────────────
// Startup performance contract
// ─────────────────────────────────────────────────────────────────────────

test("cli: --version returns within 2 seconds", () => {
  // WHY: catches an accidental top-level network call (e.g. importing a
  // module that reaches out at load time) sneaking into cli.ts startup.
  // Real wall-clock is well under 500ms.
  const t0 = Date.now();
  const res = run(["--version"]);
  const elapsed = Date.now() - t0;
  assert.equal(res.status, 0);
  assert.ok(elapsed < 2000, `--version took ${elapsed}ms (budget 2000ms)`);
});
