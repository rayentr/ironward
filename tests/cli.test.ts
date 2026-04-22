import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const binPath = join(here, "..", "dist", "bin.js");

interface Proc {
  code: number;
  stdout: string;
  stderr: string;
}

function run(args: string[], opts: { input?: string; timeoutMs?: number } = {}): Promise<Proc> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("node", [binPath, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    const timer = setTimeout(() => {
      child.kill();
      rejectPromise(new Error(`CLI timed out: ${args.join(" ")}`));
    }, opts.timeoutMs ?? 15000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? 0, stdout, stderr });
    });
    child.on("error", rejectPromise);
    if (opts.input !== undefined) {
      child.stdin.write(opts.input);
      child.stdin.end();
    }
  });
}

test("--version prints version and exits 0", async () => {
  const { code, stdout } = await run(["--version"]);
  assert.equal(code, 0);
  assert.match(stdout, /^\d+\.\d+\.\d+/);
});

test("--help lists subcommands", async () => {
  const { code, stdout } = await run(["--help"]);
  assert.equal(code, 0);
  assert.match(stdout, /scan-secrets/);
  assert.match(stdout, /scan-deps/);
  assert.match(stdout, /MCP stdio/);
});

test("unknown command exits 2 with helpful stderr", async () => {
  const { code, stderr } = await run(["banana"]);
  assert.equal(code, 2);
  assert.match(stderr, /Unknown command/i);
});

test("scan-secrets on leaky fixture finds criticals and exits 2", async () => {
  const fixture = join(here, "fixtures", "leaky.js");
  // --verbose needed because fixture paths are penalized by confidence scoring.
  const { code, stdout } = await run(["scan-secrets", "--verbose", fixture]);
  assert.equal(code, 2);
  assert.match(stdout, /CRITICAL/);
  assert.match(stdout, /aws_access_key/);
});

test("scan-secrets on clean fixture exits 0", async () => {
  const fixture = join(here, "fixtures", "clean.js");
  const { code, stdout } = await run(["scan-secrets", fixture]);
  assert.equal(code, 0);
  assert.match(stdout, /No secrets detected/);
});

test("scan-secrets with no paths exits 2 with error", async () => {
  const { code, stderr } = await run(["scan-secrets"]);
  assert.equal(code, 2);
  assert.match(stderr, /no paths/i);
});

test("scan-secrets traverses a directory and skips node_modules", async () => {
  const dir = join(here, "fixtures", "categories");
  const { code, stdout } = await run(["scan-secrets", "--verbose", dir]);
  // The category fixtures contain critical patterns → exit 2
  assert.equal(code, 2);
  assert.match(stdout, /Scanned \d+ files? in \d+ms/);
});

test("scan-secrets --format json emits a single JSON object on stdout", async () => {
  const fixture = join(here, "fixtures", "leaky.js");
  const { code, stdout } = await run(["scan-secrets", "--verbose", "--format", "json", fixture]);
  assert.equal(code, 2);
  const trimmed = stdout.trim();
  const parsed = JSON.parse(trimmed) as { tool: string; files: Array<{ findings: unknown[] }> };
  assert.equal(parsed.tool, "scan_for_secrets");
  assert.ok(Array.isArray(parsed.files));
  assert.ok(parsed.files.some((f) => f.findings.length > 0), "expected at least one finding");
});

test("scan --format json emits a combined object with secrets + code + deps", async () => {
  // Use the categories subdir — no manifests, so scan-deps is fast (no OSV network calls).
  const dir = join(here, "fixtures", "categories");
  const { stdout } = await run(["scan", "--format", "json", dir], { timeoutMs: 20000 });
  const trimmed = stdout.trim();
  const parsed = JSON.parse(trimmed) as Record<string, unknown>;
  assert.equal(parsed.tool, "scan");
  assert.ok(parsed.secrets, "expected .secrets key");
  assert.ok(parsed.code, "expected .code key");
  assert.ok(parsed.deps, "expected .deps key");
  assert.ok(typeof parsed.version === "string");
});

test("scan-deps --format json emits clean object with findings/intel arrays", async () => {
  const pkg = join(here, "fixtures", "deps", "package.json");
  const { stdout } = await run(["scan-deps", "--format=json", pkg]);
  const parsed = JSON.parse(stdout.trim()) as { tool: string; findings: unknown[]; intel: unknown[] };
  assert.equal(parsed.tool, "scan_deps");
  assert.ok(Array.isArray(parsed.findings));
  assert.ok(Array.isArray(parsed.intel));
});

test(".ironwardignore skips matching files during scan-secrets", async () => {
  const { mkdtempSync, rmSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const scratch = mkdtempSync(join(tmpdir(), "ironward-ignore-cli-"));
  try {
    mkdirSync(join(scratch, "secrets-to-ignore"));
    // A real-looking secret that would definitely be flagged
    writeFileSync(
      join(scratch, "secrets-to-ignore", "keys.js"),
      'const k = "AKIAJZ5TESTABCD2PQ3K";\n',
    );
    writeFileSync(
      join(scratch, "app.js"),
      'const safe = "hello";\n',
    );
    // Without the ignore file, the scan should find the AWS key.
    const before = await run(["scan-secrets", "--format", "json", scratch]);
    const beforeJson = JSON.parse(before.stdout.trim()) as { files: Array<{ findings: unknown[] }> };
    assert.ok(beforeJson.files.some((f) => f.findings.length > 0), "expected findings before ignore");

    // With .ironwardignore, the subdir should be skipped.
    writeFileSync(join(scratch, ".ironwardignore"), "secrets-to-ignore/\n");
    const after = await run(["scan-secrets", "--format", "json", scratch]);
    const afterJson = JSON.parse(after.stdout.trim()) as { files: Array<{ findings: unknown[] }> };
    assert.equal(
      afterJson.files.reduce((n, f) => n + f.findings.length, 0),
      0,
      "expected zero findings after .ironwardignore",
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("--format with invalid value exits 2", async () => {
  const { code, stderr } = await run(["scan-secrets", "--format", "yaml", "."]);
  assert.equal(code, 2);
  assert.match(stderr, /--format/);
});

test("MCP mode (no args) responds to initialize over stdio", async () => {
  const messages = [
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}',
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
  ].join("\n") + "\n";
  const { stdout } = await run([], { input: messages, timeoutMs: 10000 });
  const lines = stdout.trim().split("\n").filter(Boolean);
  assert.ok(lines.length >= 2, `expected >=2 responses, got ${lines.length}`);
  const listResp = JSON.parse(lines[lines.length - 1]) as { result: { tools: Array<{ name: string }> } };
  const names = listResp.result.tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "fix_and_pr",
    "scan_auth_logic",
    "scan_code",
    "scan_deps",
    "scan_docker",
    "scan_for_secrets",
    "scan_github",
    "scan_idor",
    "scan_infra",
    "scan_k8s",
    "scan_sqli",
    "scan_url",
    "scan_xss",
  ]);
});
