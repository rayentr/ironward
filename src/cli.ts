import { readdir, readFile, stat } from "node:fs/promises";
import { writeSync } from "node:fs";
import type { Dirent } from "node:fs";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import { join, relative, resolve } from "node:path";
import { formatReport, runScanSecrets, type FileReport } from "./tools/scan-secrets.js";
import { formatDepsReport, runScanDeps, parseManifest } from "./tools/scan-deps.js";
import { runScanUrl, formatUrlReport } from "./tools/scan-url.js";
import { runScanCode, formatCodeReport } from "./tools/scan-code.js";
import { record, fingerprintFor, isRecordingEnabled } from "./engines/recorder.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string; name: string };

const HELP = `ironward ${pkg.version}
AI-powered security scanner — MCP server and CLI.

Scanning:
  ironward                          start in MCP stdio mode (default)
  ironward serve                    alias for the above
  ironward scan <path>              run every offline scanner on a project (recommended)
  ironward scan-secrets <path>...   scan files/directories for secrets
  ironward scan-code <path>...      static analysis: eval, SSRF, weak crypto, prototype pollution, …
  ironward scan-deps <path>...      scan package.json / requirements.txt / Pipfile.lock
  ironward scan-url <https-url>     audit a live deployed URL for misconfiguration

Provider:
  ironward login                    pick AI provider (Anthropic, OpenAI, Gemini, Groq, Ollama)
  ironward logout                   remove saved AI provider config
  ironward whoami                   show current provider + model
  ironward free                     list tools that work without any API key

Misc:
  ironward --version | -V           print version and exit
  ironward --help | -h              print this help

Output format:
  --format json | text              scan commands accept --format json for CI use
                                    (default: text)

Exit codes for CLI scans:
  0  clean
  1  findings present but none critical/high
  2  critical or high findings present

For scan_auth_logic, scan_sqli, scan_xss, scan_idor, and fix_and_pr: use an MCP client
(Cursor, Claude Code, VS Code) or configure a provider with \`ironward login\`.
`;

const SKIP_DIRS = new Set([
  // Language / build artifacts
  "node_modules", "dist", "build", "out", "coverage", "target", "vendor",
  ".next", ".turbo", ".nuxt", ".svelte-kit", ".astro", ".output",
  ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
  // VCS + IDE
  ".git", ".hg", ".svn", ".idea", ".vscode",
  // Package / deps caches
  ".pnp", ".yarn", ".pnpm-store", ".cache", ".parcel-cache", ".eslintcache",
  // macOS user library & system (permission-protected, not project code)
  "Library", "Applications", ".Trash", ".Spotlight-V100", ".DocumentRevisions-V100",
  ".fseventsd", ".Trashes", ".TemporaryItems", "Music", "Movies", "Photos", "Pictures",
  // Global dotfiles that almost never hold project code
  ".npm", ".nvm", ".bun", ".deno", ".rustup", ".cargo", ".gem", ".gradle",
  ".m2", ".sdkman", ".cache", ".docker", ".kube", ".aws", ".ssh", ".gnupg",
  ".oh-my-zsh", ".zsh_sessions", ".bash_sessions", ".anthropic", ".claude",
  ".cursor", ".config", ".local", "Downloads",
]);

const TEXT_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".php", ".java", ".kt", ".scala",
  ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".m", ".swift",
  ".sh", ".bash", ".zsh",
  ".yaml", ".yml", ".toml", ".ini", ".env", ".conf",
  ".json", ".md", ".txt", ".sql", ".graphql",
  ".vue", ".svelte",
]);

async function* walk(root: string): AsyncGenerator<string> {
  const st = await stat(root).catch(() => null);
  if (!st) return;
  if (st.isFile()) {
    yield root;
    return;
  }
  if (!st.isDirectory()) return;
  let entries: Dirent[];
  try {
    entries = (await readdir(root, { withFileTypes: true })) as Dirent[];
  } catch {
    // Unreadable dir (EPERM / EACCES on macOS sandbox, permission issues, etc.) — skip.
    return;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".env") {
      if (!SKIP_DIRS.has(e.name)) continue;
    }
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(root, e.name);
    if (e.isDirectory()) {
      yield* walk(full);
    } else if (e.isFile()) {
      const dot = e.name.lastIndexOf(".");
      const ext = dot >= 0 ? e.name.slice(dot).toLowerCase() : "";
      if (TEXT_EXTS.has(ext) || e.name === ".env" || e.name === "Dockerfile") yield full;
    }
  }
}

function warnIfDangerousRoot(target: string): string | null {
  const resolved = resolve(process.cwd(), target);
  if (resolved === "/" || resolved === "") {
    return "Refusing to scan filesystem root ('/'). Pass a project directory instead.";
  }
  if (resolved === homedir()) {
    return (
      "Refusing to scan your entire home directory. This would hit OS-protected paths like " +
      "Library/Accounts and produce mostly noise. Pass a specific project directory, e.g. `ironward scan ./myapp`."
    );
  }
  return null;
}

async function collectFiles(targets: string[]): Promise<string[]> {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of targets) {
    const abs = resolve(process.cwd(), t);
    for await (const f of walk(abs)) {
      if (seen.has(f)) continue;
      seen.add(f);
      out.push(f);
    }
  }
  return out;
}

function exitCodeForSecrets(reports: FileReport[]): number {
  let total = 0;
  for (const r of reports) for (const f of r.findings) {
    total++;
    if (f.severity === "critical" || f.severity === "high") return 2;
  }
  return total > 0 ? 1 : 0;
}

export type OutputFormat = "text" | "json";

function writeStdoutSync(s: string): void {
  // Synchronous stdout write avoids truncation when output > 64KB pipe buffer.
  // Chunks into ~32KB pieces since writeSync with a large Buffer can still stall on macOS.
  const buf = Buffer.from(s, "utf8");
  const CHUNK = 32 * 1024;
  let offset = 0;
  while (offset < buf.length) {
    const slice = buf.subarray(offset, Math.min(offset + CHUNK, buf.length));
    try {
      offset += writeSync(1, slice);
    } catch {
      // If stdout is closed mid-write, stop.
      return;
    }
  }
}

export function parseArgs(args: string[]): { format: OutputFormat; rest: string[] } {
  let format: OutputFormat = "text";
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--format" || a === "-f") {
      const v = args[i + 1];
      if (v === "json" || v === "text") { format = v; i++; continue; }
      throw new Error(`--format expects "json" or "text", got: ${v ?? "(nothing)"}`);
    }
    const eq = a.startsWith("--format=") ? a.slice("--format=".length) : null;
    if (eq !== null) {
      if (eq === "json" || eq === "text") { format = eq as OutputFormat; continue; }
      throw new Error(`--format expects "json" or "text", got: ${eq}`);
    }
    rest.push(a);
  }
  return { format, rest };
}

async function runSecretsCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", error: "no paths provided" }) + "\n");
    else console.error("ironward scan-secrets: no paths provided.");
    return 2;
  }
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) {
      if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", error: w }) + "\n");
      else console.error(w);
      return 2;
    }
  }
  const files = await collectFiles(targets);
  if (files.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", filesScanned: 0, files: [] }) + "\n");
    else console.log("No scannable files found.");
    return 0;
  }
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      inputs.push({ path: relative(process.cwd(), f), content });
    } catch {
      // skip unreadable files silently
    }
  }
  const started = new Date().toISOString();
  const startMs = Date.now();
  const out = await runScanSecrets({ files: inputs, context: "on-demand" });
  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", filesScanned: inputs.length, ...out }) + "\n");
  } else {
    console.log(formatReport(out));
    console.log(`\nScanned ${inputs.length} file${inputs.length === 1 ? "" : "s"}.`);
  }

  if (isRecordingEnabled() && format === "text") {
    const findings = out.files.flatMap((file) =>
      file.findings.map((f) => ({
        fingerprint: fingerprintFor("scan_for_secrets", file.path, f.line, f.type),
        severity: f.severity,
        title: `${f.type} in ${file.path}`,
        description: f.description,
        path: file.path,
        line: f.line,
      })),
    );
    const result = await record({
      tool: "scan_for_secrets",
      repo: process.env.IRONWARD_REPO ?? null,
      target: targets.join(","),
      started_at: started,
      duration_ms: Date.now() - startMs,
      findings,
    });
    if (result.ok) console.log(`Recorded to dashboard.`);
    else console.warn(`Recording skipped: ${result.error}`);
  }

  return exitCodeForSecrets(out.files);
}

async function runUrlCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_url", error: "url required" }) + "\n");
    else console.error("ironward scan-url: a URL is required.");
    return 2;
  }
  const url = targets[0];
  const startMs = Date.now();
  const started = new Date().toISOString();
  const result = await runScanUrl({ url, probeTls: true });
  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_url", ...result }) + "\n");
  } else {
    console.log(formatUrlReport(result));
  }

  if (isRecordingEnabled() && format === "text") {
    const findings = result.findings.map((f) => ({
      fingerprint: fingerprintFor("scan_url", url, null, f.id),
      severity: f.severity === "info" ? "low" : f.severity,
      title: f.title,
      description: f.evidence,
      path: url,
      line: null,
    }));
    const rr = await record({
      tool: "scan_url",
      repo: process.env.IRONWARD_REPO ?? null,
      target: url,
      started_at: started,
      duration_ms: Date.now() - startMs,
      findings,
    });
    if (rr.ok) console.log(`\nRecorded to dashboard.`);
    else console.warn(`\nRecording skipped: ${rr.error}`);
  }

  if (result.findings.length === 0) return 0;
  const hasCritOrHigh = result.findings.some((f) => f.severity === "critical" || f.severity === "high");
  return hasCritOrHigh ? 2 : 1;
}

async function runCodeCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_code", error: "no paths provided" }) + "\n");
    else console.error("ironward scan-code: no paths provided.");
    return 2;
  }
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) {
      if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_code", error: w }) + "\n");
      else console.error(w);
      return 2;
    }
  }
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      inputs.push({ path: relative(process.cwd(), f), content });
    } catch {
      /* skip */
    }
  }
  const out = await runScanCode({ files: inputs });
  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_code", filesScanned: inputs.length, ...out }) + "\n");
  } else {
    console.log(formatCodeReport(out));
    console.log(`\nScanned ${inputs.length} file${inputs.length === 1 ? "" : "s"} with ${out.summary.totalFindings} finding${out.summary.totalFindings === 1 ? "" : "s"}.`);
  }

  if (isRecordingEnabled() && format === "text") {
    const findings = out.files.flatMap((file) =>
      file.findings.map((f) => ({
        fingerprint: fingerprintFor("scan_code", file.path, f.line, f.ruleId),
        severity: f.severity,
        title: f.title,
        description: f.rationale,
        path: file.path,
        line: f.line,
      })),
    );
    const r = await record({
      tool: "scan_code",
      repo: process.env.IRONWARD_REPO ?? null,
      target: targets.join(","),
      findings,
    });
    if (r.ok) console.log("Recorded to dashboard.");
  }

  if (out.summary.totalFindings === 0) return 0;
  return out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
}

async function runFullScanCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  const target = targets[0] ?? ".";
  const warning = warnIfDangerousRoot(target);
  if (warning) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan", error: warning }) + "\n");
    else console.error(warning);
    return 2;
  }
  const startedWhole = Date.now();

  if (format === "json") {
    const [secrets, code, deps] = await Promise.all([
      collectSecretsResult([target]),
      collectCodeResult([target]),
      collectDepsResult([target]),
    ]);
    const combined = {
      tool: "scan",
      target,
      durationMs: Date.now() - startedWhole,
      version: pkg.version,
      secrets: secrets.result,
      code: code.result,
      deps: deps.result,
    };
    writeStdoutSync(JSON.stringify(combined) + "\n");
    return Math.max(secrets.exit, code.exit, deps.exit);
  }

  console.log(`Ironward — offline scan of ${target}\n`);
  let worstExit = 0;
  const track = (code: number) => { if (code > worstExit) worstExit = code; };

  console.log("── scan-secrets ──");
  track(await runSecretsCli([target]));
  console.log("\n── scan-code ──");
  track(await runCodeCli([target]));
  console.log("\n── scan-deps ──");
  track(await runDepsCli([target]));
  console.log(`\nDone in ${Date.now() - startedWhole}ms.`);
  return worstExit;
}

async function collectSecretsResult(targets: string[]): Promise<{ exit: number; result: unknown }> {
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) return { exit: 2, result: { tool: "scan_for_secrets", error: w, files: [] } };
  }
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanSecrets({ files: inputs, context: "on-demand" });
  return {
    exit: exitCodeForSecrets(out.files),
    result: { tool: "scan_for_secrets", filesScanned: inputs.length, ...out },
  };
}

async function collectCodeResult(targets: string[]): Promise<{ exit: number; result: unknown }> {
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) return { exit: 2, result: { tool: "scan_code", error: w, files: [] } };
  }
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanCode({ files: inputs });
  const exit = out.summary.totalFindings === 0
    ? 0
    : out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
  return { exit, result: { tool: "scan_code", filesScanned: inputs.length, ...out } };
}

async function collectDepsResult(targets: string[]): Promise<{ exit: number; result: unknown }> {
  const paths: string[] = [];
  for (const t of targets) {
    const abs = resolve(process.cwd(), t);
    const st = await stat(abs).catch(() => null);
    if (!st) continue;
    if (st.isFile()) paths.push(abs);
    else if (st.isDirectory()) {
      for await (const f of walk(abs)) {
        const content = await readFile(f, "utf8").catch(() => "");
        if (parseManifest(f, content).length > 0) paths.push(f);
      }
    }
  }
  if (paths.length === 0) {
    return { exit: 0, result: { tool: "scan_deps", dependenciesScanned: 0, findings: [], intel: [], summary: "No manifests found." } };
  }
  const out = await runScanDeps({ paths });
  const critHigh = out.findings.some((f) => f.severity === "critical" || f.severity === "high")
    || out.intel.some((f) => f.severity === "critical" || f.severity === "high");
  const exit = out.findings.length === 0 && out.intel.length === 0 ? 0 : critHigh ? 2 : 1;
  return { exit, result: { tool: "scan_deps", ...out } };
}

async function runDepsCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_deps", error: "no paths provided" }) + "\n");
    else console.error("ironward scan-deps: no paths provided.");
    return 2;
  }
  const paths: string[] = [];
  for (const t of targets) {
    const abs = resolve(process.cwd(), t);
    const st = await stat(abs).catch(() => null);
    if (!st) continue;
    if (st.isFile()) {
      paths.push(abs);
    } else if (st.isDirectory()) {
      for await (const f of walk(abs)) {
        const content = await readFile(f, "utf8").catch(() => "");
        if (parseManifest(f, content).length > 0) paths.push(f);
      }
    }
  }
  if (paths.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_deps", dependenciesScanned: 0, findings: [], intel: [], summary: "No manifests found." }) + "\n");
    else console.log("No supported manifests (package.json, requirements.txt, Pipfile.lock) found.");
    return 0;
  }
  const out = await runScanDeps({ paths });
  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_deps", ...out }) + "\n");
  } else {
    console.log(formatDepsReport(out));
  }
  const critHigh = out.findings.some((f) => f.severity === "critical" || f.severity === "high")
    || out.intel.some((f) => f.severity === "critical" || f.severity === "high");
  if (out.findings.length === 0 && out.intel.length === 0) return 0;
  return critHigh ? 2 : 1;
}

async function startMcpServer(): Promise<void> {
  const { startServer } = await import("./server.js");
  await startServer();
}

export async function runCli(argv: string[]): Promise<number> {
  const args = argv.slice(2);

  if (args.length === 0) {
    await startMcpServer();
    return 0;
  }

  const cmd = args[0];
  let parsed: { format: OutputFormat; rest: string[] };
  try {
    parsed = parseArgs(args.slice(1));
  } catch (err) {
    console.error((err as Error).message);
    return 2;
  }
  const { format, rest } = parsed;

  switch (cmd) {
    case "-h":
    case "--help":
      console.log(HELP);
      return 0;
    case "-V":
    case "--version":
      console.log(pkg.version);
      return 0;
    case "serve":
      await startMcpServer();
      return 0;
    case "scan-secrets":
      return await runSecretsCli(rest, format);
    case "scan":
      return await runFullScanCli(rest, format);
    case "scan-code":
      return await runCodeCli(rest, format);
    case "scan-deps":
      return await runDepsCli(rest, format);
    case "scan-url":
      return await runUrlCli(rest, format);
    case "login": {
      const { runLogin } = await import("./commands/login.js");
      return await runLogin();
    }
    case "logout": {
      const { runLogout } = await import("./commands/login.js");
      return await runLogout();
    }
    case "whoami": {
      const { runWhoami } = await import("./commands/login.js");
      return await runWhoami();
    }
    case "free": {
      const { runFree } = await import("./commands/login.js");
      return await runFree();
    }
    default:
      console.error(`Unknown command: ${args[0]}`);
      console.error("Run `ironward --help` for usage.");
      return 2;
  }
}
