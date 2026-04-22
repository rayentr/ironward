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
import { runScanDocker, formatDockerReport, detectKind as detectDockerKind } from "./tools/scan-docker.js";
import { runScanK8s, formatK8sReport, detectK8s } from "./tools/scan-k8s.js";
import { runScanGithub, formatGithubReport, detectGithubWorkflow } from "./tools/scan-github.js";
import { runScanInfra, formatInfraReport, detectInfraKind } from "./tools/scan-infra.js";
import { scanText } from "./engines/secret-engine.js";
import { scanCodeRules, severityRank as codeSeverityRank } from "./engines/code-rules.js";
import { record, fingerprintFor, isRecordingEnabled } from "./engines/recorder.js";
import { IgnoreMatcher, DEFAULT_IGNORE_PATTERNS } from "./engines/ignore.js";
import { ScanCache, sha256 } from "./engines/scan-cache.js";
import { filesForScope, isGitRepo, parseScopeFromArgs, type GitScope } from "./engines/git-diff.js";
import { mapConcurrent, defaultConcurrency } from "./engines/concurrent.js";
import { dedupByValue } from "./engines/dedup.js";

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
  ironward scan-docker <path>...    Dockerfile + docker-compose security
  ironward scan-k8s <path>...       Kubernetes manifest security
  ironward scan-infra <path>...     Terraform + CloudFormation security
  ironward scan-github <path>...    GitHub Actions workflow security

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

Git-scoped scanning (makes pre-commit hooks instant):
  --staged                          scan only staged files
  --changed                         scan only uncommitted tracked changes
  --since <ref>                     scan only files changed since <ref>

Cache:
  --no-cache                        ignore ~/.ironward/cache.json for this run

Confidence + dedup:
  --verbose                         include low-confidence findings (40-59)
  --no-dedup                        keep cross-file duplicates as separate findings

Ignore rules (applied to every scan):
  - .gitignore and .ironwardignore (if present) at the project root
  - Built-in skips: node_modules/, dist/, build/, .next/, *.min.js, *.map, …

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

async function buildIgnoreMatcher(projectRoot: string): Promise<IgnoreMatcher> {
  // Seed with defaults, then layer on .gitignore and .ironwardignore if present.
  const patterns = [...DEFAULT_IGNORE_PATTERNS];
  const extra = await IgnoreMatcher.fromFiles(projectRoot, [
    join(projectRoot, ".gitignore"),
    join(projectRoot, ".ironwardignore"),
  ]);
  for (const r of extra.rules) patterns.push(r.raw);
  return new IgnoreMatcher(projectRoot, patterns);
}

async function* walk(root: string, matcher?: IgnoreMatcher): AsyncGenerator<string> {
  const st = await stat(root).catch(() => null);
  if (!st) return;
  if (st.isFile()) {
    yield root;
    return;
  }
  if (!st.isDirectory()) return;

  const ign = matcher ?? (await buildIgnoreMatcher(root));
  yield* walkInner(root, ign);
}

async function* walkInner(dir: string, ign: IgnoreMatcher): AsyncGenerator<string> {
  let entries: Dirent[];
  try {
    entries = (await readdir(dir, { withFileTypes: true })) as Dirent[];
  } catch {
    // Unreadable dir (EPERM / EACCES on macOS sandbox, permission issues, etc.) — skip.
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    const isDir = e.isDirectory();

    // Always skip known system/build dirs by name (cheap short-circuit).
    if (SKIP_DIRS.has(e.name)) continue;
    if (e.name.startsWith(".") && e.name !== ".env" && !SKIP_DIRS.has(e.name)) {
      // Hidden dotfile dirs/files — only allow .env through; ignore the rest unless whitelisted by name.
      continue;
    }

    // Apply ignore rules (.gitignore + .ironwardignore + defaults).
    if (ign.ignores(full, isDir)) continue;

    if (isDir) {
      yield* walkInner(full, ign);
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

/**
 * If --staged / --changed / --since was passed, return only the intersection
 * of git-diff files and our walker's filter (.gitignore + .ironwardignore + text exts).
 * Otherwise, return the full walker output.
 */
async function collectFilesForScope(targets: string[], scope: GitScope | null): Promise<string[]> {
  const walked = await collectFiles(targets);
  if (!scope) return walked;
  const cwd = process.cwd();
  if (!(await isGitRepo(cwd))) {
    console.error("Git scope requested (--staged / --changed / --since) but not inside a git repo.");
    return [];
  }
  const scoped = new Set(await filesForScope(scope, cwd));
  return walked.filter((f) => scoped.has(f));
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

class ProgressReporter {
  private readonly enabled: boolean;
  private lastLen = 0;
  private lastTick = 0;

  constructor(public total: number) {
    // Only show progress on a TTY, and not when the user piped to a file.
    this.enabled = Boolean(process.stderr.isTTY) && !process.env.CI && total > 10;
  }

  update(done: number, currentFile: string): void {
    if (!this.enabled) return;
    const now = Date.now();
    if (now - this.lastTick < 33 && done !== this.total) return;
    this.lastTick = now;
    const pct = this.total === 0 ? 100 : Math.floor((done / this.total) * 100);
    const bar = `[${"█".repeat(Math.floor(pct / 5)).padEnd(20, "·")}]`;
    const shortFile = currentFile.length > 40 ? "…" + currentFile.slice(-39) : currentFile;
    const line = `\rScanning ${bar} ${pct.toString().padStart(3)}%  ${done}/${this.total}  ${shortFile}`;
    this.lastLen = line.length;
    process.stderr.write(line);
  }

  clear(): void {
    if (!this.enabled) return;
    process.stderr.write("\r" + " ".repeat(this.lastLen) + "\r");
  }
}

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

export function parseArgs(args: string[]): {
  format: OutputFormat;
  scope: GitScope | null;
  noCache: boolean;
  verbose: boolean;
  noDedup: boolean;
  rest: string[];
} {
  let format: OutputFormat = "text";
  let noCache = false;
  let verbose = false;
  let noDedup = false;
  const preRest: string[] = [];
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
    if (a === "--no-cache") { noCache = true; continue; }
    if (a === "--verbose" || a === "-v") { verbose = true; continue; }
    if (a === "--no-dedup") { noDedup = true; continue; }
    preRest.push(a);
  }
  const { scope, rest } = parseScopeFromArgs(preRest);
  return { format, scope, noCache, verbose, noDedup, rest };
}

interface ScanOpts { verbose?: boolean; noDedup?: boolean }

async function runSecretsCli(targets: string[], format: OutputFormat = "text", scope: GitScope | null = null, opts: ScanOpts = {}): Promise<number> {
  if (targets.length === 0 && !scope) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", error: "no paths provided" }) + "\n");
    else console.error("ironward scan-secrets: no paths provided.");
    return 2;
  }
  if (targets.length === 0 && scope) targets = ["."];
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) {
      if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", error: w }) + "\n");
      else console.error(w);
      return 2;
    }
  }
  const files = await collectFilesForScope(targets, scope);
  if (files.length === 0) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", filesScanned: 0, files: [] }) + "\n");
    else console.log("No scannable files found.");
    return 0;
  }

  const started = new Date().toISOString();
  const startMs = Date.now();

  const cache = await ScanCache.load();
  const progress = new ProgressReporter(files.length);
  const streamText = format === "text";
  let cacheHits = 0;
  let done = 0;

  const rawReports = await mapConcurrent(
    files,
    defaultConcurrency(),
    async (f) => {
      const rel = relative(process.cwd(), f);
      let content = "";
      try { content = await readFile(f, "utf8"); } catch { return { path: rel, findings: [] } as FileReport; }
      const contentHash = sha256(content).slice(0, 16);
      let findings = cache.lookup<any>(f, "scan_for_secrets", contentHash);
      if (findings === null) {
        findings = await scanText(content, rel);
        cache.store(f, "scan_for_secrets", contentHash, findings);
      } else {
        cacheHits++;
      }
      return { path: rel, findings } as FileReport;
    },
    (_report) => {
      done++;
      progress.update(done, _report.path);
    },
  );
  progress.clear();
  await cache.save().catch(() => {/* cache is best-effort */});

  // Apply confidence filter (suppress < 40 always; hide 40-59 unless --verbose).
  const minConfidence = opts.verbose ? 40 : 60;
  let suppressedLowConf = 0;
  const filtered: FileReport[] = rawReports.map((r) => {
    const kept = r.findings.filter((f) => {
      if ((f.confidence ?? 100) < minConfidence) { suppressedLowConf++; return false; }
      return true;
    });
    return { path: r.path, findings: kept };
  });

  // Apply cross-file dedup unless the user opted out.
  const reports: FileReport[] = [];
  if (!opts.noDedup) {
    const flat: Array<{ path: string; finding: typeof filtered[number]["findings"][number] }> = [];
    for (const r of filtered) for (const fnd of r.findings) flat.push({ path: r.path, finding: fnd });
    const deduped = dedupByValue(flat);
    const byPath = new Map<string, typeof filtered[number]["findings"]>();
    for (const e of deduped) {
      if (!byPath.has(e.path)) byPath.set(e.path, []);
      byPath.get(e.path)!.push(e.finding);
    }
    for (const r of filtered) {
      reports.push({ path: r.path, findings: byPath.get(r.path) ?? [] });
    }
  } else {
    reports.push(...filtered);
  }

  // Stream findings now that filtering/dedup is done.
  if (streamText) {
    for (const r of reports) {
      for (const fnd of r.findings) {
        const sev = fnd.severity.toUpperCase();
        const confTag = fnd.confidence !== undefined ? ` conf=${fnd.confidence}` : "";
        console.log(`[${sev}${confTag}] ${r.path}:${fnd.line}  ${fnd.type}`);
        if (fnd.description) console.log(`  ${fnd.description}`);
        if (fnd.duplicates && fnd.duplicates.length > 0) {
          console.log(`  ↳ also seen in ${fnd.duplicates.length} other location${fnd.duplicates.length === 1 ? "" : "s"}`);
        }
      }
    }
  }

  const bySev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const r of reports) for (const f of r.findings) {
    total++;
    if (f.severity in bySev) bySev[f.severity]++;
  }
  const out = {
    files: reports,
    summary: { totalFindings: total, bySeverity: bySev as any, blocked: false },
  };

  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_for_secrets", filesScanned: files.length, cached: cacheHits, suppressedLowConfidence: suppressedLowConf, ...out }) + "\n");
  } else {
    if (total === 0) console.log("No secrets detected. All scanned files are clean.");
    else console.log(`\nScan summary: ${total} findings (${bySev.critical} critical, ${bySev.high} high, ${bySev.medium} medium, ${bySev.low} low).`);
    const cacheNote = cacheHits > 0 ? ` (${cacheHits} cached)` : "";
    const suppressedNote = suppressedLowConf > 0 ? ` (${suppressedLowConf} low-confidence suppressed; use --verbose to see)` : "";
    console.log(`Scanned ${files.length} file${files.length === 1 ? "" : "s"} in ${Date.now() - startMs}ms${cacheNote}${suppressedNote}.`);
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

async function runCodeCli(targets: string[], format: OutputFormat = "text", scope: GitScope | null = null): Promise<number> {
  if (targets.length === 0 && !scope) {
    if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_code", error: "no paths provided" }) + "\n");
    else console.error("ironward scan-code: no paths provided.");
    return 2;
  }
  if (targets.length === 0 && scope) targets = ["."];
  for (const t of targets) {
    const w = warnIfDangerousRoot(t);
    if (w) {
      if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_code", error: w }) + "\n");
      else console.error(w);
      return 2;
    }
  }
  const files = await collectFilesForScope(targets, scope);
  const startMs = Date.now();
  const cache = await ScanCache.load();
  let cacheHits = 0;
  const progress = new ProgressReporter(files.length);
  const streamText = format === "text";
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let done = 0;

  const reports = await mapConcurrent(
    files,
    defaultConcurrency(),
    async (f) => {
      const rel = relative(process.cwd(), f);
      let content = "";
      try { content = await readFile(f, "utf8"); } catch { return { path: rel, findings: [] as ReturnType<typeof scanCodeRules> }; }
      const contentHash = sha256(content).slice(0, 16);
      let findings = cache.lookup<ReturnType<typeof scanCodeRules>[number]>(f, "scan_code", contentHash);
      if (findings === null) {
        findings = scanCodeRules(content);
        cache.store(f, "scan_code", contentHash, findings);
      } else {
        cacheHits++;
      }
      return { path: rel, findings };
    },
    (report) => {
      done++;
      for (const fnd of report.findings) if (fnd.severity in bySeverity) bySeverity[fnd.severity]++;
      if (streamText && report.findings.length > 0) {
        progress.clear();
        const sorted = [...report.findings].sort((a, b) => codeSeverityRank(b.severity) - codeSeverityRank(a.severity) || a.line - b.line);
        for (const fnd of sorted) {
          console.log(`[${fnd.severity.toUpperCase()}] ${report.path}:L${fnd.line}  ${fnd.title}  (${fnd.ruleId})`);
        }
      }
      progress.update(done, report.path);
    },
  );
  progress.clear();
  await cache.save().catch(() => {/* best-effort */});

  const totalFindings = reports.reduce((n, r) => n + r.findings.length, 0);
  const out = {
    files: reports,
    summary: { totalFindings, bySeverity: bySeverity as any, filesScanned: files.length },
  };

  if (format === "json") {
    writeStdoutSync(JSON.stringify({ tool: "scan_code", filesScanned: files.length, cached: cacheHits, ...out }) + "\n");
  } else {
    if (totalFindings === 0) console.log(`scan_code: no issues across ${files.length} file${files.length === 1 ? "" : "s"}.`);
    else console.log(`\nscan_code: ${totalFindings} findings (${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low) in ${Date.now() - startMs}ms.`);
    const cacheNote = cacheHits > 0 ? ` (${cacheHits} cached)` : "";
    console.log(`Scanned ${files.length} file${files.length === 1 ? "" : "s"}${cacheNote}.`);
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

async function runFullScanCli(targets: string[], format: OutputFormat = "text", scope: GitScope | null = null, opts: ScanOpts = {}): Promise<number> {
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

  // Detect which IaC/container/workflow scanners are worth running.
  const detected = await detectIacScanners([target]);

  console.log("── scan-secrets ──");
  track(await runSecretsCli([target], "text", scope, opts));
  console.log("\n── scan-code ──");
  track(await runCodeCli([target], "text", scope));
  console.log("\n── scan-deps ──");
  track(await runDepsCli([target]));
  if (detected.docker) {
    console.log("\n── scan-docker ──");
    track(await runDockerCli([target]));
  }
  if (detected.k8s) {
    console.log("\n── scan-k8s ──");
    track(await runK8sCli([target]));
  }
  if (detected.infra) {
    console.log("\n── scan-infra ──");
    track(await runInfraCli([target]));
  }
  if (detected.github) {
    console.log("\n── scan-github ──");
    track(await runGithubCli([target]));
  }
  console.log(`\nDone in ${Date.now() - startedWhole}ms.`);
  return worstExit;
}

async function detectIacScanners(targets: string[]): Promise<{ docker: boolean; k8s: boolean; infra: boolean; github: boolean }> {
  const out = { docker: false, k8s: false, infra: false, github: false };
  const files = await collectFiles(targets);
  for (const f of files) {
    try {
      // For detection, only read a small prefix to be fast.
      const content = await readFile(f, "utf8").then((s) => s.slice(0, 4096));
      if (!out.docker && detectDockerKind(f, content) !== null) out.docker = true;
      if (!out.k8s && detectK8s(f, content)) out.k8s = true;
      if (!out.infra && detectInfraKind(f, content) !== null) out.infra = true;
      if (!out.github && detectGithubWorkflow(f, content)) out.github = true;
      if (out.docker && out.k8s && out.infra && out.github) break;
    } catch { /* skip */ }
  }
  return out;
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

async function runDockerCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) targets = ["."];
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      if (detectDockerKind(f, content) !== null) inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanDocker({ files: inputs });
  if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_docker", ...out }) + "\n");
  else console.log(formatDockerReport(out));
  if (out.summary.totalFindings === 0) return 0;
  return out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
}

async function runK8sCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) targets = ["."];
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      if (detectK8s(f, content)) inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanK8s({ files: inputs });
  if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_k8s", ...out }) + "\n");
  else console.log(formatK8sReport(out));
  if (out.summary.totalFindings === 0) return 0;
  return out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
}

async function runGithubCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) targets = ["."];
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      if (detectGithubWorkflow(f, content)) inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanGithub({ files: inputs });
  if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_github", ...out }) + "\n");
  else console.log(formatGithubReport(out));
  if (out.summary.totalFindings === 0) return 0;
  return out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
}

async function runInfraCli(targets: string[], format: OutputFormat = "text"): Promise<number> {
  if (targets.length === 0) targets = ["."];
  const files = await collectFiles(targets);
  const inputs: Array<{ path: string; content: string }> = [];
  for (const f of files) {
    try {
      const content = await readFile(f, "utf8");
      if (detectInfraKind(f, content) !== null) inputs.push({ path: relative(process.cwd(), f), content });
    } catch { /* skip */ }
  }
  const out = await runScanInfra({ files: inputs });
  if (format === "json") writeStdoutSync(JSON.stringify({ tool: "scan_infra", ...out }) + "\n");
  else console.log(formatInfraReport(out));
  if (out.summary.totalFindings === 0) return 0;
  return out.summary.bySeverity.critical > 0 || out.summary.bySeverity.high > 0 ? 2 : 1;
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
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs(args.slice(1));
  } catch (err) {
    console.error((err as Error).message);
    return 2;
  }
  const { format, scope, noCache, verbose, noDedup, rest } = parsed;
  if (noCache) process.env.IRONWARD_NO_CACHE = "1";

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
      return await runSecretsCli(rest, format, scope, { verbose, noDedup });
    case "scan":
      return await runFullScanCli(rest, format, scope, { verbose, noDedup });
    case "scan-code":
      return await runCodeCli(rest, format, scope);
    case "scan-deps":
      return await runDepsCli(rest, format);
    case "scan-url":
      return await runUrlCli(rest, format);
    case "scan-docker":
      return await runDockerCli(rest, format);
    case "scan-k8s":
      return await runK8sCli(rest, format);
    case "scan-github":
      return await runGithubCli(rest, format);
    case "scan-infra":
      return await runInfraCli(rest, format);
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
