import { watch as fsWatch } from "node:fs";
import type { FSWatcher } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { scanText } from "../engines/secret-engine.js";
import { scanCodeRules } from "../engines/code-rules.js";
import { ScanCache, sha256 } from "../engines/scan-cache.js";
import { IgnoreMatcher, DEFAULT_IGNORE_PATTERNS } from "../engines/ignore.js";
import { confidenceTier } from "../engines/confidence.js";

export interface WatchOptions {
  /** Root to watch. Defaults to cwd. */
  root?: string;
  /** Confidence threshold for reporting. Default 60. */
  minConfidence?: number;
  /** Abort signal for tests / graceful shutdown. */
  signal?: AbortSignal;
  /** Called once the watcher is attached and idle. */
  onReady?: () => void;
  /** Debounce window for batching changes, ms. Default 120. */
  debounceMs?: number;
}

const TEXT_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".rb", ".php", ".java", ".kt", ".scala",
  ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".m", ".swift",
  ".sh", ".bash", ".zsh",
  ".yaml", ".yml", ".toml", ".ini", ".conf", ".env",
  ".json", ".md", ".txt", ".sql", ".graphql",
  ".vue", ".svelte",
  ".tf", ".tf.json",
]);

function extOf(path: string): string {
  const dot = path.lastIndexOf(".");
  return dot >= 0 ? path.slice(dot).toLowerCase() : "";
}

function isScannable(path: string): boolean {
  const name = path.split(sep).pop() ?? "";
  if (name === ".env" || name === "Dockerfile") return true;
  if (name.startsWith("Dockerfile.") || name.endsWith(".Dockerfile")) return true;
  return TEXT_EXTS.has(extOf(path));
}

function sevPriority(sev: string): number {
  switch (sev) {
    case "critical": return 4;
    case "high":     return 3;
    case "medium":   return 2;
    case "low":      return 1;
    default:         return 0;
  }
}

function clearLine() {
  if (process.stdout.isTTY) process.stdout.write("\r\u001b[2K");
}

async function scanOne(absPath: string, rel: string, cache: ScanCache, minConfidence: number): Promise<{ findings: string[]; hadBlocker: boolean }> {
  let content: string;
  try { content = await readFile(absPath, "utf8"); } catch { return { findings: [], hadBlocker: false }; }
  const contentHash = sha256(content).slice(0, 16);

  const out: string[] = [];
  let hadBlocker = false;

  // Secrets.
  let secrets = cache.lookup<any>(absPath, "scan_for_secrets", contentHash);
  if (secrets === null) {
    secrets = await scanText(content, rel);
    cache.store(absPath, "scan_for_secrets", contentHash, secrets);
  }
  for (const f of secrets as any[]) {
    if ((f.confidence ?? 100) < minConfidence) continue;
    if (sevPriority(f.severity) >= sevPriority("high")) hadBlocker = true;
    out.push(`  [${f.severity.toUpperCase()}] L${f.line}  ${f.type}  conf=${f.confidence ?? "?"}`);
  }

  // Code rules.
  let code = cache.lookup<any>(absPath, "scan_code", contentHash);
  if (code === null) {
    code = scanCodeRules(content);
    cache.store(absPath, "scan_code", contentHash, code);
  }
  for (const f of code as any[]) {
    if (sevPriority(f.severity) >= sevPriority("high")) hadBlocker = true;
    out.push(`  [${f.severity.toUpperCase()}] L${f.line}  ${f.title}  (${f.ruleId})`);
  }

  return { findings: out, hadBlocker };
}

export async function runWatch(opts: WatchOptions = {}): Promise<number> {
  const root = resolve(opts.root ?? process.cwd());
  const minConfidence = opts.minConfidence ?? 60;
  const debounceMs = opts.debounceMs ?? 120;

  const st = await stat(root).catch(() => null);
  if (!st || !st.isDirectory()) {
    console.error(`ironward watch: ${root} is not a directory.`);
    return 2;
  }

  const cache = await ScanCache.load();
  const ign = new IgnoreMatcher(root, [
    ...DEFAULT_IGNORE_PATTERNS,
    ...(await IgnoreMatcher.fromFiles(root, [`${root}/.gitignore`, `${root}/.ironwardignore`])).rules.map((r) => r.raw),
  ]);

  console.log(`🛡  Ironward watching ${relative(process.cwd(), root) || "."}  — Ctrl-C to stop`);
  console.log(`   hiding findings below confidence ${minConfidence}; set --verbose for all`);
  console.log("");

  // Debounced per-file scan queue.
  const pending = new Set<string>();
  let timer: NodeJS.Timeout | null = null;
  let inFlight = 0;
  let scans = 0;
  let blockers = 0;

  async function drain(): Promise<void> {
    const batch = [...pending];
    pending.clear();
    timer = null;
    inFlight++;
    try {
      for (const absPath of batch) {
        const rel = relative(root, absPath) || absPath;
        if (ign.ignores(absPath, false)) continue;
        if (!isScannable(absPath)) continue;
        const st2 = await stat(absPath).catch(() => null);
        if (!st2 || !st2.isFile()) continue;
        const result = await scanOne(absPath, rel, cache, minConfidence);
        scans++;
        if (result.findings.length > 0) {
          clearLine();
          console.log(`${new Date().toTimeString().slice(0, 8)}  ${rel}`);
          for (const line of result.findings) console.log(line);
          if (result.hadBlocker) blockers++;
        } else {
          clearLine();
          if (process.stdout.isTTY) process.stdout.write(`✓ ${rel}  (${scans} scans, ${blockers} blockers)`);
        }
      }
      await cache.save().catch(() => {/* best-effort */});
    } finally {
      inFlight--;
    }
  }

  function schedule(absPath: string): void {
    pending.add(absPath);
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { void drain(); }, debounceMs);
  }

  let watcher: FSWatcher;
  try {
    watcher = fsWatch(root, { recursive: true, persistent: true }, (_evt, filename) => {
      if (!filename) return;
      const abs = resolve(root, filename);
      schedule(abs);
    });
  } catch (err) {
    console.error(`ironward watch failed to start: ${(err as Error).message}`);
    return 2;
  }

  if (opts.onReady) opts.onReady();

  return await new Promise<number>((resolvePromise) => {
    const cleanup = () => {
      try { watcher.close(); } catch {}
      if (timer) clearTimeout(timer);
      clearLine();
      console.log(`\nStopped. ${scans} scans, ${blockers} blockers.`);
      resolvePromise(blockers > 0 ? 1 : 0);
    };

    if (opts.signal) {
      if (opts.signal.aborted) { cleanup(); return; }
      opts.signal.addEventListener("abort", cleanup, { once: true });
    }
    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);
  });
}
