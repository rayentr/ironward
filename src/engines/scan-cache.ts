import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export type ScanTool = "scan_for_secrets" | "scan_code";

interface CacheEntry {
  hash: string;
  findings: unknown[];
}

interface CacheFile {
  ironwardVersion: string;
  patternsHash: string;
  engineHash: string;
  entries: Record<string, Record<string, CacheEntry>>;
}

let CACHED_PATTERNS_HASH: string | null = null;
let CACHED_ENGINE_HASH: string | null = null;

export function sha256(s: string | Buffer): string {
  return createHash("sha256").update(s).digest("hex");
}

function cachePath(): string {
  return join(homedir(), ".ironward", "cache.json");
}

function getPkgVersion(): string {
  try {
    const pkg = require("../../package.json") as { version: string };
    return pkg.version;
  } catch {
    return "unknown";
  }
}

function getPatternsHash(): string {
  if (CACHED_PATTERNS_HASH) return CACHED_PATTERNS_HASH;
  try {
    // Hash the patterns file contents so a pattern update invalidates the cache.
    const patternsPath = require.resolve("../../patterns/secrets.json");
    const content = require("fs").readFileSync(patternsPath, "utf8");
    CACHED_PATTERNS_HASH = sha256(content).slice(0, 16);
    return CACHED_PATTERNS_HASH;
  } catch {
    CACHED_PATTERNS_HASH = "unknown";
    return CACHED_PATTERNS_HASH;
  }
}

/** Best-effort hash of the static-rules engine — invalidates cache when rules change. */
function getEngineHash(): string {
  if (CACHED_ENGINE_HASH) return CACHED_ENGINE_HASH;
  try {
    const p = require.resolve("../engines/code-rules.js");
    const content = require("fs").readFileSync(p, "utf8");
    CACHED_ENGINE_HASH = sha256(content).slice(0, 16);
    return CACHED_ENGINE_HASH;
  } catch {
    CACHED_ENGINE_HASH = "unknown";
    return CACHED_ENGINE_HASH;
  }
}

export class ScanCache {
  private data: CacheFile;
  private dirty = false;
  private readonly disabled: boolean;

  constructor(data: CacheFile, disabled = false) {
    this.data = data;
    this.disabled = disabled;
  }

  static async load(): Promise<ScanCache> {
    if (process.env.IRONWARD_NO_CACHE === "1") {
      return new ScanCache(ScanCache.fresh(), true);
    }
    try {
      const raw = await readFile(cachePath(), "utf8");
      const parsed = JSON.parse(raw) as CacheFile;
      // Invalidate if ironward version / patterns / engine changed.
      if (
        parsed.ironwardVersion !== getPkgVersion() ||
        parsed.patternsHash !== getPatternsHash() ||
        parsed.engineHash !== getEngineHash()
      ) {
        return new ScanCache(ScanCache.fresh());
      }
      if (!parsed.entries || typeof parsed.entries !== "object") {
        return new ScanCache(ScanCache.fresh());
      }
      return new ScanCache(parsed);
    } catch {
      return new ScanCache(ScanCache.fresh());
    }
  }

  static fresh(): CacheFile {
    return {
      ironwardVersion: getPkgVersion(),
      patternsHash: getPatternsHash(),
      engineHash: getEngineHash(),
      entries: {},
    };
  }

  /**
   * Return cached findings for (file, tool) if the content hash matches the stored entry.
   * `absPath` is used as the cache key — callers should pass the canonical absolute path.
   */
  lookup<T = unknown>(absPath: string, tool: ScanTool, contentHash: string): T[] | null {
    if (this.disabled) return null;
    const key = resolve(absPath);
    const perTool = this.data.entries[key];
    if (!perTool) return null;
    const entry = perTool[tool];
    if (!entry) return null;
    if (entry.hash !== contentHash) return null;
    return entry.findings as T[];
  }

  store(absPath: string, tool: ScanTool, contentHash: string, findings: unknown[]): void {
    if (this.disabled) return;
    const key = resolve(absPath);
    if (!this.data.entries[key]) this.data.entries[key] = {};
    this.data.entries[key][tool] = { hash: contentHash, findings };
    this.dirty = true;
  }

  /** Drop cache entries for files that no longer exist on disk. */
  prune(existingPaths: Set<string>): void {
    if (this.disabled) return;
    for (const key of Object.keys(this.data.entries)) {
      if (!existingPaths.has(key)) {
        delete this.data.entries[key];
        this.dirty = true;
      }
    }
  }

  async save(): Promise<void> {
    if (this.disabled || !this.dirty) return;
    const p = cachePath();
    await mkdir(dirname(p), { recursive: true, mode: 0o700 });
    await writeFile(p, JSON.stringify(this.data), { mode: 0o600 });
  }

  stats(): { files: number; entries: number } {
    let entries = 0;
    for (const perTool of Object.values(this.data.entries)) entries += Object.keys(perTool).length;
    return { files: Object.keys(this.data.entries).length, entries };
  }
}
