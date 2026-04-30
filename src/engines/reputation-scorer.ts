import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { DepIntelFinding } from "./dep-intel.js";

// ──────────────────────────────────────────────────────────────
// Reputation scorer for npm packages.
// Combines weekly downloads, publish recency, maintainer counts,
// repo/homepage presence, version maturity, dependents counts,
// download spikes, and recent maintainer changes into a 0-100
// score with a band ("trusted" / "caution" / "warning" / "danger").
// ──────────────────────────────────────────────────────────────

export interface NpmPackageMeta {
  name: string;
  modified?: string | Date | null;
  created?: string | Date | null;
  latestVersion?: string | null;
  maintainerCount?: number;
  repository?: string | null;
  homepage?: string | null;
  weeklyDownloads?: number | null;
  weeklyDownloadsPrev?: number | null;
  dependents?: number | null;
  maintainerChangedRecently?: boolean | null;
}

export interface ReputationScore {
  score: number;
  band: "trusted" | "caution" | "warning" | "danger";
  signals: Array<{ kind: "+" | "-"; points: number; reason: string }>;
}

const DAY_MS = 86400000;
const YEAR_MS = 365 * DAY_MS;

function toDate(v: string | Date | null | undefined): Date | null {
  if (!v) return null;
  if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

function parseMajor(version: string | null | undefined): number | null {
  if (!version) return null;
  const m = /^v?(\d+)/.exec(version.trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

export function scorePackage(meta: NpmPackageMeta, now: Date = new Date()): ReputationScore {
  const signals: Array<{ kind: "+" | "-"; points: number; reason: string }> = [];
  let score = 50;

  const add = (kind: "+" | "-", points: number, reason: string) => {
    signals.push({ kind, points, reason });
    score += kind === "+" ? points : -points;
  };

  // Weekly downloads — positive tier
  const wd = meta.weeklyDownloads;
  if (wd != null && wd > 1_000_000) {
    add("+", 20, "weekly downloads > 1M");
  } else if (wd != null && wd > 100_000) {
    add("+", 15, "weekly downloads > 100K");
  } else if (wd != null && wd > 10_000) {
    add("+", 10, "weekly downloads > 10K");
  }

  const created = toDate(meta.created);
  if (created && now.getTime() - created.getTime() > 2 * YEAR_MS) {
    add("+", 10, "package created over 2 years ago");
  }

  const modified = toDate(meta.modified);
  if (modified && now.getTime() - modified.getTime() < YEAR_MS) {
    add("+", 10, "published within the last year");
  }

  if (meta.maintainerCount != null && meta.maintainerCount > 1) {
    add("+", 5, "multiple maintainers");
  }

  if (meta.repository && meta.repository.trim().length > 0) {
    add("+", 5, "repository present");
  }

  if (meta.homepage && meta.homepage.trim().length > 0) {
    add("+", 3, "homepage present");
  }

  const major = parseMajor(meta.latestVersion ?? null);
  if (major != null && major >= 1) {
    add("+", 5, "latest version major >= 1");
  }

  if (meta.dependents != null && meta.dependents > 1000) {
    add("+", 10, "more than 1000 dependents");
  }

  // Negative signals
  if (modified) {
    const ageMs = now.getTime() - modified.getTime();
    if (ageMs > 4 * YEAR_MS) {
      add("-", 30, "no recent publish (>4y)");
    } else if (ageMs > 2 * YEAR_MS) {
      add("-", 15, "no recent publish (>2y)");
    }
  }

  if (meta.maintainerCount === 1) {
    add("-", 5, "single maintainer");
  }

  if (wd != null && wd < 100) {
    add("-", 20, "weekly downloads < 100");
  } else if (wd != null && wd < 1000) {
    add("-", 10, "weekly downloads < 1000");
  }

  if (meta.repository == null || (typeof meta.repository === "string" && meta.repository.trim().length === 0)) {
    add("-", 10, "no repository");
  }

  if (major === 0) {
    add("-", 5, "pre-1.0 release (major === 0)");
  }

  if (
    meta.weeklyDownloadsPrev != null &&
    meta.weeklyDownloads != null &&
    meta.weeklyDownloads >= 10 * meta.weeklyDownloadsPrev
  ) {
    add("-", 15, "sudden 10x download spike (possible typosquat)");
  }

  if (meta.maintainerChangedRecently === true) {
    add("-", 20, "maintainer changed in the last 6 months");
  }

  // Clamp
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  let band: ReputationScore["band"];
  if (score >= 80) band = "trusted";
  else if (score >= 60) band = "caution";
  else if (score >= 40) band = "warning";
  else band = "danger";

  return { score, band, signals };
}

// ──────────────────────────────────────────────────────────────
// Reputation fetcher with on-disk cache (24h TTL by default).
// Pulls /registry.npmjs.org/{name} and /downloads/point/last-week
// in parallel, with a per-request timeout. Caps concurrency to 10
// underlying network calls.
// ──────────────────────────────────────────────────────────────

export interface ReputationFetcher {
  fetch(name: string): Promise<NpmPackageMeta | null>;
}

interface CacheEntry {
  fetchedAt: number;
  meta: NpmPackageMeta;
}

interface CacheFile {
  [name: string]: CacheEntry;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_CONCURRENT_FETCHES = 10;

function defaultCachePath(): string {
  return join(homedir(), ".ironward", "npm-cache.json");
}

interface RegistryRoot {
  time?: { modified?: string; created?: string } & Record<string, string>;
  "dist-tags"?: { latest?: string };
  maintainers?: unknown[];
  repository?: { url?: string } | string;
  homepage?: string;
}

interface DownloadsPoint {
  downloads?: number;
}

export class CachingNpmReputationFetcher implements ReputationFetcher {
  private readonly cachePath: string;
  private readonly ttlMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private cache: CacheFile | null = null;
  private cacheLoaded = false;
  private active = 0;
  private waiters: Array<() => void> = [];

  constructor(opts?: {
    cachePath?: string;
    ttlMs?: number;
    timeoutMs?: number;
    fetchImpl?: typeof fetch;
  }) {
    this.cachePath = opts?.cachePath ?? defaultCachePath();
    this.ttlMs = opts?.ttlMs ?? DEFAULT_TTL_MS;
    this.timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = opts?.fetchImpl ?? fetch;
  }

  private async loadCache(): Promise<CacheFile> {
    if (this.cacheLoaded && this.cache) return this.cache;
    try {
      const raw = await readFile(this.cachePath, "utf8");
      const parsed = JSON.parse(raw) as CacheFile;
      this.cache = parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      this.cache = {};
    }
    this.cacheLoaded = true;
    return this.cache;
  }

  private async saveCache(): Promise<void> {
    if (!this.cache) return;
    try {
      await mkdir(dirname(this.cachePath), { recursive: true, mode: 0o700 });
      await writeFile(this.cachePath, JSON.stringify(this.cache), { mode: 0o600 });
    } catch {
      // Best-effort: ignore write failures.
    }
  }

  private async acquire(): Promise<void> {
    if (this.active < MAX_CONCURRENT_FETCHES) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
    this.active++;
  }

  private release(): void {
    this.active--;
    const next = this.waiters.shift();
    if (next) next();
  }

  private async fetchWithTimeout(url: string): Promise<unknown | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, { signal: controller.signal });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async fetch(name: string): Promise<NpmPackageMeta | null> {
    const cache = await this.loadCache();
    const cached = cache[name];
    const now = Date.now();
    if (cached && now - cached.fetchedAt < this.ttlMs) {
      return cached.meta;
    }

    await this.acquire();
    let registry: RegistryRoot | null = null;
    let downloads: DownloadsPoint | null = null;
    try {
      const encoded = encodeURIComponent(name);
      const [r, d] = await Promise.all([
        this.fetchWithTimeout(`https://registry.npmjs.org/${encoded}`),
        this.fetchWithTimeout(`https://api.npmjs.org/downloads/point/last-week/${encoded}`),
      ]);
      registry = r as RegistryRoot | null;
      downloads = d as DownloadsPoint | null;
    } finally {
      this.release();
    }

    if (!registry) return null;

    const repoRaw = registry.repository;
    const repository = typeof repoRaw === "string"
      ? repoRaw
      : (repoRaw && typeof repoRaw === "object" && typeof repoRaw.url === "string" ? repoRaw.url : null);

    const meta: NpmPackageMeta = {
      name,
      modified: registry.time?.modified ?? null,
      created: registry.time?.created ?? null,
      latestVersion: registry["dist-tags"]?.latest ?? null,
      maintainerCount: Array.isArray(registry.maintainers) ? registry.maintainers.length : 0,
      repository,
      homepage: typeof registry.homepage === "string" ? registry.homepage : null,
      weeklyDownloads: downloads && typeof downloads.downloads === "number" ? downloads.downloads : null,
    };

    cache[name] = { fetchedAt: now, meta };
    await this.saveCache();
    return meta;
  }
}

// ──────────────────────────────────────────────────────────────
// Score → DepIntelFinding bridge. Returns null for healthy
// packages so the orchestrator only emits findings when there's
// something worth flagging.
// ──────────────────────────────────────────────────────────────

export function scoreToFinding(
  packageName: string,
  packageVersion: string,
  source: string,
  score: ReputationScore,
): DepIntelFinding | null {
  if (score.band === "trusted" || score.band === "caution") return null;

  const severity: DepIntelFinding["severity"] = score.band === "danger" ? "high" : "medium";
  const evidence = score.signals
    .filter((s) => s.kind === "-")
    .map((s) => s.reason)
    .join(", ");

  return {
    package: packageName,
    version: packageVersion,
    ecosystem: "npm",
    source,
    kind: "reputation" as DepIntelFinding["kind"],
    severity,
    summary: `${packageName}@${packageVersion} reputation score ${score.score}/100 (${score.band})`,
    evidence: evidence || undefined,
  };
}
