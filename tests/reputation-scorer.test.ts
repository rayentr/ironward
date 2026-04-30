import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFile, readFile, unlink } from "node:fs/promises";
import {
  scorePackage,
  scoreToFinding,
  CachingNpmReputationFetcher,
  type NpmPackageMeta,
} from "../src/engines/reputation-scorer.ts";

const NOW = new Date("2026-04-23T00:00:00Z");
const DAY = 86400000;

function daysAgo(d: number): string {
  return new Date(NOW.getTime() - d * DAY).toISOString();
}

test("heavy-hitter package scores 'trusted' (>= 80)", () => {
  const meta: NpmPackageMeta = {
    name: "react",
    weeklyDownloads: 25_000_000,
    created: daysAgo(365 * 8),
    modified: daysAgo(30),
    maintainerCount: 12,
    repository: "git+https://github.com/facebook/react.git",
    homepage: "https://reactjs.org",
    latestVersion: "18.3.1",
    dependents: 250_000,
  };
  const result = scorePackage(meta, NOW);
  assert.ok(result.score >= 80, `expected score >= 80, got ${result.score}`);
  assert.equal(result.band, "trusted");
});

test("abandoned package scores 'danger' (< 40)", () => {
  const meta: NpmPackageMeta = {
    name: "left-behind",
    weeklyDownloads: 17,
    created: daysAgo(365 * 6),
    modified: daysAgo(365 * 5),
    maintainerCount: 1,
    repository: null,
    homepage: null,
    latestVersion: "0.2.1",
  };
  const result = scorePackage(meta, NOW);
  assert.ok(result.score < 40, `expected score < 40, got ${result.score}`);
  assert.equal(result.band, "danger");
});

test("sudden 10x download spike applies -15 signal", () => {
  const meta: NpmPackageMeta = {
    name: "spikey",
    weeklyDownloads: 50_000,
    weeklyDownloadsPrev: 4_000,
    created: daysAgo(365 * 3),
    modified: daysAgo(20),
    maintainerCount: 2,
    repository: "git+https://github.com/x/spikey.git",
    homepage: "https://example.com",
    latestVersion: "1.0.0",
  };
  const result = scorePackage(meta, NOW);
  const spike = result.signals.find((s) => s.reason.includes("spike"));
  assert.ok(spike, "expected spike signal");
  assert.equal(spike!.kind, "-");
  assert.equal(spike!.points, 15);
});

test("maintainer changed recently applies -20 signal", () => {
  const meta: NpmPackageMeta = {
    name: "handed-off",
    weeklyDownloads: 5_000,
    created: daysAgo(365 * 4),
    modified: daysAgo(60),
    maintainerCount: 2,
    repository: "https://github.com/x/handed-off",
    homepage: "https://example.com",
    latestVersion: "2.0.0",
    maintainerChangedRecently: true,
  };
  const result = scorePackage(meta, NOW);
  const sig = result.signals.find((s) => s.reason.includes("maintainer changed"));
  assert.ok(sig, "expected maintainer-change signal");
  assert.equal(sig!.kind, "-");
  assert.equal(sig!.points, 20);
});

test("score is clamped to [0, 100]", () => {
  // Pile on every negative signal possible
  const worst: NpmPackageMeta = {
    name: "garbage",
    weeklyDownloads: 1,
    weeklyDownloadsPrev: 0,
    created: daysAgo(365 * 10),
    modified: daysAgo(365 * 6),
    maintainerCount: 1,
    repository: null,
    homepage: null,
    latestVersion: "0.0.1",
    maintainerChangedRecently: true,
  };
  const low = scorePackage(worst, NOW);
  assert.ok(low.score >= 0 && low.score <= 100, `score out of range: ${low.score}`);
  assert.equal(low.score, 0);

  // Pile on every positive signal possible
  const best: NpmPackageMeta = {
    name: "perfect",
    weeklyDownloads: 50_000_000,
    created: daysAgo(365 * 10),
    modified: daysAgo(7),
    maintainerCount: 25,
    repository: "git+https://github.com/x/perfect.git",
    homepage: "https://example.com",
    latestVersion: "5.0.0",
    dependents: 100_000,
  };
  const high = scorePackage(best, NOW);
  assert.ok(high.score >= 0 && high.score <= 100, `score out of range: ${high.score}`);
  assert.equal(high.score, 100);
});

test("scoreToFinding returns null for 'trusted' band", () => {
  const meta: NpmPackageMeta = {
    name: "react",
    weeklyDownloads: 25_000_000,
    created: daysAgo(365 * 8),
    modified: daysAgo(30),
    maintainerCount: 12,
    repository: "git+https://github.com/facebook/react.git",
    homepage: "https://reactjs.org",
    latestVersion: "18.3.1",
    dependents: 250_000,
  };
  const score = scorePackage(meta, NOW);
  assert.equal(score.band, "trusted");
  assert.equal(scoreToFinding("react", "18.3.1", "package.json", score), null);
});

test("scoreToFinding returns null for 'caution' band", () => {
  const score = { score: 70, band: "caution" as const, signals: [] };
  assert.equal(scoreToFinding("foo", "1.0.0", "package.json", score), null);
});

test("scoreToFinding returns 'high' severity for 'danger' band", () => {
  const meta: NpmPackageMeta = {
    name: "shady",
    weeklyDownloads: 5,
    created: daysAgo(365 * 6),
    modified: daysAgo(365 * 5),
    maintainerCount: 1,
    repository: null,
    homepage: null,
    latestVersion: "0.1.0",
  };
  const score = scorePackage(meta, NOW);
  assert.equal(score.band, "danger");
  const finding = scoreToFinding("shady", "0.1.0", "package.json", score);
  assert.ok(finding, "expected a finding");
  assert.equal(finding!.severity, "high");
  assert.equal(finding!.package, "shady");
  assert.equal(finding!.version, "0.1.0");
  assert.ok(finding!.summary.includes("reputation score"));
  assert.ok(finding!.evidence && finding!.evidence.length > 0, "expected evidence text");
});

test("scoreToFinding returns 'medium' severity for 'warning' band", () => {
  const score = { score: 50, band: "warning" as const, signals: [{ kind: "-" as const, points: 10, reason: "no repository" }] };
  const finding = scoreToFinding("meh", "1.0.0", "package.json", score);
  assert.ok(finding);
  assert.equal(finding!.severity, "medium");
  assert.equal(finding!.evidence, "no repository");
});

test("CachingNpmReputationFetcher returns cached meta within TTL", async () => {
  const cachePath = join(tmpdir(), `ironward-rep-test-${Date.now()}-cached.json`);
  const cachedMeta: NpmPackageMeta = {
    name: "cached-pkg",
    weeklyDownloads: 12345,
    modified: daysAgo(10),
    created: daysAgo(1000),
    latestVersion: "2.0.0",
    maintainerCount: 3,
    repository: "https://github.com/x/cached-pkg",
    homepage: null,
  };
  const cacheFile = {
    "cached-pkg": { fetchedAt: Date.now(), meta: cachedMeta },
  };
  await writeFile(cachePath, JSON.stringify(cacheFile));

  let calls = 0;
  const fakeFetch = (async () => {
    calls++;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;

  const f = new CachingNpmReputationFetcher({
    cachePath,
    ttlMs: 60_000,
    fetchImpl: fakeFetch,
  });
  const meta = await f.fetch("cached-pkg");
  assert.deepEqual(meta, cachedMeta);
  assert.equal(calls, 0, "should not call network when cache is fresh");
  await unlink(cachePath).catch(() => {});
});

test("CachingNpmReputationFetcher: graceful degradation when fetchImpl rejects", async () => {
  const cachePath = join(tmpdir(), `ironward-rep-test-${Date.now()}-reject.json`);
  const fakeFetch = (async () => {
    throw new Error("network exploded");
  }) as unknown as typeof fetch;

  const f = new CachingNpmReputationFetcher({
    cachePath,
    ttlMs: 60_000,
    fetchImpl: fakeFetch,
  });
  const meta = await f.fetch("missing-pkg");
  assert.equal(meta, null);
  await unlink(cachePath).catch(() => {});
});

test("CachingNpmReputationFetcher: timeout aborts fetch and returns null", async () => {
  const cachePath = join(tmpdir(), `ironward-rep-test-${Date.now()}-timeout.json`);
  const slowFetch = ((_url: string, init?: { signal?: AbortSignal }) => {
    return new Promise((_resolve, reject) => {
      const onAbort = () => {
        const err = new Error("aborted");
        (err as Error & { name: string }).name = "AbortError";
        reject(err);
      };
      if (init?.signal) {
        if (init.signal.aborted) {
          onAbort();
          return;
        }
        init.signal.addEventListener("abort", onAbort, { once: true });
      }
      // Never resolve otherwise — relies on the abort.
    });
  }) as unknown as typeof fetch;

  const f = new CachingNpmReputationFetcher({
    cachePath,
    ttlMs: 60_000,
    timeoutMs: 30,
    fetchImpl: slowFetch,
  });
  const start = Date.now();
  const meta = await f.fetch("slow-pkg");
  const elapsed = Date.now() - start;
  assert.equal(meta, null);
  assert.ok(elapsed < 1500, `expected timeout to fire quickly, took ${elapsed}ms`);
  await unlink(cachePath).catch(() => {});
});

test("CachingNpmReputationFetcher: maps registry response to NpmPackageMeta and writes cache", async () => {
  const cachePath = join(tmpdir(), `ironward-rep-test-${Date.now()}-write.json`);
  const fakeFetch = (async (url: string) => {
    if (url.includes("/downloads/point/")) {
      return new Response(JSON.stringify({ downloads: 9999 }), { status: 200 });
    }
    return new Response(
      JSON.stringify({
        time: { modified: "2025-01-01T00:00:00Z", created: "2020-01-01T00:00:00Z" },
        "dist-tags": { latest: "3.4.5" },
        maintainers: [{ name: "alice" }, { name: "bob" }],
        repository: { url: "git+https://github.com/x/y.git" },
        homepage: "https://example.com",
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;

  const f = new CachingNpmReputationFetcher({
    cachePath,
    ttlMs: 60_000,
    fetchImpl: fakeFetch,
  });
  const meta = await f.fetch("some-pkg");
  assert.ok(meta);
  assert.equal(meta!.latestVersion, "3.4.5");
  assert.equal(meta!.maintainerCount, 2);
  assert.equal(meta!.repository, "git+https://github.com/x/y.git");
  assert.equal(meta!.homepage, "https://example.com");
  assert.equal(meta!.weeklyDownloads, 9999);

  // Cache should be persisted on disk.
  const raw = await readFile(cachePath, "utf8");
  const parsed = JSON.parse(raw);
  assert.ok(parsed["some-pkg"]);
  assert.equal(parsed["some-pkg"].meta.latestVersion, "3.4.5");
  await unlink(cachePath).catch(() => {});
});
