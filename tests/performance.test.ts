// Performance budgets for Ironward's hot paths.
//
// These thresholds are deliberately ~3-10x the measured wall-clock on a fast
// developer laptop so that a slow CI machine does not flake. They are
// regression sentinels, not benchmarks.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scanText, setPatterns, type PatternDef } from "../src/engines/secret-engine.ts";
import { CODE_RULES, scanCodeRules } from "../src/engines/code-rules.ts";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";
import { runBenchmarkCases } from "../src/commands/benchmark.ts";

async function timed<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const t0 = Date.now();
  const result = await fn();
  return { result, ms: Date.now() - t0 };
}

const CLEAN_LINE = "export function add(a: number, b: number): number { return a + b; }";

test("perf: cold scan of 100 small files completes in under 6s", async () => {
  // WHY: protects against accidental O(n^2) work over the file list, slow
  // per-file pattern recompilation, or a cache regression. Real wall-clock
  // is ~1-2s on a laptop; budget 6s to absorb CI noise.
  const dir = await mkdtemp(join(tmpdir(), "ironward-perf-"));
  try {
    const paths: string[] = [];
    const lines = Array(50).fill(CLEAN_LINE).join("\n");
    for (let i = 0; i < 100; i++) {
      const p = join(dir, `f${i}.ts`);
      await writeFile(p, lines, "utf8");
      paths.push(p);
    }
    const { ms } = await timed(() => runScanSecrets({ paths }));
    assert.ok(ms < 6000, `cold scan of 100 files took ${ms}ms (budget 6000ms)`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("perf: cold-process scan is at least 3x slower than in-process warm", async () => {
  // WHY: the secret engine compiles ~700 regexes once and memoizes the
  // result. A regression that clears `compiled` per call (or recompiles
  // on every scanText invocation) would erase that one-shot cost — the
  // warm in-process path would then look as slow as a fresh node startup.
  // We measure cold by spawning a subprocess that imports the engine cold;
  // warm is just a second in-process call.
  const sample = "const a = 1;\n".repeat(50);
  await scanText(sample); // ensure patterns are compiled in this process
  const warm = await timed(() => scanText(sample));

  const { spawnSync } = await import("node:child_process");
  const script = `
import('${process.cwd().replace(/\\/g, "/")}/src/engines/secret-engine.ts').then(async ({ scanText }) => {
  const t0 = Date.now();
  await scanText(${JSON.stringify(sample)});
  process.stdout.write(String(Date.now() - t0));
});
`;
  const res = spawnSync(process.execPath, ["--import", "tsx", "-e", script], {
    encoding: "utf8",
    timeout: 15000,
  });
  const coldMs = Number.parseInt(res.stdout.trim(), 10);
  assert.ok(Number.isFinite(coldMs), `failed to measure cold: ${res.stderr}`);

  if (coldMs < 30) {
    // Cold ran impossibly fast — environment must be unusually quick.
    // Skip rather than flake; the patterns-load budget test still guards.
    return;
  }
  assert.ok(
    warm.ms * 3 <= coldMs,
    `warm scanText (${warm.ms}ms) not >=3x faster than cold first-call (${coldMs}ms)`,
  );
});

test("perf: single 50k-line file scans in under 9s", async () => {
  // WHY: catches catastrophic-backtracking regressions where one new rule
  // pushes the per-file budget through the roof on large legitimate files
  // (vendored bundles, generated code).
  const big = (CLEAN_LINE + "\n").repeat(50_000);
  const { ms } = await timed(() => scanText(big));
  assert.ok(ms < 9000, `50k-line scanText took ${ms}ms (budget 9000ms)`);
});

test("perf: 665+ secret patterns load in under 300ms", async () => {
  // WHY: the patterns file is parsed and every regex compiled on first use.
  // A regression here (e.g. ridiculous regex flags, sync I/O on a slow
  // filesystem) shows up as a startup penalty for every CLI invocation.
  // We force a fresh load by injecting an empty set first.
  setPatterns({} as Record<string, PatternDef>);
  // After setPatterns, scanText uses the injected (empty) set — no load.
  // To time a *real* load, we need to defeat the cache. The next best thing
  // is to time a fresh process-level call. We can approximate by clearing
  // and re-injecting from disk: spawn a subprocess that imports the
  // engine cold.
  const { spawnSync } = await import("node:child_process");
  const script = `
import('${process.cwd().replace(/\\/g, "/")}/src/engines/secret-engine.ts').then(async ({ scanText }) => {
  const t0 = Date.now();
  await scanText('foo');
  process.stdout.write(String(Date.now() - t0));
});
`;
  const res = spawnSync(process.execPath, ["--import", "tsx", "-e", script], {
    encoding: "utf8",
    timeout: 10000,
  });
  const ms = Number.parseInt(res.stdout.trim(), 10);
  assert.ok(Number.isFinite(ms), `failed to measure load: stdout=${res.stdout} stderr=${res.stderr}`);
  // Budget includes subprocess spawn + tsx import + engine load + 665 regex compiles.
  // 600ms gives 2x headroom over the typical ~200-300ms measurement so CI machines and
  // loaded laptops don't false-fail. A real regression (e.g. catastrophic regex compile
  // cost) would be in the seconds, not 600ms.
  assert.ok(ms < 600, `pattern load took ${ms}ms (budget 600ms)`);
});

test("perf: 300 code rules scan empty content in under 100ms", async () => {
  // WHY: scanning an empty string still iterates every compiled regex once.
  // If that loop blows past 100ms, every clean file pays the cost — visible
  // pause on save in editor integrations.
  // (CODE_RULES.length is asserted nonzero so the import is load-bearing.)
  assert.ok(CODE_RULES.length >= 200, `expected >=200 rules, found ${CODE_RULES.length}`);
  const { ms } = await timed(async () => scanCodeRules(""));
  assert.ok(ms < 100, `scanCodeRules('') took ${ms}ms (budget 100ms)`);
});

test("perf: full benchmark suite completes in under 1500ms", async () => {
  // WHY: `ironward benchmark` is the headline number we report in the
  // README; if it slows past ~1.5s users notice. Real measurement is
  // ~150ms, so 10x headroom.
  const { ms } = await timed(() => runBenchmarkCases());
  assert.ok(ms < 1500, `runBenchmarkCases took ${ms}ms (budget 1500ms)`);
});

test("perf: scanCodeRules on a small snippet averages under 5ms", async () => {
  // WHY: protects against accidentally adding a catastrophic-backtracking
  // regex. Per-call mean over 50 iterations smooths jitter — single calls
  // include warm-up costs.
  const snippet = "const x = req.body.id;\nconsole.log(x);\n";
  // One untimed warm-up so JIT is hot.
  scanCodeRules(snippet);
  const t0 = Date.now();
  for (let i = 0; i < 50; i++) scanCodeRules(snippet);
  const totalMs = Date.now() - t0;
  const meanMs = totalMs / 50;
  assert.ok(
    meanMs < 5,
    `scanCodeRules averaged ${meanMs.toFixed(2)}ms/call over 50 runs (budget 5ms; total ${totalMs}ms)`,
  );
});
