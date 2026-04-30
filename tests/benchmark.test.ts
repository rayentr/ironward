import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BENCHMARK_CASES,
  runBenchmarkCases,
  formatBenchmarkReport,
  type BenchmarkCase,
} from "../src/commands/benchmark.ts";

test("runBenchmarkCases([oneCase]) returns a result with totalCases: 1", async () => {
  const oneCase: BenchmarkCase = {
    id: "single-positive",
    category: "sql-injection",
    code: `db.query("SELECT * FROM u WHERE id=" + req.body.id);`,
    expectedRuleIds: ["sql-string-concat"],
  };
  const r = await runBenchmarkCases([oneCase]);
  assert.equal(r.totalCases, 1);
});

test("a correctly-detected case yields totalPassed: 1, detectionRate: 1", async () => {
  const c: BenchmarkCase = {
    id: "detected-case",
    category: "sql-injection",
    code: `db.query("SELECT * FROM u WHERE id=" + req.body.id);`,
    expectedRuleIds: ["sql-string-concat"],
  };
  const r = await runBenchmarkCases([c]);
  assert.equal(r.totalPassed, 1);
  assert.equal(r.detectionRate, 1);
});

test("a negative case that incorrectly triggers bumps falsePositiveCount", async () => {
  // This negative case uses an MD5 hash — the scanner *should* detect it,
  // so as a "negative" fixture it produces a false positive.
  const trips: BenchmarkCase = {
    id: "negative-that-triggers",
    category: "negative",
    code: `const h = createHash("md5").update("x").digest("hex");`,
    negative: true,
  };
  const r = await runBenchmarkCases([trips]);
  assert.equal(r.falsePositiveCount, 1);
  assert.ok(r.falsePositiveRate > 0);
});

test("runBenchmarkCases() (no args, full set) returns >=50 cases and detectionRate >= 0.85", async () => {
  const r = await runBenchmarkCases();
  assert.ok(r.totalCases >= 50, `expected >= 50 positive cases, got ${r.totalCases}`);
  assert.ok(
    r.detectionRate >= 0.85,
    `expected detection rate >= 0.85, got ${r.detectionRate.toFixed(3)} — failing cases: ${r.byCategory.flatMap((c) => c.failed.map((f) => f.id)).join(", ")}`,
  );
});

test("false-positive rate from the full suite is <= 0.2", async () => {
  const r = await runBenchmarkCases();
  assert.ok(
    r.falsePositiveRate <= 0.2,
    `expected FP rate <= 0.2, got ${r.falsePositiveRate.toFixed(3)} (${r.falsePositiveCount}/${r.falsePositiveTotal})`,
  );
});

test("formatBenchmarkReport includes header, per-category line, and Overall line", async () => {
  const r = await runBenchmarkCases();
  const text = formatBenchmarkReport(r);
  assert.match(text, /Detection Benchmark/);
  assert.match(text, /Overall:/);
  // At least one category line should appear (e.g. "SQL Injection:", "XSS:", etc.)
  assert.ok(
    /SQL Injection:|XSS:|Secret Detection:/.test(text),
    `expected a per-category line in report:\n${text}`,
  );
});

test("all BENCHMARK_CASES have unique ids", () => {
  const ids = new Set<string>();
  for (const c of BENCHMARK_CASES) {
    assert.ok(!ids.has(c.id), `duplicate id: ${c.id}`);
    ids.add(c.id);
  }
});

test("all BENCHMARK_CASES with negative: true have no expectedRuleIds", () => {
  for (const c of BENCHMARK_CASES) {
    if (!c.negative) continue;
    assert.ok(
      !c.expectedRuleIds || c.expectedRuleIds.length === 0,
      `negative case ${c.id} has expectedRuleIds`,
    );
  }
});
