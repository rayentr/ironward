import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreConfidence, confidenceTier } from "../src/engines/confidence.ts";

test("pattern match with secret-named variable scores high", () => {
  const r = scoreConfidence({
    match: "AKIAIOSFODNN7EXXX123",
    line: 'const AWS_SECRET_KEY = "AKIAIOSFODNN7EXXX123";',
    path: "src/config.ts",
    source: "pattern",
    severity: "critical",
  });
  assert.ok(r.score >= 85, `expected >= 85, got ${r.score}`);
  assert.ok(["high", "definite"].includes(confidenceTier(r.score)));
});

test("fixture path penalizes confidence", () => {
  const r = scoreConfidence({
    match: "AKIAIOSFODNN7EXXX123",
    line: 'const AWS_SECRET_KEY = "AKIAIOSFODNN7EXXX123";',
    path: "tests/fixtures/leaky.js",
    source: "pattern",
    severity: "critical",
  });
  // Fixture-path penalty (-30) drops from ~90 to ~60.
  assert.ok(r.score < 80, `expected < 80, got ${r.score}`);
});

test("// example comment on same line suppresses hard", () => {
  const r = scoreConfidence({
    match: "sk_live_abcdefghijklmnop",
    line: '// example: sk_live_abcdefghijklmnop',
    path: "src/README.ts",
    source: "pattern",
    severity: "critical",
  });
  assert.ok(r.score < 60, `expected suppressed/low, got ${r.score}`);
});

test("entropy-sourced finding in docs scores low", () => {
  const r = scoreConfidence({
    match: "someRandomLookingStringThatIsntReallySecret",
    line: 'The token string could be "someRandomLookingStringThatIsntReallySecret"',
    path: "docs/API.md",
    source: "entropy",
    entropy: 4.8,
    severity: "medium",
  });
  assert.ok(r.score < 60, `docs+entropy should be low: got ${r.score}`);
});

test("tier mapping covers definite/high/medium/low/suppressed", () => {
  assert.equal(confidenceTier(95), "definite");
  assert.equal(confidenceTier(80), "high");
  assert.equal(confidenceTier(65), "medium");
  assert.equal(confidenceTier(50), "low");
  assert.equal(confidenceTier(30), "suppressed");
});

test("reasons include readable signal names", () => {
  const r = scoreConfidence({
    match: "xyz",
    line: 'const API_KEY = "xyz"',
    path: "src/foo.ts",
    source: "pattern",
  });
  assert.ok(r.reasons.some((s) => /pattern match/.test(s)));
  assert.ok(r.reasons.some((s) => /secret-named/.test(s)));
});
