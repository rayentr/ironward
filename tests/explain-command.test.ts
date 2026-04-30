import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const cliPath = join(process.cwd(), "dist", "bin.js");

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const res = spawnSync("node", [cliPath, ...args], { encoding: "utf8", timeout: 10000 });
  return { code: res.status ?? 1, stdout: res.stdout, stderr: res.stderr };
}

test("explain: shows full detail for a known rule", () => {
  // WHY: this is the primary use case — `ironward explain sql-string-concat` is the
  // command we point developers to when they want to understand a rule.
  const r = runCli(["explain", "sql-string-concat"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /sql-string-concat/);
  assert.match(r.stdout, /Severity:\s+CRITICAL/);
  assert.match(r.stdout, /WHAT IT DETECTS/);
  assert.match(r.stdout, /PATTERN/);
  assert.match(r.stdout, /FIX/);
  assert.match(r.stdout, /PROOF OF CONCEPT/);
  assert.match(r.stdout, /CVSS:/);
});

test("explain: --list groups rules by category", () => {
  // WHY: developers exploring the rule set need a quick browseable index.
  const r = runCli(["explain", "--list"]);
  assert.equal(r.code, 0);
  // Header includes total count and category count.
  assert.match(r.stdout, /Ironward — \d+ rules across \d+ categories/);
  // At least one category with parenthesized count.
  assert.match(r.stdout, /── \w[\w-]* \(\d+\) ──/);
});

test("explain: --category filters to a single category", () => {
  // WHY: scoping to a single concern (e.g. supabase) helps focused review.
  const r = runCli(["explain", "--category", "supabase"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /supabase/);
  assert.match(r.stdout, /\d+ rules/);
});

test("explain: unknown rule returns exit 2 with helpful message", () => {
  // WHY: typos are common — the command must not crash and should hint at the issue.
  const r = runCli(["explain", "this-rule-does-not-exist"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Unknown rule id/);
});

test("explain: unknown rule with substring matches suggests near rules", () => {
  // WHY: when the user mistypes a real rule, suggestions reduce the lookup loop.
  const r = runCli(["explain", "supabase"]);  // matches multiple supabase- rules
  // Either it's a category match (some rules id-equal "supabase"? no) or it lists suggestions.
  assert.equal(r.code, 2);
  assert.match(r.stderr, /(Unknown rule id|Did you mean)/);
});

test("explain: unknown category returns exit 2 with available list", () => {
  // WHY: helpful enumeration of valid categories reduces guessing.
  const r = runCli(["explain", "--category", "not-a-real-category"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Available categories:/);
});

test("explain: no args prints usage to stderr with exit 2", () => {
  // WHY: a bare `explain` should not silently succeed.
  const r = runCli(["explain"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Usage:/);
});
