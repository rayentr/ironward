import { test } from "node:test";
import assert from "node:assert/strict";
import {
  colorForScore,
  computeSecurityScore,
  shieldsBadgeUrl,
  renderBadge,
  renderBadgeSvg,
  updateReadmeBadge,
} from "../src/integrations/badge.ts";
import type { NormalizedFinding } from "../src/engines/sarif.ts";

function f(severity: NormalizedFinding["severity"], i = 0): NormalizedFinding {
  return {
    ruleId: `r-${severity}-${i}`,
    severity,
    title: `Issue ${i}`,
    description: "x",
    file: `src/file${i}.ts`,
    line: i + 1,
    tool: "scan_code",
  };
}

// ───────────────────────────────────────────────
// colorForScore — boundary cases
// ───────────────────────────────────────────────
test("colorForScore boundaries", () => {
  assert.equal(colorForScore(0), "red");
  assert.equal(colorForScore(39), "red");
  assert.equal(colorForScore(40), "orange");
  assert.equal(colorForScore(59), "orange");
  assert.equal(colorForScore(60), "yellow");
  assert.equal(colorForScore(74), "yellow");
  assert.equal(colorForScore(75), "green");
  assert.equal(colorForScore(89), "green");
  assert.equal(colorForScore(90), "brightgreen");
  assert.equal(colorForScore(100), "brightgreen");
});

// ───────────────────────────────────────────────
// computeSecurityScore
// ───────────────────────────────────────────────
test("computeSecurityScore — empty array → 100", () => {
  assert.equal(computeSecurityScore([]), 100);
});

test("computeSecurityScore — single critical → 85", () => {
  assert.equal(computeSecurityScore([f("critical")]), 85);
});

test("computeSecurityScore — clamps to 0 when overwhelmed", () => {
  const many: NormalizedFinding[] = [];
  for (let i = 0; i < 20; i++) many.push(f("critical", i));
  for (let i = 0; i < 20; i++) many.push(f("high", i));
  for (let i = 0; i < 20; i++) many.push(f("medium", i));
  for (let i = 0; i < 20; i++) many.push(f("low", i));
  // Penalty caps: 75 + 56 + 30 + 10 = 171 → clamped to 0.
  assert.equal(computeSecurityScore(many), 0);
});

test("computeSecurityScore — caps respected (5 critical = -75 then capped)", () => {
  const findings: NormalizedFinding[] = [];
  for (let i = 0; i < 10; i++) findings.push(f("critical", i));
  // 10*15=150 → capped at -75 → 25.
  assert.equal(computeSecurityScore(findings), 25);
});

// ───────────────────────────────────────────────
// shieldsBadgeUrl
// ───────────────────────────────────────────────
test("shieldsBadgeUrl includes ?logo=shield and the score", () => {
  const url = shieldsBadgeUrl({ score: 87 });
  assert.match(url, /^https:\/\/img\.shields\.io\/badge\//);
  assert.ok(url.includes("87%2F100"), `expected encoded score in URL: ${url}`);
  assert.ok(url.includes("?logo=shield"), `expected ?logo=shield in URL: ${url}`);
});

// ───────────────────────────────────────────────
// renderBadge
// ───────────────────────────────────────────────
test("renderBadge('markdown') produces a valid Markdown image link", () => {
  const md = renderBadge(75, "markdown", "https://example.com/report");
  assert.match(md, /^\[!\[/);
  assert.ok(md.includes("https://img.shields.io/badge/"));
  assert.ok(md.endsWith("(https://example.com/report)"));
});

test("renderBadge('html') produces a valid <img> tag", () => {
  const html = renderBadge(75, "html");
  assert.match(html, /<img\s+src="https:\/\/img\.shields\.io\/badge\/[^"]+"/);
  assert.ok(html.includes("alt="));
});

test("renderBadge('url') returns a URL string", () => {
  const u = renderBadge(50, "url");
  assert.match(u, /^https:\/\/img\.shields\.io\/badge\//);
});

test("renderBadge('json') returns Shields-compatible JSON", () => {
  const j = JSON.parse(renderBadge(50, "json"));
  assert.equal(j.schemaVersion, 1);
  assert.equal(j.label, "security");
  assert.equal(j.message, "50/100");
  assert.equal(j.color, "orange");
});

// ───────────────────────────────────────────────
// renderBadgeSvg
// ───────────────────────────────────────────────
test("renderBadgeSvg returns a string starting with <svg", () => {
  const svg = renderBadgeSvg(85);
  assert.ok(svg.startsWith("<svg"));
  assert.ok(svg.includes("85/100"));
});

// ───────────────────────────────────────────────
// updateReadmeBadge
// ───────────────────────────────────────────────
test("updateReadmeBadge inserts badge after first H1 when none exists", () => {
  const md = `# My Project\n\nSome description here.\n`;
  const out = updateReadmeBadge(md, 88, "https://example.com");
  assert.ok(out.includes("<!-- ironward-badge -->"));
  assert.ok(out.includes("<!-- /ironward-badge -->"));
  assert.ok(out.includes("https://img.shields.io/badge/"));
  assert.ok(out.includes("](https://example.com)"));
  // Heading should still be first
  const lines = out.split("\n");
  assert.equal(lines[0], "# My Project");
});

test("updateReadmeBadge inserts at top when no H1 exists", () => {
  const md = `Just plain text without heading.\n`;
  const out = updateReadmeBadge(md, 88, "https://example.com");
  assert.ok(out.startsWith("<!-- ironward-badge -->"));
});

test("updateReadmeBadge replaces existing badge in markers", () => {
  const md = `# My Project\n\n<!-- ironward-badge -->[![old](https://old.example/badge)](https://old.example)<!-- /ironward-badge -->\n\nBody\n`;
  const out = updateReadmeBadge(md, 99, "https://new.example");
  assert.ok(!out.includes("https://old.example"), "old badge should be gone");
  assert.ok(out.includes("https://new.example"), "new link should be present");
  // Only one badge block.
  const matches = out.match(/<!-- ironward-badge -->/g) ?? [];
  assert.equal(matches.length, 1);
});
