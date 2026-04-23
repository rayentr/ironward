/**
 * JUnit XML output for Ironward findings.
 *
 * Lets findings appear in Jenkins / CircleCI / GitLab / Azure DevOps
 * test-result panels alongside regular test failures.
 *
 * Each finding becomes a failing testcase. Clean files (or clean scans)
 * produce passing testcases so the report shows zero-failure runs as green.
 */

import type { NormalizedFinding } from "./sarif.js";

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function attr(s: string): string { return `"${xmlEscape(s)}"`; }

export function buildJunit(findings: NormalizedFinding[], name = "Ironward"): string {
  const bySuite = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    const suite = f.tool;
    if (!bySuite.has(suite)) bySuite.set(suite, []);
    bySuite.get(suite)!.push(f);
  }

  let totalTests = 0;
  let totalFailures = 0;
  const suites: string[] = [];

  for (const [suite, items] of bySuite) {
    const tests = items.length;
    const failures = items.length; // every Ironward finding is a failure
    totalTests += tests;
    totalFailures += failures;

    const cases = items.map((f) => {
      const caseName = `${f.ruleId} at ${f.file}:${f.line}`;
      const detail = [
        `Severity: ${f.severity}`,
        `File: ${f.file}:${f.line}`,
        `Title: ${f.title}`,
        `Description: ${f.description}`,
      ].join("\n");
      return [
        `    <testcase classname=${attr(f.tool)} name=${attr(caseName)}>`,
        `      <failure message=${attr(f.title)} type=${attr(f.severity)}>`,
        xmlEscape(detail),
        `      </failure>`,
        `    </testcase>`,
      ].join("\n");
    }).join("\n");

    suites.push([
      `  <testsuite name=${attr(suite)} tests="${tests}" failures="${failures}" errors="0" skipped="0">`,
      cases,
      `  </testsuite>`,
    ].join("\n"));
  }

  // When there are zero findings, emit a single passing "clean" testcase
  // so CI panels render a green result rather than an empty one.
  if (suites.length === 0) {
    totalTests = 1;
    suites.push([
      `  <testsuite name="ironward" tests="1" failures="0" errors="0" skipped="0">`,
      `    <testcase classname="ironward" name="no findings"/>`,
      `  </testsuite>`,
    ].join("\n"));
  }

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<testsuites name=${attr(name)} tests="${totalTests}" failures="${totalFailures}" errors="0">`,
    suites.join("\n"),
    `</testsuites>`,
    "",
  ].join("\n");
}
