import { test } from "node:test";
import assert from "node:assert/strict";
import { DEP_SECURITY_RULES } from "../src/rules/dep-security.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = DEP_SECURITY_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    return true;
  }
  return false;
}

// WHY: pinning to "*" is the canonical floating-version anti-pattern.
test("dep-wildcard-version: \"*\" is flagged", () => {
  const code = `{ "dependencies": { "lodash": "*" } }`;
  assert.equal(fire(code, "dep-wildcard-version"), true);
});

// WHY: pinned semver must not flag.
test("dep-wildcard-version: pinned ^1.2.3 is NOT flagged", () => {
  const code = `{ "dependencies": { "lodash": "^1.2.3" } }`;
  assert.equal(fire(code, "dep-wildcard-version"), false);
});

test("dep-wildcard-version: metadata is well-formed", () => {
  // WHY: severity high — supply-chain risk, not a style issue.
  const r = DEP_SECURITY_RULES.find((x) => x.id === "dep-wildcard-version")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: postinstall is a frequent supply-chain attack vector.
test("dep-postinstall-script: postinstall present is flagged", () => {
  const code = `{ "scripts": { "postinstall": "node setup.js" } }`;
  assert.equal(fire(code, "dep-postinstall-script"), true);
});

// WHY: a normal `test` script must not flag.
test("dep-postinstall-script: only test script is NOT flagged", () => {
  const code = `{ "scripts": { "test": "node --test" } }`;
  assert.equal(fire(code, "dep-postinstall-script"), false);
});

test("dep-postinstall-script: metadata is well-formed", () => {
  // WHY: medium severity — needs human review of intent.
  const r = DEP_SECURITY_RULES.find((x) => x.id === "dep-postinstall-script")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: `npm install` in CI mutates the lockfile non-deterministically.
test("dep-npm-install-in-ci: bare `npm install` in CI is flagged", () => {
  const code = `jobs:\n  test:\n    steps:\n      - run: npm install\n      - run: npm test`;
  assert.equal(fire(code, "dep-npm-install-in-ci"), true);
});

// WHY: `npm ci` is the deterministic alternative.
test("dep-npm-install-in-ci: `npm ci` is NOT flagged", () => {
  const code = `jobs:\n  test:\n    steps:\n      - run: npm ci\n      - run: npm test`;
  assert.equal(fire(code, "dep-npm-install-in-ci"), false);
});

test("dep-npm-install-in-ci: metadata is well-formed", () => {
  // WHY: medium severity — reproducibility / supply-chain hardening, not direct RCE.
  const r = DEP_SECURITY_RULES.find((x) => x.id === "dep-npm-install-in-ci")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: jquery 1.x has known prototype pollution / XSS sinks.
test("dep-old-jquery: jquery@1.12 is flagged", () => {
  const code = `{ "dependencies": { "jquery": "1.12.4" } }`;
  assert.equal(fire(code, "dep-old-jquery"), true);
});

// WHY: jquery 3.7.1 (current) must not flag.
test("dep-old-jquery: jquery 3.7.1 is NOT flagged", () => {
  const code = `{ "dependencies": { "jquery": "3.7.1" } }`;
  assert.equal(fire(code, "dep-old-jquery"), false);
});

test("dep-old-jquery: metadata is well-formed", () => {
  // WHY: severity high — known CVEs, exploitable XSS sinks.
  const r = DEP_SECURITY_RULES.find((x) => x.id === "dep-old-jquery")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
