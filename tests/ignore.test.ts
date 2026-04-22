import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IgnoreMatcher, compilePattern, DEFAULT_IGNORE_PATTERNS } from "../src/engines/ignore.ts";

test("compilePattern handles simple glob", () => {
  const r = compilePattern("*.log")!;
  assert.ok(r.regex.test("foo.log"));
  assert.ok(r.regex.test("sub/foo.log"));
  assert.ok(!r.regex.test("foo.txt"));
});

test("compilePattern handles anchored root", () => {
  const r = compilePattern("/build")!;
  assert.ok(r.regex.test("build"));
  assert.ok(r.regex.test("build/index.js"));
  assert.ok(!r.regex.test("src/build"));
});

test("compilePattern handles unanchored dir name", () => {
  const r = compilePattern("node_modules")!;
  assert.ok(r.regex.test("node_modules"));
  assert.ok(r.regex.test("src/node_modules/foo"));
});

test("compilePattern handles trailing slash as dir-only", () => {
  const r = compilePattern("dist/")!;
  assert.equal(r.dirOnly, true);
});

test("compilePattern handles negation", () => {
  const r = compilePattern("!keep.log")!;
  assert.equal(r.negate, true);
  assert.ok(r.regex.test("keep.log"));
});

test("compilePattern handles ** globstar", () => {
  const r = compilePattern("**/generated/*.ts")!;
  assert.ok(r.regex.test("src/deep/nested/generated/foo.ts"));
  assert.ok(r.regex.test("generated/foo.ts"));
});

test("compilePattern skips comments and empty", () => {
  assert.equal(compilePattern("# a comment"), null);
  assert.equal(compilePattern(""), null);
  assert.equal(compilePattern("   "), null);
});

test("IgnoreMatcher respects negation ordering", () => {
  const m = new IgnoreMatcher("/root", ["*.log", "!keep.log"]);
  assert.equal(m.ignores("/root/any.log", false), true);
  assert.equal(m.ignores("/root/keep.log", false), false);
});

test("IgnoreMatcher with default patterns hides node_modules + dist + min.js", () => {
  const m = new IgnoreMatcher("/root", DEFAULT_IGNORE_PATTERNS);
  assert.equal(m.ignores("/root/node_modules", true), true);
  assert.equal(m.ignores("/root/node_modules/foo/index.js", false), true);
  assert.equal(m.ignores("/root/dist/build.js", false), true);
  assert.equal(m.ignores("/root/app.min.js", false), true);
  assert.equal(m.ignores("/root/src/app.js", false), false);
});

test("IgnoreMatcher treats paths outside root as not-ignored", () => {
  const m = new IgnoreMatcher("/root", ["*"]);
  assert.equal(m.ignores("/elsewhere/foo", false), false);
});

test("IgnoreMatcher loads from .ironwardignore file", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "ignore-test-"));
  try {
    writeFileSync(join(scratch, ".ironwardignore"), "# my rules\nsecrets/\n*.pem\n");
    mkdirSync(join(scratch, "secrets"));
    writeFileSync(join(scratch, "secrets", "real.key"), "xxx");
    writeFileSync(join(scratch, "cert.pem"), "-----BEGIN");
    writeFileSync(join(scratch, "keep.txt"), "ok");

    const m = await IgnoreMatcher.fromFiles(scratch, [join(scratch, ".ironwardignore")]);
    assert.equal(m.ignores(join(scratch, "secrets"), true), true);
    assert.equal(m.ignores(join(scratch, "secrets/real.key"), false), true);
    assert.equal(m.ignores(join(scratch, "cert.pem"), false), true);
    assert.equal(m.ignores(join(scratch, "keep.txt"), false), false);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
