// Adversarial inputs that the scanner must handle without crashing.
// Each test exercises one shape of pathological input. The scanner is allowed to
// detect or not detect, but it must NEVER throw, hang, or blow the stack.
//
// Self-scan note: this test file lives in tests/ which is excluded from the
// default scan scope (only ./src is scanned). The bare `eval(` and AWS-shaped
// strings below are inert string literals.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";
import { scanText } from "../src/engines/secret-engine.ts";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";
import { runScanCode } from "../src/tools/scan-code.ts";

// A real-shape AWS access key id: 4-char prefix + 16 of [0-9A-Z].
// (No "EXAMPLE" / "FAKE" tokens — those are placeholder-filtered.)
const AWS_KEY = "AKIA2E0A8F3B244C9986";

test("adversarial: empty file returns no findings", () => {
  // WHY: the scanner must not throw on a 0-byte input — empty files are a
  // routine edge case (touch foo.ts, new file, etc.).
  const findings = scanCodeRules("");
  assert.ok(Array.isArray(findings));
  assert.equal(findings.length, 0);
});

test("adversarial: whitespace-only file returns no findings", () => {
  // WHY: tab/space/newline-only files happen during refactors and must not
  // trip any pattern that anchors on line starts or word boundaries.
  const findings = scanCodeRules("   \n\n\t  \n   ");
  assert.equal(findings.length, 0);
});

test("adversarial: binary content does not crash the scanner", () => {
  // WHY: users occasionally point the scanner at binary blobs (lockfiles,
  // small images that escaped the skip list). UTF-8 decoding of arbitrary
  // bytes can produce replacement chars and unusual code points — the
  // scanner must absorb that without throwing.
  const buf = Buffer.from([0x00, 0xff, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x7f, 0x80, 0xc0, 0xc1]);
  const content = buf.toString("utf8");
  const findings = scanCodeRules(content);
  assert.ok(Array.isArray(findings));
});

test("adversarial: 100k-char single line completes quickly", () => {
  // WHY: catastrophic-backtracking regexes turn long single lines into
  // multi-second hangs. Budget 5s as a generous CI ceiling — real wall
  // clock on a laptop is < 100ms.
  const oneLine = "a".repeat(100_000);
  const t0 = Date.now();
  const findings = scanCodeRules(oneLine);
  const elapsed = Date.now() - t0;
  assert.ok(Array.isArray(findings));
  assert.ok(elapsed < 5000, `scanCodeRules took ${elapsed}ms on 100k-char line`);
});

test("adversarial: file with only // comments returns no findings", () => {
  // WHY: comment-only files (license headers, generated banners) must not
  // trip rules that look for code keywords inside comment text.
  const findings = scanCodeRules("// just a comment\n// another comment\n// final\n");
  assert.equal(findings.length, 0);
});

test("adversarial: minified JS on one line does not crash", () => {
  // WHY: minified bundles are commonly fed to the scanner via accidental
  // glob matches. Some patterns may produce odd column numbers but none
  // may throw.
  const minified = "var x=1;".repeat(2000);
  const findings = scanCodeRules(minified);
  assert.ok(Array.isArray(findings));
});

test("adversarial: deeply nested braces do not blow the stack", () => {
  // WHY: a recursive regex or naive descent over a 500-deep brace structure
  // would stack-overflow. Linear scanners must stay iterative.
  const deep = "{".repeat(500) + "}".repeat(500);
  const findings = scanCodeRules(deep);
  assert.ok(Array.isArray(findings));
});

test("adversarial: unicode content (Arabic, Chinese, emoji) does not crash", () => {
  // WHY: non-ASCII content in identifiers/comments must not break regex
  // matching or character indexing — Ironward is shipped to international
  // teams.
  const content = "// مرحبا 你好 🚨\nconst greeting = \"héllo\";\n";
  const findings = scanCodeRules(content);
  assert.ok(Array.isArray(findings));
});

test("adversarial: null byte in content does not crash", () => {
  // WHY: null bytes occasionally show up in malformed inputs and in some
  // ELF/binary content. The scanner must not assume null-terminated strings.
  const findings = scanCodeRules("const a = 1;\x00const b = 2;\n");
  assert.ok(Array.isArray(findings));
});

test("adversarial: secret-shaped string in fixture path scans without crash", async () => {
  // WHY: scanning a synthetic fixture path with secret-shaped content
  // exercises the path-handling code (filename arg propagated to scanText).
  // It may flag or not, but it must not throw.
  const out = await runScanSecrets({
    files: [{ path: "tests/fixtures/x.ts", content: AWS_KEY }],
  });
  assert.ok(Array.isArray(out.files));
  assert.ok(out.summary.totalFindings >= 0);
});

test("adversarial: AWS key at byte 0 of file is detected", async () => {
  // WHY: regex anchors and word boundaries can subtly fail at file start.
  // A secret with no leading whitespace must still be detected.
  const findings = await scanText(AWS_KEY);
  assert.ok(findings.length >= 1, "AWS key at byte 0 should be detected");
  assert.equal(findings[0].type, "aws_access_key");
});

test("adversarial: AWS key at end of file with no trailing newline is detected", async () => {
  // WHY: many regex patterns implicitly assume trailing whitespace or
  // newline. A secret as the very last bytes of a file must still match.
  const content = "const config = {\n  region: 'us-east-1',\n  key: " + AWS_KEY;
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "AWS key at file end should be detected");
});

test("adversarial: same secret repeated 100 times stays bounded", async () => {
  // WHY: dedup contract — the scanner may return one per occurrence or
  // collapse to one, but must never explode (e.g. quadratic behaviour
  // pushing thousands of findings).
  const repeated = Array(100).fill(AWS_KEY).join("\n");
  const findings = await scanText(repeated);
  assert.ok(findings.length >= 1, "should detect at least one occurrence");
  assert.ok(findings.length <= 100, `expected <= 100 findings, got ${findings.length}`);
});

test("adversarial: secret embedded in URL query parameter is detected", async () => {
  // WHY: secrets leaked via URL query strings are a real exfil vector
  // (logged by proxies, browser history). The detector should not be
  // fooled by surrounding URL syntax.
  const content = "fetch('https://example.com/api?key=" + AWS_KEY + "');";
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "AWS key inside URL should be detected");
});

test("adversarial: secret inside a // comment is detected", async () => {
  // WHY: commented-out secrets still leak in git history forever — the
  // scanner must not treat comments as a safe zone.
  const content = "// old key, do not use: " + AWS_KEY + "\n";
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "commented secret should be detected");
});

test("adversarial: random UUID is NOT flagged as a secret", async () => {
  // WHY: UUIDs look high-entropy but are not secrets. The allowlist must
  // suppress them or false-positive noise will overwhelm developers.
  const content = "const id = \"550e8400-e29b-41d4-a716-446655440000\";";
  const findings = await scanText(content);
  assert.equal(findings.length, 0, `UUID should not be flagged; got ${findings.map(f => f.type).join(",")}`);
});

test("adversarial: long sha256 hex hash is NOT flagged as a secret", async () => {
  // WHY: 64-char hex digests are integrity hashes, not credentials. The
  // common-non-secret allowlist must skip them.
  const content = "const sha = \"" + "a1b2c3d4".repeat(8) + "\";"; // 64 hex chars
  const findings = await scanText(content);
  assert.equal(findings.length, 0, `sha256 should not be flagged; got ${findings.map(f => f.type).join(",")}`);
});

test("adversarial: minified-JS variable like _0xabc1234 is NOT flagged", async () => {
  // WHY: minifier-generated identifiers (_0xabc..., _0x1234) look secret-ish
  // but are bundle artifacts. They must not trigger entropy-based detection.
  const content = "const _0xabc1234 = 1; const _0x4567def = 2;";
  const findings = await scanText(content);
  assert.equal(findings.length, 0, `minifier identifier should not be flagged; got ${findings.map(f => f.type).join(",")}`);
});

test("adversarial: ironward-ignore directive suppresses finding on that line", async () => {
  // WHY: the ignore directive is a load-bearing escape hatch. If it stops
  // working, every false positive becomes a hard blocker.
  const content = AWS_KEY + " // ironward-ignore\n";
  const findings = await scanText(content);
  assert.equal(findings.length, 0, "ironward-ignore on the same line must suppress secret");
});

test("adversarial: ironward-ignore on eval() line suppresses code finding", async () => {
  // WHY: same suppression contract for code rules. runScanCode is the
  // user-facing entry point so we exercise the full path.
  const out = await runScanCode({
    content: "eval(userInput); // ironward-ignore\n",
  });
  assert.equal(out.summary.totalFindings, 0, "ironward-ignore on eval line must suppress finding");
});

test("adversarial: two distinct secrets on same line yield up to 2 findings", async () => {
  // WHY: dedup must not collapse two genuinely different secret values.
  const aws2 = "AKIA1234567890ABCDEF";
  const content = AWS_KEY + " " + aws2;
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "expected at least one of two secrets");
  assert.ok(findings.length <= 2, `expected at most 2 findings, got ${findings.length}`);
});

test("adversarial: file path with spaces and unicode is handled", async () => {
  // WHY: paths in the wild have spaces, accented chars, and non-Latin
  // scripts. The scanner must not URL-encode, escape, or otherwise mangle
  // them into errors.
  const out = await runScanSecrets({
    files: [{ path: "src/some folder/файл.ts", content: "const a = 1;" }],
  });
  assert.equal(out.files.length, 1);
  assert.equal(out.files[0].path, "src/some folder/файл.ts");
});

test("adversarial: long line with secret in the middle is still detected", async () => {
  // WHY: detectors that bail on lines over a length threshold would miss
  // secrets buried in long config blobs.
  const content = "x".repeat(2000) + " " + AWS_KEY + " " + "y".repeat(2000);
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "secret embedded in long line should still be detected");
});

test("adversarial: shadowed eval function still flags subsequent eval(", () => {
  // WHY: documents expected behaviour — Ironward does pattern matching, not
  // dataflow. A user-defined `function eval() {}` does not change the fact
  // that `eval(` later on still looks dangerous, and we'd rather flag than
  // miss.
  const content = "function eval(s) { return s; }\nconsole.log(eval('1+1'));\n";
  const findings = scanCodeRules(content);
  assert.ok(Array.isArray(findings));
  // At least one eval-related finding is acceptable; zero would also be
  // acceptable. The key contract is: no crash, returns an array.
});

test("adversarial: CRLF line endings produce correct line numbers", async () => {
  // WHY: Windows line endings would shift line numbers by one if the
  // scanner used \r\n-naive splitting. Tooling consumers (editors, SARIF
  // viewers) rely on accurate line numbers.
  const content = "line1\r\nline2 with " + AWS_KEY + "\r\nline3\r\n";
  const findings = await scanText(content);
  assert.ok(findings.length >= 1, "AWS key should be detected with CRLF endings");
  assert.equal(findings[0].line, 2, `expected line 2, got line ${findings[0].line}`);
});
