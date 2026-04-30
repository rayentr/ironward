import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// =============================================================================
// Hardcoded IV variants (rule: crypto-iv-all-zero-buffer)
// =============================================================================

// WHY: canonical hex form of an all-zero IV must fire — primary case the rule
// was written for. Prevents accidental regex tightening from breaking detection.
test("crypto-depth: Buffer.from('00...00', 'hex') 32-char zero IV is flagged", () => {
  const code = `const iv = Buffer.from('00000000000000000000000000000000', 'hex');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-iv-all-zero-buffer"));
});

// WHY: an ASCII literal of zeros (no hex flag) is also a zero IV but the
// regex requires the 'hex' encoding marker — documents the gap.
test("crypto-depth: literal '0000000000000000' string IV WITHOUT hex flag is NOT flagged (documented gap)", () => {
  const code = `const iv = "0000000000000000";`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — rule requires Buffer.from(...,'hex') wrapper, so a
  // bare ASCII zero literal slips past. Lock in current behavior; if the rule
  // grows a literal-string variant, flip this assertion.
  assert.ok(!f.some((x) => x.ruleId === "crypto-iv-all-zero-buffer"));
});

// WHY: numeric-array Buffer.from is yet another way to express a zero IV but
// the regex is tied to the hex literal form. Document the gap.
test("crypto-depth: Buffer.from([0,0,...]) numeric array zero IV is NOT flagged (documented gap)", () => {
  const code = `const iv = Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — numeric-array constructor isn't covered by the
  // hex-string regex. Either expand the rule or accept this is documented.
  assert.ok(!f.some((x) => x.ruleId === "crypto-iv-all-zero-buffer"));
});

// =============================================================================
// ECB mode (rule: crypto-ecb-mode)
// =============================================================================

// WHY: aes-128-ecb must fire — it's the smallest concrete ECB cipher.
test("crypto-depth: createCipheriv('aes-128-ecb',...) is flagged as ECB", () => {
  const code = `crypto.createCipheriv('aes-128-ecb', key, null);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-ecb-mode"));
});

// WHY: aes-256-ecb is the highest-stakes concrete ECB call (people pick
// 256 thinking it's safe, but ECB defeats key size). Must fire.
test("crypto-depth: createCipheriv('aes-256-ecb',...) is flagged as ECB", () => {
  const code = `crypto.createCipheriv('aes-256-ecb', key, null);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-ecb-mode"));
});

// WHY: createCipher (legacy, no IV variant) with des-ecb must also be caught
// — the rule covers both createCipher and createCipheriv shapes.
test("crypto-depth: createCipher('des-ecb',...) is flagged as ECB", () => {
  const code = `crypto.createCipher('des-ecb', key);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-ecb-mode"));
});

// =============================================================================
// bcrypt rounds (rules: bcrypt-short-salt-rounds, bcrypt-mid-salt-rounds-2026)
// =============================================================================

// WHY: rounds 4 are squarely in the "short" rule (1-6). Must fire there.
test("crypto-depth: bcrypt.hash(pw, 4) is flagged as short rounds", () => {
  const code = `await bcrypt.hash(pw, 4);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "bcrypt-short-salt-rounds"));
});

// WHY: rounds 6 sits at the boundary of the short rule. Must still flag — if
// the regex tightens to [1-5] this breaks.
test("crypto-depth: bcrypt.hash(pw, 6) is flagged as short rounds", () => {
  const code = `await bcrypt.hash(pw, 6);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "bcrypt-short-salt-rounds"));
});

// WHY: rounds 7 is the lower boundary of the mid-rounds 2026 rule (7-9).
test("crypto-depth: bcrypt.hash(pw, 7) is flagged as mid-rounds 2026", () => {
  const code = `await bcrypt.hash(pw, 7);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "bcrypt-mid-salt-rounds-2026"));
});

// WHY: rounds 10/12/14 are safe — must NOT trip either bcrypt rule.
test("crypto-depth: bcrypt.hash(pw, 10|12|14) is NOT flagged", () => {
  for (const n of [10, 12, 14]) {
    const code = `await bcrypt.hash(pw, ${n});`;
    const f = scanCodeRules(code);
    assert.ok(
      !f.some((x) => x.ruleId === "bcrypt-short-salt-rounds"),
      `rounds=${n} unexpectedly flagged short`,
    );
    assert.ok(
      !f.some((x) => x.ruleId === "bcrypt-mid-salt-rounds-2026"),
      `rounds=${n} unexpectedly flagged mid`,
    );
  }
});

// =============================================================================
// RSA short keys (rule: crypto-short-rsa-key)
// =============================================================================

// WHY: 512-bit RSA is trivially factored — the highest-stakes positive case.
test("crypto-depth: generateKeyPair('rsa', { modulusLength: 512 }) is flagged critical", () => {
  const code = `crypto.generateKeyPair('rsa', { modulusLength: 512 }, cb);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "crypto-short-rsa-key");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: 1024-bit RSA is borderline-broken; must also fire.
test("crypto-depth: generateKeyPair('rsa', { modulusLength: 1024 }) is flagged", () => {
  const code = `crypto.generateKeyPair('rsa', { modulusLength: 1024 }, cb);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-short-rsa-key"));
});

// WHY: 2048-bit RSA is the recommended floor; must NOT flag.
test("crypto-depth: generateKeyPair('rsa', { modulusLength: 2048 }) is NOT flagged", () => {
  const code = `crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "crypto-short-rsa-key"));
});

// =============================================================================
// MD5 / SHA-1 variants (rules: md5-hash, sha1-hash)
// =============================================================================

// WHY: namespace-qualified createHash('md5') must fire — verifies the regex
// doesn't anchor to bareword form.
test("crypto-depth: crypto.createHash('md5') is flagged", () => {
  const code = `const h = crypto.createHash('md5').update(x).digest('hex');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "md5-hash"));
});

// WHY: SHA-1 with lower-case literal must fire.
test("crypto-depth: createHash('sha1') is flagged", () => {
  const code = `const h = crypto.createHash('sha1').update(x).digest('hex');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "sha1-hash"));
});

// WHY: SHA-1 with upper-case literal must fire — case-insensitive flag check.
test("crypto-depth: createHash('SHA1') uppercase is flagged", () => {
  const code = `const h = crypto.createHash('SHA1').update(x).digest('hex');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "sha1-hash"));
});

// =============================================================================
// Severity & OWASP metadata
// =============================================================================

// WHY: every security-critical crypto rule must carry severity=critical so
// totals/exit codes don't silently drift.
test("crypto-depth: critical-severity crypto rules really are critical", () => {
  const ids = [
    "crypto-iv-all-zero-buffer",
    "crypto-hardcoded-key-padend",
    "jwt-sign-short-literal-secret",
    "crypto-ecb-mode",
    "crypto-short-rsa-key",
    "crypto-short-aes-key",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: at least one cryptography-category rule must carry the OWASP A02:2021
// tag — that's the canonical mapping for crypto failures.
test("crypto-depth: at least one cryptography rule maps to OWASP A02:2021", () => {
  const cryptoRules = CODE_RULES.filter((r) => r.category === "cryptography");
  assert.ok(cryptoRules.length > 0);
  assert.ok(
    cryptoRules.some((r) => r.owasp && /^A02:2021/.test(r.owasp)),
    "expected at least one cryptography rule tagged A02:2021",
  );
});
