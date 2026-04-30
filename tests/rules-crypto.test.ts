import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("crypto: flags hardcoded all-zeros IV from Buffer.from hex", () => {
  const code = `const iv = Buffer.from("00000000000000000000000000000000", "hex");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-iv-all-zero-buffer"));
});

test("crypto: flags Date.now() used as token source", () => {
  const code = `const resetToken = "tok_" + Date.now();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-date-now-as-token-source"));
});

test("crypto: flags pseudoRandomBytes use", () => {
  const code = `const x = crypto.pseudoRandomBytes(16);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-pseudo-random-bytes"));
});

test("crypto: flags hardcoded bcrypt salt literal", () => {
  const code = `await bcrypt.hash(pw, "$2b$10$abcdefghijklmnopqrstuv");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "bcrypt-hardcoded-salt-literal"));
});

test("crypto: flags PBKDF2 iterations below 100000", () => {
  const code = `crypto.pbkdf2(pw, salt, 1000, 32, "sha256", cb);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "pbkdf2-iterations-too-low"));
});

test("crypto: flags bcrypt with 8 rounds", () => {
  const code = `await bcrypt.hash(pw, 8);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "bcrypt-mid-salt-rounds-2026"));
});

test("crypto: flags createHmac with sha1", () => {
  const code = `crypto.createHmac("sha1", key);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "hmac-sha1-new-code"));
});

test("crypto: flags blowfish cipher", () => {
  const code = `crypto.createCipheriv("bf-cbc", key, iv);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "crypto-blowfish-cipher"));
});

test("crypto: does NOT flag bcrypt with 12 rounds", () => {
  const code = `await bcrypt.hash(pw, 12);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "bcrypt-mid-salt-rounds-2026"));
});

test("crypto: does NOT flag PBKDF2 with 600000 iterations", () => {
  const code = `crypto.pbkdf2(pw, salt, 600000, 32, "sha256", cb);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "pbkdf2-iterations-too-low"));
});
