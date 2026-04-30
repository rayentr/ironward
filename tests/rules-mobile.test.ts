import { test } from "node:test";
import assert from "node:assert/strict";
import { MOBILE_SECURITY_RULES } from "../src/rules/mobile-security.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = MOBILE_SECURITY_RULES.find((r) => r.id === ruleId);
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

// WHY: storing an auth token in plaintext AsyncStorage on a mobile device is the
// canonical mobile credential leak.
test("rn-asyncstorage-sensitive: setItem('authToken', ...) is flagged", () => {
  const code = `await AsyncStorage.setItem('authToken', token);`;
  assert.equal(fire(code, "rn-asyncstorage-sensitive"), true);
});

// WHY: a non-secret key (theme preference) must not flag.
test("rn-asyncstorage-sensitive: setItem('themeMode', ...) is NOT flagged", () => {
  const code = `await AsyncStorage.setItem('themeMode', 'dark');`;
  assert.equal(fire(code, "rn-asyncstorage-sensitive"), false);
});

test("rn-asyncstorage-sensitive: metadata is well-formed", () => {
  // WHY: lock severity at high — credential at rest in plaintext.
  const r = MOBILE_SECURITY_RULES.find((x) => x.id === "rn-asyncstorage-sensitive")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: cleartext fetch to a public host on a mobile device — must fire.
test("rn-fetch-http: fetch('http://api.example.com') is flagged", () => {
  const code = `const r = await fetch('http://api.example.com/v1/users');`;
  assert.equal(fire(code, "rn-fetch-http"), true);
});

// WHY: localhost fetch is a normal dev pattern; must not flag.
test("rn-fetch-http: fetch('http://localhost:3000') is NOT flagged", () => {
  const code = `const r = await fetch('http://localhost:3000/dev');`;
  assert.equal(fire(code, "rn-fetch-http"), false);
});

test("rn-fetch-http: metadata is well-formed", () => {
  // WHY: severity high — passive interception is trivial on mobile networks.
  const r = MOBILE_SECURITY_RULES.find((x) => x.id === "rn-fetch-http")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: secret bundled into expo `extra` is the most common Expo footgun.
test("rn-expo-config-secret: extra.apiKey literal is flagged", () => {
  const code = `module.exports = { expo: { extra: { apiKey: 'sk_live_abc123def456' } } };`;
  assert.equal(fire(code, "rn-expo-config-secret"), true);
});

// WHY: extra with a public-by-design publishable key value is fine if it doesn't
// match the secret-shaped key list (e.g. publishableKey).
test("rn-expo-config-secret: extra.publishableKey is NOT flagged", () => {
  const code = `module.exports = { expo: { extra: { publishableKey: 'pk_test_xyz' } } };`;
  assert.equal(fire(code, "rn-expo-config-secret"), false);
});

test("rn-expo-config-secret: metadata is critical", () => {
  // WHY: severity critical — secret is in every shipped binary.
  const r = MOBILE_SECURITY_RULES.find((x) => x.id === "rn-expo-config-secret")!;
  assert.equal(r.severity, "critical");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: dev-only return that bypasses an auth/cert check leaks once a dev build
// escapes; this is the canonical pattern.
test("rn-debug-mode-skip: if (__DEV__) return; is flagged", () => {
  const code = `function pinCert() { if (__DEV__) return; verifyPin(); }`;
  assert.equal(fire(code, "rn-debug-mode-skip"), true);
});

// WHY: a regular if (__DEV__) console.log block (no return) must not flag.
test("rn-debug-mode-skip: if (__DEV__) console.log is NOT flagged", () => {
  const code = `if (__DEV__) console.log('init');`;
  assert.equal(fire(code, "rn-debug-mode-skip"), false);
});

test("rn-debug-mode-skip: metadata is well-formed", () => {
  // WHY: severity high — a leaked dev build becomes a permanent bypass.
  const r = MOBILE_SECURITY_RULES.find((x) => x.id === "rn-debug-mode-skip")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: reading a secret-shaped key out of Constants.manifest.extra means it's
// bundled.
test("rn-react-native-keys-bundled: Constants.manifest.extra.apiSecret is flagged", () => {
  const code = `const k = Constants.manifest.extra.apiSecret;`;
  assert.equal(fire(code, "rn-react-native-keys-bundled"), true);
});

// WHY: reading a non-secret-shaped value (theme, version) must not flag.
test("rn-react-native-keys-bundled: Constants.manifest.extra.theme is NOT flagged", () => {
  const code = `const k = Constants.manifest.extra.theme;`;
  assert.equal(fire(code, "rn-react-native-keys-bundled"), false);
});

test("rn-react-native-keys-bundled: metadata is well-formed", () => {
  // WHY: severity high — values bundled at build time are extractable.
  const r = MOBILE_SECURITY_RULES.find((x) => x.id === "rn-react-native-keys-bundled")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
