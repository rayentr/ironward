import { test } from "node:test";
import assert from "node:assert/strict";
import { SECRETS_MGMT_RULES } from "../src/rules/secrets-mgmt.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = SECRETS_MGMT_RULES.find((r) => r.id === ruleId);
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

// WHY: prod URL hardcoded next to an Authorization header is the canonical
// credential-pair leak.
test("secret-mgmt-hardcoded-prod-url: prod URL + Authorization is flagged", () => {
  const code = `fetch('https://api.production.com/v1/users', { headers: { Authorization: 'Bearer abc.def.ghi' } });`;
  assert.equal(fire(code, "secret-mgmt-hardcoded-prod-url"), true);
});

// WHY: env-driven base URL with no inline bearer must not flag.
test("secret-mgmt-hardcoded-prod-url: env URL only is NOT flagged", () => {
  const code = `fetch(process.env.API_URL + '/v1/users', { headers: { Authorization: token } });`;
  assert.equal(fire(code, "secret-mgmt-hardcoded-prod-url"), false);
});

test("secret-mgmt-hardcoded-prod-url: metadata is well-formed", () => {
  // WHY: severity high — both pieces required to attack are committed together.
  const r = SECRETS_MGMT_RULES.find((x) => x.id === "secret-mgmt-hardcoded-prod-url")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: a public IP literal is the canonical hit.
test("secret-mgmt-hardcoded-ip: public IP is flagged", () => {
  const code = `const host = '34.218.156.209';`;
  assert.equal(fire(code, "secret-mgmt-hardcoded-ip"), true);
});

// WHY: localhost / RFC1918 / 127. ranges must not flag.
test("secret-mgmt-hardcoded-ip: 127.0.0.1 is NOT flagged", () => {
  const code = `const host = '127.0.0.1';`;
  assert.equal(fire(code, "secret-mgmt-hardcoded-ip"), false);
});

test("secret-mgmt-hardcoded-ip: metadata is well-formed", () => {
  // WHY: medium severity — config hygiene + topology leak.
  const r = SECRETS_MGMT_RULES.find((x) => x.id === "secret-mgmt-hardcoded-ip")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: a real-shaped Stripe live secret literal is the most dangerous case —
// must fire even in a test-shaped file.
test("secret-mgmt-secret-in-test-file: sk_live_ literal is flagged", () => {
  const code = `const stripeKey = 'sk_live_abcdef0123456789ABCDEF0123';`;
  assert.equal(fire(code, "secret-mgmt-secret-in-test-file"), true);
});

// WHY: an obvious test-fixture placeholder must not flag.
test("secret-mgmt-secret-in-test-file: sk_test_ placeholder is NOT flagged", () => {
  const code = `const stripeKey = 'sk_test_FAKE_PLACEHOLDER';`;
  assert.equal(fire(code, "secret-mgmt-secret-in-test-file"), false);
});

test("secret-mgmt-secret-in-test-file: metadata is well-formed", () => {
  // WHY: severity high — secret in git history, must rotate.
  const r = SECRETS_MGMT_RULES.find((x) => x.id === "secret-mgmt-secret-in-test-file")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: .env.production reference next to a real-looking key=value pair = file
// is in the repo.
test("secret-mgmt-multiple-env-files-prod: .env.production with concrete value is flagged", () => {
  const code = `# .env.production\nSTRIPE_SECRET_KEY=sk_live_abcdef0123456789ABCDEF`;
  assert.equal(fire(code, "secret-mgmt-multiple-env-files-prod"), true);
});

// WHY: a docs reference to .env.production with template placeholders must not flag.
test("secret-mgmt-multiple-env-files-prod: .env.production placeholder doc is NOT flagged", () => {
  const code = `# Add a .env.production file. See README.`;
  assert.equal(fire(code, "secret-mgmt-multiple-env-files-prod"), false);
});

test("secret-mgmt-multiple-env-files-prod: metadata is well-formed", () => {
  // WHY: severity high — committed secrets file is a worst-case finding.
  const r = SECRETS_MGMT_RULES.find((x) => x.id === "secret-mgmt-multiple-env-files-prod")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: classic config.json with literal username + password = creds in source.
test("secret-mgmt-config-with-creds: literal username+password pair is flagged", () => {
  const code = `{ "username": "admin", "password": "hunter2hunter2" }`;
  assert.equal(fire(code, "secret-mgmt-config-with-creds"), true);
});

// WHY: templated values (${ENV} or <PLACEHOLDER>) must not flag.
test("secret-mgmt-config-with-creds: templated password is NOT flagged", () => {
  const code = `{ "username": "admin", "password": "\${DB_PASSWORD}" }`;
  assert.equal(fire(code, "secret-mgmt-config-with-creds"), false);
});

test("secret-mgmt-config-with-creds: metadata is well-formed", () => {
  // WHY: severity high — credential pair in git, must rotate.
  const r = SECRETS_MGMT_RULES.find((x) => x.id === "secret-mgmt-config-with-creds")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
