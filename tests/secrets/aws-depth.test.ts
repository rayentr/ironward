import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// canonical AKIA values that don't include "EXAMPLE" — the engine drops anything
// containing the EXAMPLE/PLACEHOLDER tokens. Synthetic IDs only.
const AWS_AKID = "AKIA2E0A8F3B244C9986";
const AWS_SECRET = "wJalrXUtnFEMIxK7MDENGbPxRfiCYEXAMPLEKEYz";  // 40 chars, ironward-ignore — but EXAMPLEKEY token present so engine drops it
// Use a non-placeholder 40-char synthetic value.
const AWS_SECRET_REAL = "abCDefGHijKLmnOPqrSTuvWXyz0123456789ab12";  // 40 chars
// Engine treats 6+ identical chars as placeholder, so build a long varied base64 token.
const AWS_SESSION =
  "FQoGZXIvYXdzEBYaDAaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh1J2K3L4M5N6O7P8Q9R0Sa";
const AWS_MWS = "amzn.mws.4ea38b7b-f563-46d9-8d85-1c5b2a7e9f10";

// ============================================================
// aws_access_key (AKIA...)
// ============================================================

// WHY: basic — canonical AKIA-prefixed key in a variable assignment must fire critical.
test("aws_access_key: basic detection in variable", async () => {
  const code = `const accessKey = '${AWS_AKID}';`;
  const f = await findFor(code, "aws_access_key");
  assert.ok(f, "expected aws_access_key finding");
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — key buried in a config object should still fire.
test("aws_access_key: object property", async () => {
  const code = `const config = { aws: { accessKeyId: '${AWS_AKID}' } };`;
  const f = await findFor(code, "aws_access_key");
  assert.ok(f);
});

// WHY: template literal — Bearer-style usage in template should still fire (AKIA pattern is bare-token).
test("aws_access_key: template literal", async () => {
  const code = "const auth = `AWS ${'" + AWS_AKID + "'}:sig`;";
  const f = await findFor(code, "aws_access_key");
  assert.ok(f);
});

// WHY: false-positive — explicit placeholder must not fire (engine has placeholder filter).
test("aws_access_key: placeholder NOT flagged", async () => {
  const code = `const accessKey = 'YOUR_AWS_ACCESS_KEY_HERE';`;
  const f = await findFor(code, "aws_access_key");
  assert.equal(f, undefined);
});

// WHY: false-positive — env reference (process.env.AWS_ACCESS_KEY_ID) is the safe shape.
test("aws_access_key: env reference NOT flagged", async () => {
  const code = `const accessKey = process.env.AWS_ACCESS_KEY_ID;`;
  const f = await findFor(code, "aws_access_key");
  assert.equal(f, undefined);
});

// ============================================================
// aws_secret_key_contextual (40 chars after aws_secret_access_key=)
// ============================================================

// WHY: basic — canonical 40-char value with the contextual prefix fires.
test("aws_secret_key_contextual: basic detection with prefix", async () => {
  const code = `aws_secret_access_key=${AWS_SECRET_REAL}`;
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.ok(f, "expected aws_secret_key_contextual finding");
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — prefix-containing assignment in object form should fire.
test("aws_secret_key_contextual: object property", async () => {
  const code = `const cfg = { aws_secret_access_key: '${AWS_SECRET_REAL}' };`;
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.ok(f);
});

// WHY: template literal — prefix in a template still triggers contextual rule.
test("aws_secret_key_contextual: template literal", async () => {
  const code = "const line = `aws_secret_access_key=" + AWS_SECRET_REAL + "`;";
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.ok(f);
});

// WHY: placeholder — well-known placeholder must not fire (engine has placeholder filter).
test("aws_secret_key_contextual: placeholder NOT flagged", async () => {
  const code = `aws_secret_access_key=YOUR_AWS_SECRET_KEY_HERE_PLACEHOLDER____________`;
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.equal(f, undefined);
});

// WHY: env reference — referencing process.env (no inline secret) must not fire.
test("aws_secret_key_contextual: env reference NOT flagged", async () => {
  const code = `const secret = process.env.AWS_SECRET_ACCESS_KEY;`;
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.equal(f, undefined);
});

// ============================================================
// aws_session_token
// ============================================================

// WHY: basic — long session token after the prefix fires critical.
test("aws_session_token: basic detection with prefix", async () => {
  const code = `aws_session_token=${AWS_SESSION}`;
  const f = await findFor(code, "aws_session_token");
  assert.ok(f, "expected aws_session_token finding");
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — token in an object literal still fires.
test("aws_session_token: object property", async () => {
  const code = `const cfg = { aws_session_token: '${AWS_SESSION}' };`;
  const f = await findFor(code, "aws_session_token");
  assert.ok(f);
});

// WHY: template literal — token interpolated in a template fires.
test("aws_session_token: template literal", async () => {
  const code = "const v = `aws_session_token=" + AWS_SESSION + "`;";
  const f = await findFor(code, "aws_session_token");
  assert.ok(f);
});

// WHY: placeholder — explicit placeholder text must not fire.
test("aws_session_token: placeholder NOT flagged", async () => {
  const code = `aws_session_token=YOUR_AWS_SESSION_TOKEN_HERE_PLACEHOLDER` + "x".repeat(80);
  const f = await findFor(code, "aws_session_token");
  assert.equal(f, undefined);
});

// WHY: env reference — process.env access alone should not fire the secret pattern.
test("aws_session_token: env reference NOT flagged", async () => {
  const code = `const t = process.env.AWS_SESSION_TOKEN;`;
  const f = await findFor(code, "aws_session_token");
  assert.equal(f, undefined);
});

// ============================================================
// aws_mws_auth_token (amzn.mws.<uuid>)
// ============================================================

// WHY: basic — canonical amzn.mws.<uuid> string fires.
test("aws_mws_auth_token: basic detection", async () => {
  const code = `const mws = '${AWS_MWS}';`;
  const f = await findFor(code, "aws_mws_auth_token");
  assert.ok(f, "expected aws_mws_auth_token finding");
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — token nested in config still fires.
test("aws_mws_auth_token: object property", async () => {
  const code = `const cfg = { mws: { authToken: '${AWS_MWS}' } };`;
  const f = await findFor(code, "aws_mws_auth_token");
  assert.ok(f);
});

// WHY: template literal — token in a template fires.
test("aws_mws_auth_token: template literal", async () => {
  const code = "const auth = `Bearer " + AWS_MWS + "`;";
  const f = await findFor(code, "aws_mws_auth_token");
  assert.ok(f);
});

// WHY: placeholder — clearly synthetic placeholder doesn't fire.
test("aws_mws_auth_token: placeholder NOT flagged", async () => {
  const code = `const mws = 'YOUR_MWS_AUTH_TOKEN_PLACEHOLDER';`;
  const f = await findFor(code, "aws_mws_auth_token");
  assert.equal(f, undefined);
});

// WHY: env reference — process.env reference must not fire the pattern.
test("aws_mws_auth_token: env reference NOT flagged", async () => {
  const code = `const mws = process.env.AWS_MWS_AUTH_TOKEN;`;
  const f = await findFor(code, "aws_mws_auth_token");
  assert.equal(f, undefined);
});
