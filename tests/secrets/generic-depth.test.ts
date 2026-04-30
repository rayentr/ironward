import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const SECRET_VAL = "x7Kp2mN9qR4wL8jY1Vd0Ze";
const TOKEN_VAL = "aBcDeFgH1J2K3L4M5N6O7P8Q9R0Sa";
const BCRYPT = "$2b$12$" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY1.2";

// ============================================================
// generic_password_assignment
// ============================================================

// WHY: password = "..." with a literal value is the canonical generic leak.
test("generic_password_assignment: basic detection", async () => {
  const f = await findFor(`password = "Sup3rS3cur3P@ss"`, "generic_password_assignment");
  assert.ok(f);
  assert.equal(f.severity, "medium");
});

// WHY: passwd alias variant.
test("generic_password_assignment: passwd alias", async () => {
  const f = await findFor(`passwd = "MyAdminP@ss123"`, "generic_password_assignment");
  assert.ok(f);
});

// WHY: pwd alias variant.
test("generic_password_assignment: pwd alias", async () => {
  const f = await findFor(`pwd = "MyAdminP@ss123"`, "generic_password_assignment");
  assert.ok(f);
});

// WHY: env reference is the safe pattern.
test("generic_password_assignment: env reference NOT flagged", async () => {
  const f = await findFor(`password = process.env.DB_PASSWORD`, "generic_password_assignment");
  assert.equal(f, undefined);
});

// WHY: a value <8 chars is too short to be a real password — must not fire.
test("generic_password_assignment: short value NOT flagged", async () => {
  const f = await findFor(`password = "short"`, "generic_password_assignment");
  assert.equal(f, undefined);
});

// ============================================================
// generic_secret_assignment
// ============================================================

// WHY: secret = "..." with a high-entropy value is the canonical leak.
test("generic_secret_assignment: secret basic detection", async () => {
  const f = await findFor(`secret = "${SECRET_VAL}"`, "generic_secret_assignment");
  assert.ok(f);
  assert.equal(f.severity, "medium");
});

// WHY: api_key alias variant.
test("generic_secret_assignment: api_key alias", async () => {
  const f = await findFor(`api_key = "${TOKEN_VAL}"`, "generic_secret_assignment");
  assert.ok(f);
});

// WHY: access_token alias.
test("generic_secret_assignment: access_token alias", async () => {
  const f = await findFor(`access_token = "${TOKEN_VAL}"`, "generic_secret_assignment");
  assert.ok(f);
});

// WHY: env reference is the safe pattern.
test("generic_secret_assignment: env reference NOT flagged", async () => {
  const f = await findFor(`secret = process.env.APP_SECRET`, "generic_secret_assignment");
  assert.equal(f, undefined);
});

// WHY: function call result (not literal) must not fire.
test("generic_secret_assignment: function call NOT flagged", async () => {
  const f = await findFor(`secret = generateSecret()`, "generic_secret_assignment");
  assert.equal(f, undefined);
});

// ============================================================
// generic_bearer_header
// ============================================================

// WHY: Authorization: Bearer <20+ chars> in a string literal — canonical leak.
test("generic_bearer_header: basic detection", async () => {
  const f = await findFor(`const h = "Authorization: Bearer ${TOKEN_VAL}";`, "generic_bearer_header");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: lowercase 'authorization' header still fires (case-insensitive rule).
test("generic_bearer_header: lowercase header", async () => {
  const f = await findFor(`const h = "authorization: bearer ${TOKEN_VAL}";`, "generic_bearer_header");
  assert.ok(f);
});

// WHY: header set via fetch headers object.
test("generic_bearer_header: fetch headers object", async () => {
  const f = await findFor(`fetch(url, { headers: { authorization: "Bearer ${TOKEN_VAL}" } });`, "generic_bearer_header");
  assert.ok(f);
});

// WHY: env reference safe.
test("generic_bearer_header: env reference NOT flagged", async () => {
  const f = await findFor(`const h = "Authorization: Bearer " + process.env.TOKEN;`, "generic_bearer_header");
  assert.equal(f, undefined);
});

// WHY: short bearer (less than 20 chars) must not fire.
test("generic_bearer_header: short bearer NOT flagged", async () => {
  const f = await findFor(`const h = "Authorization: Bearer abc";`, "generic_bearer_header");
  assert.equal(f, undefined);
});

// ============================================================
// generic_basic_auth_header
// ============================================================

// WHY: Authorization: Basic <base64> in a string literal — canonical leak.
test("generic_basic_auth_header: basic detection", async () => {
  const f = await findFor(`const h = "Authorization: Basic dXNlcjpwYXNzd29yZGFiY2RlZmdoaWprbA==";`, "generic_basic_auth_header");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: lowercase 'basic' still fires.
test("generic_basic_auth_header: lowercase basic", async () => {
  const f = await findFor(`const h = "authorization: basic dXNlcjpwYXNzd29yZGFiY2RlZmdoaWprbA==";`, "generic_basic_auth_header");
  assert.ok(f);
});

// WHY: header set via fetch headers object.
test("generic_basic_auth_header: fetch headers object", async () => {
  const f = await findFor(`fetch(url, { headers: { authorization: "Basic dXNlcjpwYXNzd29yZGFiY2RlZmdoaWprbA==" } });`, "generic_basic_auth_header");
  assert.ok(f);
});

// WHY: env reference safe.
test("generic_basic_auth_header: env reference NOT flagged", async () => {
  const f = await findFor(`const h = "Authorization: Basic " + process.env.BASIC_AUTH;`, "generic_basic_auth_header");
  assert.equal(f, undefined);
});

// WHY: short basic (less than 20 chars) must not fire.
test("generic_basic_auth_header: short basic NOT flagged", async () => {
  const f = await findFor(`const h = "Authorization: Basic abc";`, "generic_basic_auth_header");
  assert.equal(f, undefined);
});

// ============================================================
// htpasswd_bcrypt
// ============================================================

// WHY: $2b$12$... bcrypt hash — must fire (treat as exposed credential hash).
test("htpasswd_bcrypt: basic detection", async () => {
  const f = await findFor(`const h = "${BCRYPT}";`, "htpasswd_bcrypt");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: $2a$ variant.
test("htpasswd_bcrypt: 2a variant", async () => {
  const f = await findFor(`const h = "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX1.2";`, "htpasswd_bcrypt");
  assert.ok(f);
});

// WHY: $2y$ variant (PHP).
test("htpasswd_bcrypt: 2y variant", async () => {
  const f = await findFor(`const h = "$2y$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX1.2";`, "htpasswd_bcrypt");
  assert.ok(f);
});

// WHY: object property variant.
test("htpasswd_bcrypt: object property", async () => {
  const f = await findFor(`const u = { password: "${BCRYPT}" };`, "htpasswd_bcrypt");
  assert.ok(f);
});

// WHY: a string that's NOT a bcrypt hash (e.g. plain text) must not fire.
test("htpasswd_bcrypt: plain string NOT flagged", async () => {
  const f = await findFor(`const h = "this_is_not_a_bcrypt_hash_at_all_xyz";`, "htpasswd_bcrypt");
  assert.equal(f, undefined);
});

// ============================================================
// ipv4_with_creds (postgres://user:pass@1.2.3.4 etc)
// ============================================================

// WHY: scheme://user:password@ipv4 is a classic connection string leak.
test("ipv4_with_creds: postgres detection", async () => {
  const f = await findFor(`const url = "postgres://admin:Sup3rS3cret@10.0.1.5/db";`, "ipv4_with_creds");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: ftp connection string variant — credentials over an unsafe protocol.
test("ipv4_with_creds: ftp detection", async () => {
  const f = await findFor(`const url = "ftp://admin:Sup3rS3cret@10.0.1.5/files";`, "ipv4_with_creds");
  assert.ok(f);
});

// WHY: amqp (RabbitMQ) connection string with credentials.
test("ipv4_with_creds: amqp detection", async () => {
  const f = await findFor(`const url = "amqp://admin:RabbitPassword@10.0.0.5:5672/";`, "ipv4_with_creds");
  assert.ok(f);
});

// WHY: env reference is the safe pattern.
test("ipv4_with_creds: env reference NOT flagged", async () => {
  const f = await findFor(`const url = process.env.DATABASE_URL;`, "ipv4_with_creds");
  assert.equal(f, undefined);
});

// WHY: connection string without password (just user@host) must not fire.
test("ipv4_with_creds: no password NOT flagged", async () => {
  const f = await findFor(`const url = "postgres://admin@10.0.1.5/db";`, "ipv4_with_creds");
  assert.equal(f, undefined);
});
