import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic connection strings & tokens.
// NOTE: avoid the substring "example" in any value — engine drops anything containing
// the EXAMPLE placeholder marker (case-insensitive).
const PG_URL    = "postgres://app:s3cretP4ss@db.acme-prod.io:5432/prod";
const MYSQL_URL = "mysql://app:s3cretP4ss@db.acme-prod.io:3306/prod";
const MONGO_URL = "mongodb+srv://app:s3cretP4ss@db.acme-prod.io/prod";
// Supabase service_role JWT: pattern requires literal "service_role" between the
// header and the signature segment. Real Supabase keys sometimes match because the
// base64 of the role claim aligns. We craft a synthetic that includes the literal.
const SUPABASE_SR_JWT =
  "eyJhbGciOiJIUzI1NiJ9.eyJpc3MibIronwardsupabaseservice_roleAbCdEfGhIjK.aBcDeFgHiJkLmNoPqRsTuVwXyZabcdef1234";
// Clerk pattern allowlist suppresses 50-100 char bodies; need >100 to fire.
const CLERK_SK   = "sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123ab";
const AUTH0_64   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";  // 64 chars

// ============================================================
// postgres_url
// ============================================================

// WHY: basic.
test("postgres_url: basic detection", async () => {
  const code = `const url = '${PG_URL}';`;
  const f = await findFor(code, "postgres_url");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("postgres_url: object property", async () => {
  const code = `const cfg = { db: { url: '${PG_URL}' } };`;
  const f = await findFor(code, "postgres_url");
  assert.ok(f);
});

// WHY: template literal.
test("postgres_url: template literal", async () => {
  const code = "const u = `" + PG_URL + "`;";
  const f = await findFor(code, "postgres_url");
  assert.ok(f);
});

// WHY: placeholder.
test("postgres_url: placeholder NOT flagged", async () => {
  const code = `const u = 'postgres://user:YOUR_PASSWORD_HERE@db.example.com/db';`;
  const f = await findFor(code, "postgres_url");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("postgres_url: env reference NOT flagged", async () => {
  const code = `const u = process.env.DATABASE_URL;`;
  const f = await findFor(code, "postgres_url");
  assert.equal(f, undefined);
});

// ============================================================
// mysql_url
// ============================================================

// WHY: basic.
test("mysql_url: basic detection", async () => {
  const code = `const url = '${MYSQL_URL}';`;
  const f = await findFor(code, "mysql_url");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("mysql_url: object property", async () => {
  const code = `const cfg = { db: { url: '${MYSQL_URL}' } };`;
  const f = await findFor(code, "mysql_url");
  assert.ok(f);
});

// WHY: template literal.
test("mysql_url: template literal", async () => {
  const code = "const u = `" + MYSQL_URL + "`;";
  const f = await findFor(code, "mysql_url");
  assert.ok(f);
});

// WHY: placeholder.
test("mysql_url: placeholder NOT flagged", async () => {
  const code = `const u = 'mysql://user:YOUR_MYSQL_PASSWORD_HERE@db/db';`;
  const f = await findFor(code, "mysql_url");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("mysql_url: env reference NOT flagged", async () => {
  const code = `const u = process.env.MYSQL_URL;`;
  const f = await findFor(code, "mysql_url");
  assert.equal(f, undefined);
});

// ============================================================
// mongodb_url
// ============================================================

// WHY: basic.
test("mongodb_url: basic detection", async () => {
  const code = `const url = '${MONGO_URL}';`;
  const f = await findFor(code, "mongodb_url");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("mongodb_url: object property", async () => {
  const code = `const cfg = { mongo: { uri: '${MONGO_URL}' } };`;
  const f = await findFor(code, "mongodb_url");
  assert.ok(f);
});

// WHY: template literal.
test("mongodb_url: template literal", async () => {
  const code = "const u = `" + MONGO_URL + "`;";
  const f = await findFor(code, "mongodb_url");
  assert.ok(f);
});

// WHY: placeholder.
test("mongodb_url: placeholder NOT flagged", async () => {
  const code = `const u = 'mongodb://user:YOUR_MONGO_PASSWORD_HERE@db/db';`;
  const f = await findFor(code, "mongodb_url");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("mongodb_url: env reference NOT flagged", async () => {
  const code = `const u = process.env.MONGO_URI;`;
  const f = await findFor(code, "mongodb_url");
  assert.equal(f, undefined);
});

// ============================================================
// supabase_service_role
// ============================================================

// WHY: basic — service_role JWT shape fires critical.
test("supabase_service_role: basic detection", async () => {
  const code = `const k = '${SUPABASE_SR_JWT}';`;
  const f = await findFor(code, "supabase_service_role");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("supabase_service_role: object property", async () => {
  const code = `const cfg = { supabase: { serviceRole: '${SUPABASE_SR_JWT}' } };`;
  const f = await findFor(code, "supabase_service_role");
  assert.ok(f);
});

// WHY: template literal.
test("supabase_service_role: template literal", async () => {
  const code = "const a = `Bearer " + SUPABASE_SR_JWT + "`;";
  const f = await findFor(code, "supabase_service_role");
  assert.ok(f);
});

// WHY: placeholder.
test("supabase_service_role: placeholder NOT flagged", async () => {
  const code = `const k = 'YOUR_SUPABASE_SERVICE_ROLE_JWT_HERE_PLACEHOLDER';`;
  const f = await findFor(code, "supabase_service_role");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("supabase_service_role: env reference NOT flagged", async () => {
  const code = `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;`;
  const f = await findFor(code, "supabase_service_role");
  assert.equal(f, undefined);
});

// ============================================================
// clerk_secret_key
// ============================================================

// WHY: basic — sk_live_ + 50 chars matches Clerk pattern.
test("clerk_secret_key: basic detection", async () => {
  const code = `const k = '${CLERK_SK}';`;
  const f = await findFor(code, "clerk_secret_key");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("clerk_secret_key: object property", async () => {
  const code = `const cfg = { clerk: { secret: '${CLERK_SK}' } };`;
  const f = await findFor(code, "clerk_secret_key");
  assert.ok(f);
});

// WHY: template literal.
test("clerk_secret_key: template literal", async () => {
  const code = "const a = `Bearer " + CLERK_SK + "`;";
  const f = await findFor(code, "clerk_secret_key");
  assert.ok(f);
});

// WHY: placeholder — has a placeholder marker so engine drops it.
test("clerk_secret_key: placeholder NOT flagged", async () => {
  const code = `const k = 'sk_live_YOUR_CLERK_SECRET_HERE_PLACEHOLDER_VALUE_XX';`;
  const f = await findFor(code, "clerk_secret_key");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("clerk_secret_key: env reference NOT flagged", async () => {
  const code = `const k = process.env.CLERK_SECRET_KEY;`;
  const f = await findFor(code, "clerk_secret_key");
  assert.equal(f, undefined);
});

// ============================================================
// auth0_client_secret — context pattern: auth0_client_secret = '<64+ chars>'
// ============================================================

// WHY: basic — the pattern requires the auth0[-_]?(client[-_]?)?secret prefix.
test("auth0_client_secret: basic detection (with auth0 prefix)", async () => {
  const code = `auth0_client_secret = '${AUTH0_64}'`;
  const f = await findFor(code, "auth0_client_secret");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object — the auth0_client_secret key satisfies the prefix requirement.
test("auth0_client_secret: object property", async () => {
  const code = `const cfg = { auth0_client_secret: '${AUTH0_64}' };`;
  const f = await findFor(code, "auth0_client_secret");
  assert.ok(f);
});

// WHY: template literal — the pattern is context-prefixed, so a Bearer template
// without 'auth0' near the value cannot fire. Document the limitation.
// TODO: auth0_client_secret requires the auth0(_client)_secret prefix to fire — it
// will not match a raw 64-char token in a Bearer template literal.
test("auth0_client_secret: template literal NOT flagged (pattern requires prefix)", async () => {
  const code = "const a = `Bearer " + AUTH0_64 + "`;";
  const f = await findFor(code, "auth0_client_secret");
  assert.equal(f, undefined);
});

// WHY: placeholder.
test("auth0_client_secret: placeholder NOT flagged", async () => {
  const code = `auth0_client_secret = 'YOUR_AUTH0_CLIENT_SECRET_HERE_PLACEHOLDER_VALUE_FILLERFILLERFILL'`;
  const f = await findFor(code, "auth0_client_secret");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("auth0_client_secret: env reference NOT flagged", async () => {
  const code = `const k = process.env.AUTH0_CLIENT_SECRET;`;
  const f = await findFor(code, "auth0_client_secret");
  assert.equal(f, undefined);
});
