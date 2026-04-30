import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

// This file adds 3 additional context-shape tests per pattern across the
// 5 depth categories that were already at 5 tests each (aws, payment, ai-ml,
// scm, db-auth). The shapes covered are:
//
//   T6 — multi-line / YAML  (split assignment, indented YAML key)
//   T7 — module.exports / export default  (config-module shape)
//   T8 — .env-file format  (KEY=value with no quotes)
//
// WHY: each shape is a real-world surface area that a flat literal test misses.
// All three appear daily in production repos.

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Shared synthetic fixtures. Different from the originals to prove the rule
// matches across distinct values.
const AWS_AKID_2 = "AKIAJ7K8L9M0N1P2Q3R4";
const AWS_SECRET_2 = "AbCdEf1234567890aBcDeFgHiJkLmNoPqRsTuVwX"; // 40 chars
const STRIPE_LIVE = "sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl"; // sk_live_ + 48
const OPENAI_KEY = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"; // sk- + 48
const ANTHROPIC_KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZAbCdEfGhIjKlMnOpQrStUvWxYz0123456789-12345AAAA";
const GH_PAT = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";  // ghp_ + 36
const GL_PAT = "glpat-AbCdEfGh1J2K3L4M5N6O";  // glpat- + 20
const POSTGRES_URL = "postgres://admin:Sup3rS3cret@db.host.com:5432/proddb";

// =====================================================================
// AWS — additional shape variants
// =====================================================================

// WHY (T6): multi-line YAML assignment shape — IaC repos use it heavily.
test("aws_access_key: T6 yaml multiline", async () => {
  const yaml = `aws:\n  access_key_id: ${AWS_AKID_2}\n  region: us-east-1`;
  const f = await findFor(yaml, "aws_access_key");
  assert.ok(f);
});

// WHY (T7): config module export — bundlers happily ship these to client.
test("aws_access_key: T7 module.exports", async () => {
  const code = `module.exports = { aws: { accessKeyId: '${AWS_AKID_2}' } };`;
  const f = await findFor(code, "aws_access_key");
  assert.ok(f);
});

// WHY (T8): .env file format — direct grep-able leak.
test("aws_access_key: T8 dotenv", async () => {
  const f = await findFor(`AWS_ACCESS_KEY_ID=${AWS_AKID_2}`, "aws_access_key");
  assert.ok(f);
});

// WHY (T6): contextual secret in YAML assignment.
test("aws_secret_key_contextual: T6 yaml", async () => {
  const yaml = `aws_secret_access_key: ${AWS_SECRET_2}\nregion: us-east-1`;
  const f = await findFor(yaml, "aws_secret_key_contextual");
  assert.ok(f);
});

// WHY (T7): export default config carrying secret.
test("aws_secret_key_contextual: T7 export default", async () => {
  const code = `export default { aws_secret_access_key: '${AWS_SECRET_2}' };`;
  const f = await findFor(code, "aws_secret_key_contextual");
  assert.ok(f);
});

// WHY (T8): canonical .env line — the AWS CLI looks for exactly this.
test("aws_secret_key_contextual: T8 dotenv", async () => {
  const f = await findFor(`AWS_SECRET_ACCESS_KEY=${AWS_SECRET_2}`, "aws_secret_key_contextual");
  assert.ok(f);
});

// =====================================================================
// PAYMENT — additional shape variants
// =====================================================================

// WHY (T6): YAML config (used by Helm/Kustomize secret manifests).
test("stripe_live_secret: T6 yaml", async () => {
  const yaml = `stripe:\n  secretKey: '${STRIPE_LIVE}'`;
  const f = await findFor(yaml, "stripe_live_secret");
  assert.ok(f);
});

// WHY (T7): module.exports config form.
test("stripe_live_secret: T7 module.exports", async () => {
  const code = `module.exports = { stripeSecret: '${STRIPE_LIVE}' };`;
  const f = await findFor(code, "stripe_live_secret");
  assert.ok(f);
});

// WHY (T8): .env file shape.
test("stripe_live_secret: T8 dotenv", async () => {
  const f = await findFor(`STRIPE_SECRET_KEY=${STRIPE_LIVE}`, "stripe_live_secret");
  assert.ok(f);
});

// =====================================================================
// AI/ML — additional shape variants
// =====================================================================

// WHY (T6): YAML config common in LLM-routing services.
test("openai_api_key: T6 yaml", async () => {
  const yaml = `openai:\n  apiKey: '${OPENAI_KEY}'`;
  const f = await findFor(yaml, "openai_project_key_legacy");
  assert.ok(f);
});

// WHY (T7): export default for SDK config module.
test("openai_api_key: T7 export default", async () => {
  const code = `export default { openai: { apiKey: '${OPENAI_KEY}' } };`;
  const f = await findFor(code, "openai_project_key_legacy");
  assert.ok(f);
});

// WHY (T8): .env shape — Next.js/Vercel projects load this directly.
test("openai_api_key: T8 dotenv", async () => {
  const f = await findFor(`OPENAI_API_KEY=${OPENAI_KEY}`, "openai_project_key_legacy");
  assert.ok(f);
});

// WHY (T6): YAML config for Anthropic key.
test("anthropic_api_key: T6 yaml", async () => {
  const yaml = `anthropic:\n  apiKey: '${ANTHROPIC_KEY}'`;
  const f = await findFor(yaml, "anthropic_api_key");
  assert.ok(f);
});

// WHY (T7): module.exports config.
test("anthropic_api_key: T7 module.exports", async () => {
  const code = `module.exports = { anthropic: { apiKey: '${ANTHROPIC_KEY}' } };`;
  const f = await findFor(code, "anthropic_api_key");
  assert.ok(f);
});

// WHY (T8): .env shape.
test("anthropic_api_key: T8 dotenv", async () => {
  const f = await findFor(`ANTHROPIC_API_KEY=${ANTHROPIC_KEY}`, "anthropic_api_key");
  assert.ok(f);
});

// =====================================================================
// SCM — additional shape variants
// =====================================================================

// WHY (T6): YAML config used by deploy scripts.
test("github_pat_classic: T6 yaml", async () => {
  const yaml = `github:\n  token: '${GH_PAT}'`;
  const f = await findFor(yaml, "github_pat_classic");
  assert.ok(f);
});

// WHY (T7): export default for SDK config module.
test("github_pat_classic: T7 export default", async () => {
  const code = `export default { github: { token: '${GH_PAT}' } };`;
  const f = await findFor(code, "github_pat_classic");
  assert.ok(f);
});

// WHY (T8): .env file shape — most CI loaders read this directly.
test("github_pat_classic: T8 dotenv", async () => {
  const f = await findFor(`GITHUB_TOKEN=${GH_PAT}`, "github_pat_classic");
  assert.ok(f);
});

// WHY (T6): YAML for GitLab token.
test("gitlab_pat: T6 yaml", async () => {
  const yaml = `gitlab:\n  token: '${GL_PAT}'`;
  const f = await findFor(yaml, "gitlab_pat");
  assert.ok(f);
});

// WHY (T7): module.exports for GitLab config.
test("gitlab_pat: T7 module.exports", async () => {
  const code = `module.exports = { gitlab: { token: '${GL_PAT}' } };`;
  const f = await findFor(code, "gitlab_pat");
  assert.ok(f);
});

// WHY (T8): .env shape.
test("gitlab_pat: T8 dotenv", async () => {
  const f = await findFor(`GITLAB_TOKEN=${GL_PAT}`, "gitlab_pat");
  assert.ok(f);
});

// =====================================================================
// DB-AUTH — additional shape variants
// =====================================================================

// WHY (T6): YAML for connection string.
test("postgres_url: T6 yaml", async () => {
  const yaml = `database:\n  url: '${POSTGRES_URL}'`;
  const f = await findFor(yaml, "postgres_url");
  assert.ok(f);
});

// WHY (T7): module.exports config.
test("postgres_url: T7 module.exports", async () => {
  const code = `module.exports = { db: { url: '${POSTGRES_URL}' } };`;
  const f = await findFor(code, "postgres_url");
  assert.ok(f);
});

// WHY (T8): .env shape.
test("postgres_url: T8 dotenv", async () => {
  const f = await findFor(`DATABASE_URL=${POSTGRES_URL}`, "postgres_url");
  assert.ok(f);
});

const MONGO_URL = "mongodb+srv://admin:Sup3rSecret@cluster0.demo.mongodb.net/proddb";

// WHY (T6): YAML for mongo connection string.
test("mongodb_url: T6 yaml", async () => {
  const yaml = `mongo:\n  url: '${MONGO_URL}'`;
  const f = await findFor(yaml, "mongodb_url");
  assert.ok(f);
});

// WHY (T7): module.exports config.
test("mongodb_url: T7 module.exports", async () => {
  const code = `module.exports = { mongo: { url: '${MONGO_URL}' } };`;
  const f = await findFor(code, "mongodb_url");
  assert.ok(f);
});

// WHY (T8): .env shape.
test("mongodb_url: T8 dotenv", async () => {
  const f = await findFor(`MONGODB_URL=${MONGO_URL}`, "mongodb_url");
  assert.ok(f);
});
