import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

async function scanOne(path: string) {
  const content = await fixture(path);
  const out = await runScanSecrets({ files: [{ path, content }] });
  return out.files[0].findings;
}

test("cloud fixture: AWS, GCP, Azure, DO, Alibaba all detected", async () => {
  const findings = await scanOne("categories/cloud.txt");
  const types = new Set(findings.map((f) => f.type));
  for (const t of [
    "aws_access_key",
    "gcp_api_key",
    "gcp_oauth_client_secret",
    "azure_storage_connection_string",
    "digitalocean_pat",
    "alibaba_access_key",
  ]) {
    assert.ok(types.has(t), `missing ${t}`);
  }
});

test("SCM + AI fixture: GitHub, GitLab, OpenAI, Anthropic, HF, Replicate, Groq, Perplexity all detected", async () => {
  const findings = await scanOne("categories/scm_ai.txt");
  const types = new Set(findings.map((f) => f.type));
  for (const t of [
    "github_pat_classic",
    "github_oauth",
    "github_fine_grained_pat",
    "gitlab_pat",
    "openai_key",
    "anthropic_api_key",
    "huggingface_token",
    "replicate_token",
    "groq_key",
    "perplexity_key",
  ]) {
    assert.ok(types.has(t), `missing ${t}`);
  }
});

test("comms + db fixture: Slack bot + webhook, Discord webhook, SendGrid, Postgres, Mongo, Redis, Sentry all detected", async () => {
  const findings = await scanOne("categories/comms_db.txt");
  const types = new Set(findings.map((f) => f.type));
  for (const t of [
    "slack_bot_token",
    "slack_webhook",
    "discord_webhook",
    "sendgrid_key",
    "postgres_url",
    "mongodb_url",
    "redis_url_with_creds",
    "sentry_dsn",
  ]) {
    assert.ok(types.has(t), `missing ${t}`);
  }
});

test("crypto + SaaS fixture: PEM, OpenSSH, npm, DockerHub, Notion, Linear, Figma, Tailscale all detected", async () => {
  const findings = await scanOne("categories/crypto_saas.txt");
  const types = new Set(findings.map((f) => f.type));
  for (const t of [
    "private_key_pem",
    "ssh_openssh_private",
    "npm_token",
    "dockerhub_pat",
    "notion_integration_token",
    "linear_api_key",
    "figma_pat",
    "tailscale_key",
  ]) {
    assert.ok(types.has(t), `missing ${t}`);
  }
});

test("v1.0 expansion fixture: payment, comms, infra, monitoring, web3, db, saas, scm patterns detected", async () => {
  const findings = await scanOne("categories/v1_expansion.txt");
  const types = new Set(findings.map((f) => f.type));
  for (const t of [
    "paypal_client_secret",
    "square_access_token",
    "razorpay_key_secret",
    "stripe_restricted_live",
    "resend_api_key",
    "mailgun_key",
    "shopify_access_token",
    "pagerduty_routing_key",
    "infura_project_id",
    "planetscale_token",
    "notion_integration_token",
    "linear_api_key",
    "discord_bot_token",
    "posthog_personal_api_key",
  ]) {
    assert.ok(types.has(t), `missing ${t}`);
  }
});

test("total pattern families is >= 600 for v1.0", async () => {
  const { default: patterns } = await import("../patterns/secrets.json", { with: { type: "json" } });
  const count = Object.keys(patterns as Record<string, unknown>).length;
  assert.ok(count >= 600, `expected >= 600 pattern families, got ${count}`);
});

test("all matched secrets are redacted (never contain full match in redacted field)", async () => {
  for (const path of [
    "categories/cloud.txt",
    "categories/scm_ai.txt",
    "categories/comms_db.txt",
    "categories/crypto_saas.txt",
    "categories/v1_expansion.txt",
  ]) {
    const findings = await scanOne(path);
    for (const f of findings) {
      assert.ok(f.redacted.includes("***"), `${path}: ${f.type} not redacted: ${f.redacted}`);
      assert.notEqual(f.redacted, f.match, `${path}: ${f.type} redacted == match`);
    }
  }
});
