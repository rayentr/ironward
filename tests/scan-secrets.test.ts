import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

test("detects AWS key, Stripe live key, GitHub PAT, and Postgres URL in leaky fixture", async () => {
  const content = await fixture("leaky.js");
  const out = await runScanSecrets({ files: [{ path: "leaky.js", content }] });
  const types = new Set(out.files[0].findings.map((f) => f.type));
  assert.ok(types.has("aws_access_key"), "should detect AWS access key");
  assert.ok(types.has("stripe_live_secret"), "should detect Stripe live key");
  assert.ok(types.has("github_pat_classic"), "should detect GitHub PAT");
  assert.ok(types.has("postgres_url"), "should detect Postgres URL with creds");
  assert.ok(out.summary.bySeverity.critical >= 3, "expected >=3 critical findings");
});

test("entropy scanner flags a high-entropy literal with no prefix and no keyword trigger", async () => {
  const snippet = `const blob = "Zx9pQ7Rv2LmK4Nt8Wj3Hb6Fy1Cd5Ae0G";`;
  const out = await runScanSecrets({ content: snippet });
  const hasEntropy = out.files[0].findings.some(
    (f) => f.source === "entropy" || f.type === "high_entropy_string",
  );
  assert.ok(hasEntropy, "entropy scanner should flag high-H literal");
});

test("clean fixture produces zero findings", async () => {
  const content = await fixture("clean.js");
  const out = await runScanSecrets({ files: [{ path: "clean.js", content }] });
  assert.equal(out.summary.totalFindings, 0);
});

test("pre-commit context blocks when critical findings are present", async () => {
  const content = await fixture("leaky.js");
  const out = await runScanSecrets({
    files: [{ path: "leaky.js", content }],
    context: "pre-commit",
  });
  assert.equal(out.summary.blocked, true);
});

test("on-demand context does not block even with critical findings", async () => {
  const content = await fixture("leaky.js");
  const out = await runScanSecrets({
    files: [{ path: "leaky.js", content }],
    context: "on-demand",
  });
  assert.equal(out.summary.blocked, false);
});

test("redacts matches (never returns full secret in redacted field)", async () => {
  const content = await fixture("leaky.js");
  const out = await runScanSecrets({ files: [{ path: "leaky.js", content }] });
  for (const f of out.files[0].findings) {
    assert.ok(f.redacted.includes("***"), `redacted should be masked: got ${f.redacted}`);
  }
});
