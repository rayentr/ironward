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

test("UUIDs and git SHAs do not trigger pattern or entropy findings", async () => {
  const findings = await scanOne("clean/uuids_shas.txt");
  assert.equal(findings.length, 0, `expected 0, got ${findings.length}: ${findings.map((f) => `${f.type}@L${f.line}`).join(", ")}`);
});

test("Placeholder values (EXAMPLE, XXXX, PLACEHOLDER, CHANGEME) are all suppressed", async () => {
  const findings = await scanOne("clean/placeholders.txt");
  assert.equal(findings.length, 0, `expected 0, got ${findings.length}: ${findings.map((f) => `${f.type}@L${f.line} (${f.redacted})`).join(", ")}`);
});

test("Env-var usage patterns (process.env.X, os.environ) yield zero findings", async () => {
  const findings = await scanOne("clean/env_usage.txt");
  assert.equal(findings.length, 0, `expected 0, got ${findings.length}: ${findings.map((f) => `${f.type}@L${f.line}`).join(", ")}`);
});

test("`securemcp-ignore` and `nosecrets` directives suppress findings", async () => {
  const findings = await scanOne("clean/suppressed.txt");
  assert.equal(findings.length, 0, `expected 0, got ${findings.length}: ${findings.map((f) => `${f.type}@L${f.line}`).join(", ")}`);
});

test("Short common-format strings (hex colors, kebab paths) do not trigger entropy", async () => {
  const snippet = `
const red = "#ff0000";
const teal = "#00c2b8";
const pkg = "lodash/fp/getOr";
const tz = "America/Los_Angeles";
const sha = "6b3c7a02e9d4f5a1c2b3d4e5f6a7b8c9d0e1f2a3";
`;
  const out = await runScanSecrets({ content: snippet });
  assert.equal(out.files[0].findings.length, 0);
});
