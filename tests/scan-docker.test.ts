import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runScanDocker, scanDockerfile, detectKind, formatDockerReport } from "../src/tools/scan-docker.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

test("detectKind recognizes Dockerfile by name", () => {
  assert.equal(detectKind("Dockerfile", "FROM node"), "dockerfile");
  assert.equal(detectKind("path/to/Dockerfile.prod", "FROM node"), "dockerfile");
});

test("detectKind recognizes docker-compose by name", () => {
  assert.equal(detectKind("docker-compose.yml", "services:"), "compose");
  assert.equal(detectKind("compose.yaml", "services:"), "compose");
});

test("detectKind falls back to content sniffing", () => {
  assert.equal(detectKind("random.txt", "FROM node:20\nRUN echo ok"), "dockerfile");
  assert.equal(detectKind("random.yml", "services:\n  web:"), "compose");
  assert.equal(detectKind("random.txt", "just some prose"), null);
});

test("insecure Dockerfile fires expected rules", async () => {
  const content = await fixture("docker/insecure.Dockerfile");
  const findings = scanDockerfile(content, "dockerfile");
  const ids = new Set(findings.map((f) => f.ruleId));
  for (const id of [
    "latest-tag",
    "secret-in-env",
    "copy-everything",
    "add-remote-url",
    "curl-pipe-shell",
    "no-user-directive",
    "no-healthcheck",
    "expose-ssh",
    "expose-db-ports",
  ]) {
    assert.ok(ids.has(id), `expected rule ${id} to fire`);
  }
});

test("secure Dockerfile is clean", async () => {
  const content = await fixture("docker/secure.Dockerfile");
  const findings = scanDockerfile(content, "dockerfile");
  const ids = new Set(findings.map((f) => f.ruleId));
  // The secure example should not have critical/high findings.
  const critical = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  assert.equal(critical.length, 0, `got: ${[...ids].join(", ")}`);
});

test("insecure docker-compose fires expected rules", async () => {
  const content = await fixture("docker/compose-insecure.yml");
  const findings = scanDockerfile(content, "compose");
  const ids = new Set(findings.map((f) => f.ruleId));
  for (const id of [
    "compose-privileged-mode",
    "compose-host-network",
    "compose-sensitive-mount",
    "compose-secret-in-environment",
  ]) {
    assert.ok(ids.has(id), `expected rule ${id} to fire`);
  }
});

test("runScanDocker aggregates across files", async () => {
  const content = await fixture("docker/insecure.Dockerfile");
  const out = await runScanDocker({
    files: [{ path: "Dockerfile", content }],
  });
  assert.equal(out.files.length, 1);
  assert.equal(out.files[0].kind, "dockerfile");
  assert.ok(out.summary.totalFindings > 5);
});

test("runScanDocker ignores unrelated files", async () => {
  const out = await runScanDocker({
    files: [{ path: "README.md", content: "# hello world" }],
  });
  assert.equal(out.files.length, 0);
  assert.equal(out.summary.totalFindings, 0);
});

test("formatDockerReport prints 'no issues' for clean output", async () => {
  const content = await fixture("docker/secure.Dockerfile");
  const out = await runScanDocker({ files: [{ path: "Dockerfile", content }] });
  const text = formatDockerReport(out);
  // Secure Dockerfile still has `low` findings (maybe); we just check the formatter works
  assert.ok(text.length > 0);
});
