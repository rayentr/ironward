import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadProjectConfig,
  saveProjectConfig,
  detectStack,
  buildInitialConfig,
  scannerEnabled,
  ruleDisabled,
  downgradeFor,
  PROJECT_CONFIG_FILENAME,
} from "../src/integrations/project-config.ts";

async function tmpDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "iw-project-cfg-"));
}

test("project-config: loadProjectConfig returns null when missing", async () => {
  const d = await tmpDir();
  try {
    const cfg = await loadProjectConfig(d);
    assert.equal(cfg, null);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

test("project-config: save and load round-trip", async () => {
  const d = await tmpDir();
  try {
    const cfg = { version: "1" as const, threshold: "high" as const, offline: true };
    await saveProjectConfig(cfg, d);
    const loaded = await loadProjectConfig(d);
    assert.equal(loaded?.threshold, "high");
    assert.equal(loaded?.offline, true);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

test("project-config: detectStack picks up package.json + Dockerfile", async () => {
  const d = await tmpDir();
  try {
    await writeFile(join(d, "package.json"), "{}");
    await writeFile(join(d, "Dockerfile"), "FROM node:20\n");
    const detected = await detectStack(d);
    assert.equal(detected.hasPackageJson, true);
    assert.equal(detected.hasDockerfile, true);
    assert.equal(detected.hasNextJs, false);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

test("project-config: buildInitialConfig enables scanners for detected stack", async () => {
  const cfg = buildInitialConfig({
    hasNextJs: false,
    hasDockerfile: true,
    hasTerraform: false,
    hasGithubActions: true,
    hasPackageJson: true,
    hasPipfile: false,
    hasRequirementsTxt: false,
  });
  assert.ok(cfg.enabledScanners?.includes("secrets"));
  assert.ok(cfg.enabledScanners?.includes("code"));
  assert.ok(cfg.enabledScanners?.includes("deps"));
  assert.ok(cfg.enabledScanners?.includes("docker"));
  assert.ok(cfg.enabledScanners?.includes("github"));
  assert.ok(!cfg.enabledScanners?.includes("infra"));
});

test("project-config: buildInitialConfig minimal stack disables deps", async () => {
  const cfg = buildInitialConfig({
    hasNextJs: false, hasDockerfile: false, hasTerraform: false, hasGithubActions: false,
    hasPackageJson: false, hasPipfile: false, hasRequirementsTxt: false,
  });
  assert.ok(!cfg.enabledScanners?.includes("deps"));
});

test("project-config: scannerEnabled honours enabledScanners list", () => {
  const cfg = { enabledScanners: ["secrets", "code"] as const };
  assert.equal(scannerEnabled(cfg as any, "secrets"), true);
  assert.equal(scannerEnabled(cfg as any, "deps"), false);
  // No config → all enabled
  assert.equal(scannerEnabled(null, "anything"), true);
});

test("project-config: ruleDisabled + downgradeFor", () => {
  const cfg = {
    rules: {
      disable: ["react-localstorage-token"],
      downgrade: { "bcrypt-low-rounds": "low" as const },
    },
  };
  assert.equal(ruleDisabled(cfg as any, "react-localstorage-token"), true);
  assert.equal(ruleDisabled(cfg as any, "other"), false);
  assert.equal(downgradeFor(cfg as any, "bcrypt-low-rounds"), "low");
  assert.equal(downgradeFor(cfg as any, "other"), null);
});

test("project-config: filename constant is .ironward.json", () => {
  assert.equal(PROJECT_CONFIG_FILENAME, ".ironward.json");
});
