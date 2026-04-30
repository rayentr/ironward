import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectTyposquat,
  detectKnownMalware,
  classifyAbandonment,
  classifyLicense,
  parsePackageLock,
  POPULAR_NPM_PACKAGES,
  KNOWN_MALWARE_NPM,
  type RegistryFetcher,
} from "../src/engines/dep-intel.ts";
import { runScanDeps } from "../src/tools/scan-deps.ts";
import { OsvClient, type Fetcher } from "../src/engines/osv-client.ts";

test("detectTyposquat flags 'lodahs' as typo of 'lodash'", () => {
  assert.equal(detectTyposquat("lodahs"), "lodash");
});

test("detectTyposquat flags 'expres' as typo of 'express'", () => {
  assert.equal(detectTyposquat("expres"), "express");
});

test("detectTyposquat does NOT flag legitimate 'lodash'", () => {
  assert.equal(detectTyposquat("lodash"), null);
});

test("detectTyposquat does NOT flag scoped packages", () => {
  assert.equal(detectTyposquat("@types/lodash"), null);
});

test("detectTyposquat does NOT flag very short names", () => {
  assert.equal(detectTyposquat("fs"), null);
});

test("detectTyposquat does NOT flag unrelated names", () => {
  assert.equal(detectTyposquat("my-custom-thing-xyz"), null);
});

test("detectKnownMalware flags 'event-stream' in npm", () => {
  assert.equal(detectKnownMalware("event-stream", "npm"), true);
});

test("detectKnownMalware does NOT flag 'event-stream' in PyPI", () => {
  assert.equal(detectKnownMalware("event-stream", "PyPI"), false);
});

test("detectKnownMalware does NOT flag safe packages", () => {
  assert.equal(detectKnownMalware("lodash", "npm"), false);
});

test("classifyAbandonment: active within 2 years", () => {
  const recent = new Date();
  recent.setDate(recent.getDate() - 100);
  assert.equal(classifyAbandonment(recent), "active");
});

test("classifyAbandonment: stale between 2-4 years", () => {
  const now = new Date("2026-04-22");
  const stale = new Date("2023-06-01");
  assert.equal(classifyAbandonment(stale, now), "stale");
});

test("classifyAbandonment: abandoned over 4 years", () => {
  const now = new Date("2026-04-22");
  const old = new Date("2020-01-01");
  assert.equal(classifyAbandonment(old, now), "abandoned");
});

test("classifyAbandonment: null when no date", () => {
  assert.equal(classifyAbandonment(null), null);
});

test("classifyLicense: MIT is permissive", () => {
  assert.equal(classifyLicense("MIT"), "permissive");
});

test("classifyLicense: Apache-2.0 is permissive", () => {
  assert.equal(classifyLicense("Apache-2.0"), "permissive");
});

test("classifyLicense: GPL-3.0 is copyleft", () => {
  assert.equal(classifyLicense("GPL-3.0"), "copyleft");
});

test("classifyLicense: AGPL-3.0-only is copyleft", () => {
  assert.equal(classifyLicense("AGPL-3.0-only"), "copyleft");
});

test("classifyLicense: UNLICENSED flagged", () => {
  assert.equal(classifyLicense("UNLICENSED"), "unlicensed");
});

test("classifyLicense: missing flagged as unlicensed", () => {
  assert.equal(classifyLicense(null), "unlicensed");
});

test("classifyLicense: SPDX composite '(MIT OR Apache-2.0)' is permissive", () => {
  assert.equal(classifyLicense("(MIT OR Apache-2.0)"), "permissive");
});

test("parsePackageLock reads npm v7+ lockfile packages", () => {
  const content = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { foo: "^1.0.0" } },
      "node_modules/foo": { version: "1.2.3" },
      "node_modules/foo/node_modules/bar": { version: "2.0.0" },
    },
  });
  const lock = parsePackageLock(content);
  assert.ok(lock.has("foo@1.2.3"));
  assert.ok(lock.has("bar@2.0.0"));
  assert.equal(lock.get("foo@1.2.3")!.direct, true);
  assert.equal(lock.get("bar@2.0.0")!.direct, false);
});

test("runScanDeps includes typosquat intel findings", async () => {
  const noVulns: Fetcher = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const osv = new OsvClient(noVulns);
  const content = JSON.stringify({
    name: "test",
    license: "MIT",
    dependencies: { lodahs: "1.0.0", expres: "1.0.0" },
  });
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  assert.equal(out.findings.length, 0);
  const kinds = out.intel.map((i) => i.kind).sort();
  assert.deepEqual(kinds, ["typosquat", "typosquat"]);
});

test("runScanDeps includes malware intel findings (exact tainted version → critical)", async () => {
  const noVulns: Fetcher = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const osv = new OsvClient(noVulns);
  const content = JSON.stringify({
    name: "test",
    license: "MIT",
    dependencies: { "event-stream": "3.3.6" },
  });
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  const malware = out.intel.find((i) => i.kind === "malware");
  assert.ok(malware);
  assert.equal(malware!.severity, "critical");
});

test("runScanDeps name-only malware match is HIGH (clean version of tainted name)", async () => {
  const noVulns: Fetcher = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const osv = new OsvClient(noVulns);
  const content = JSON.stringify({
    name: "test",
    license: "MIT",
    dependencies: { "event-stream": "4.0.1" },
  });
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  const malware = out.intel.find((i) => i.kind === "malware");
  assert.ok(malware, "expected a malware finding for name match");
  assert.equal(malware!.severity, "high");
});

test("runScanDeps flags UNLICENSED packages", async () => {
  const noVulns: Fetcher = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const osv = new OsvClient(noVulns);
  const content = JSON.stringify({
    name: "proprietary-app",
    license: "UNLICENSED",
    dependencies: {},
  });
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  const unlicensed = out.intel.find((i) => i.kind === "unlicensed");
  assert.ok(unlicensed);
});

test("runScanDeps uses injected registry fetcher for abandoned check", async () => {
  const noVulns: Fetcher = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const osv = new OsvClient(noVulns);
  const fakeRegistry: RegistryFetcher = {
    async lastPublished(_name) {
      return new Date("2019-01-01");
    },
  };
  const content = JSON.stringify({
    name: "test",
    license: "MIT",
    dependencies: { "some-old-pkg": "1.0.0" },
  });
  const out = await runScanDeps(
    { manifests: [{ path: "package.json", content }], checkAbandoned: true },
    osv,
    fakeRegistry,
  );
  const abandoned = out.intel.find((i) => i.kind === "abandoned");
  assert.ok(abandoned);
  assert.equal(abandoned!.severity, "high");
});

test("POPULAR_NPM_PACKAGES contains at least 100 names", () => {
  assert.ok(POPULAR_NPM_PACKAGES.length >= 100);
});

test("KNOWN_MALWARE_NPM contains at least 50 names", () => {
  assert.ok(KNOWN_MALWARE_NPM.size >= 50);
});
