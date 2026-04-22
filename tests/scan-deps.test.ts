import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parsePackageJson,
  parseRequirementsTxt,
  parsePipfileLock,
  parseManifest,
  runScanDeps,
} from "../src/tools/scan-deps.ts";
import { OsvClient, type Fetcher, type OsvVuln } from "../src/engines/osv-client.ts";
import { highestSeverity, fixedVersions } from "../src/engines/osv-client.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

test("package.json parser extracts deps, devDeps, optionalDeps with normalized versions", async () => {
  const content = await fixture("deps/package.json");
  const deps = parsePackageJson(content, "package.json");
  const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
  assert.equal(byName["lodash"].version, "4.17.15");
  assert.equal(byName["express"].version, "4.17.1"); // `^` stripped
  assert.equal(byName["minimist"].version, "1.2.0"); // `~` stripped
  assert.equal(byName["chai"].version, "4.3.4");
  assert.equal(byName["fsevents"].version, "2.1.0");
  assert.ok(deps.every((d) => d.ecosystem === "npm"));
});

test("requirements.txt parser skips comments, URLs, and editable installs", async () => {
  const content = await fixture("deps/requirements.txt");
  const deps = parseRequirementsTxt(content, "requirements.txt");
  const names = deps.map((d) => d.name).sort();
  assert.deepEqual(names, ["django", "flask", "pillow", "pyyaml", "requests", "urllib3"]);
  assert.equal(deps.find((d) => d.name === "django")?.version, "2.2.3");
  assert.equal(deps.find((d) => d.name === "pillow")?.version, "5.2.0");
  assert.ok(deps.every((d) => d.ecosystem === "PyPI"));
});

test("Pipfile.lock parser extracts default + develop sections", () => {
  const content = JSON.stringify({
    default: { requests: { version: "==2.19.0" } },
    develop: { pytest: { version: "==5.0.0" } },
  });
  const deps = parsePipfileLock(content, "Pipfile.lock");
  assert.equal(deps.length, 2);
  assert.ok(deps.some((d) => d.name === "requests" && d.version === "2.19.0"));
  assert.ok(deps.some((d) => d.name === "pytest" && d.version === "5.0.0"));
});

test("parseManifest dispatches by filename", async () => {
  const pkg = await fixture("deps/package.json");
  const req = await fixture("deps/requirements.txt");
  assert.ok(parseManifest("/a/b/package.json", pkg).length > 0);
  assert.ok(parseManifest("/a/b/requirements.txt", req).length > 0);
  assert.equal(parseManifest("/a/b/README.md", "").length, 0);
});

test("highestSeverity maps CVSS base scores to labels", () => {
  const v = (score: string): OsvVuln => ({ id: "X", severity: [{ type: "CVSS_V3", score }] });
  assert.equal(highestSeverity(v("CVSS:3.1/BASE:9.8")), "critical");
  assert.equal(highestSeverity(v("CVSS:3.1/BASE:7.2")), "high");
  assert.equal(highestSeverity(v("CVSS:3.1/BASE:5.3")), "medium");
  assert.equal(highestSeverity(v("CVSS:3.1/BASE:3.1")), "low");
  assert.equal(highestSeverity({ id: "X" }), "unknown");
});

test("fixedVersions extracts `fixed` events from the matching affected range", () => {
  const vuln: OsvVuln = {
    id: "GHSA-abcd",
    affected: [
      {
        package: { ecosystem: "npm", name: "lodash" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
  };
  assert.deepEqual(fixedVersions(vuln, "npm", "lodash"), ["4.17.21"]);
});

test("runScanDeps queries OSV for each unique dep and builds findings", async () => {
  const calls: string[] = [];
  const fetchImpl: Fetcher = async (_url, init) => {
    const body = JSON.parse(init.body);
    calls.push(`${body.package.ecosystem}:${body.package.name}@${body.version}`);
    if (body.package.name === "lodash") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          vulns: [
            {
              id: "GHSA-p6mc-m468-83gw",
              summary: "Prototype pollution in lodash",
              aliases: ["CVE-2019-10744"],
              severity: [{ type: "CVSS_V3", score: "CVSS:3.1/BASE:9.1" }],
              affected: [
                {
                  package: { ecosystem: "npm", name: "lodash" },
                  ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.12" }] }],
                },
              ],
              references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-p6mc-m468-83gw" }],
            },
          ],
        }),
      };
    }
    return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
  };
  const osv = new OsvClient(fetchImpl);

  const content = await fixture("deps/package.json");
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);

  assert.equal(out.dependenciesScanned, 5);
  assert.equal(calls.length, 5);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].package, "lodash");
  assert.equal(out.findings[0].severity, "critical");
  assert.ok(out.findings[0].aliases.includes("CVE-2019-10744"));
  assert.deepEqual(out.findings[0].fixedIn, ["4.17.12"]);
});

test("runScanDeps with zero vulns produces clean summary", async () => {
  const fetchImpl: Fetcher = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ vulns: [] }),
  });
  const osv = new OsvClient(fetchImpl);
  const content = await fixture("deps/package.json");
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  assert.equal(out.findings.length, 0);
  assert.match(out.summary, /No known vulnerabilities/);
});

test("runScanDeps swallows individual OSV errors and continues", async () => {
  let invocations = 0;
  const fetchImpl: Fetcher = async (_url, init) => {
    invocations++;
    const body = JSON.parse(init.body);
    if (body.package.name === "express") return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
  };
  const osv = new OsvClient(fetchImpl);
  const content = await fixture("deps/package.json");
  const out = await runScanDeps({ manifests: [{ path: "package.json", content }] }, osv);
  assert.equal(invocations, 5);
  assert.equal(out.findings.length, 0);
});
