import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  detectGithubWorkflow,
  runScanGithub,
  scanGithubWorkflow,
} from "../src/tools/scan-github.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

function ids(findings: { ruleId: string }[]): Set<string> {
  return new Set(findings.map((f) => f.ruleId));
}

// ──────────────────────────────────────────────────────────────
// detectGithubWorkflow
// ──────────────────────────────────────────────────────────────
test("detectGithubWorkflow: matches path under .github/workflows/", () => {
  assert.equal(detectGithubWorkflow(".github/workflows/ci.yml"), true);
  assert.equal(detectGithubWorkflow("repo/.github/workflows/deploy.yaml"), true);
  assert.equal(detectGithubWorkflow(".GITHUB/Workflows/CI.YML"), true);
});

test("detectGithubWorkflow: rejects unrelated paths without content", () => {
  assert.equal(detectGithubWorkflow("src/server.ts"), false);
  assert.equal(detectGithubWorkflow("some.yml"), false);
});

test("detectGithubWorkflow: content heuristic catches workflow-shaped YAML at other paths", () => {
  const yml = `on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n`;
  assert.equal(detectGithubWorkflow("workflow-copy.yml", yml), true);
  assert.equal(detectGithubWorkflow("random.yml", "name: just yaml\nversion: 1\n"), false);
});

// ──────────────────────────────────────────────────────────────
// gh-pull-request-target-with-checkout
// ──────────────────────────────────────────────────────────────
test("gh-pull-request-target-with-checkout fires on the pwn-request fixture", async () => {
  const content = await fixture("github/pwn-request.yml");
  const f = scanGithubWorkflow(content);
  assert.ok(ids(f).has("gh-pull-request-target-with-checkout"));
});

test("gh-pull-request-target-with-checkout does not fire on safe pull_request_target workflow", async () => {
  const content = await fixture("github/safe-pr-target.yml");
  const f = scanGithubWorkflow(content);
  assert.ok(!ids(f).has("gh-pull-request-target-with-checkout"));
});

// ──────────────────────────────────────────────────────────────
// gh-secrets-in-if-condition
// ──────────────────────────────────────────────────────────────
test("gh-secrets-in-if-condition fires on secrets.X gate", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  deploy:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Deploy",
    "        if: ${{ secrets.DEPLOY_TOKEN }}",
    "        run: ./deploy.sh",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-secrets-in-if-condition"));
});

test("gh-secrets-in-if-condition does not fire when using vars.* or event_name", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  deploy:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Deploy",
    "        if: ${{ vars.ENABLE_DEPLOY == 'true' && github.event_name == 'push' }}",
    "        run: ./deploy.sh",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-secrets-in-if-condition"));
});

// ──────────────────────────────────────────────────────────────
// gh-token-write-all
// ──────────────────────────────────────────────────────────────
test("gh-token-write-all fires on permissions: write-all", () => {
  const yml = "on: [push]\npermissions: write-all\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-token-write-all"));
});

test("gh-token-write-all fires on top-level contents: write", () => {
  const yml = [
    "on: [push]",
    "permissions:",
    "  contents: write",
    "  issues: read",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-token-write-all"));
});

test("gh-token-write-all does not fire on least-privilege permissions", () => {
  const yml = [
    "on: [push]",
    "permissions:",
    "  contents: read",
    "  issues: read",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-token-write-all"));
});

// ──────────────────────────────────────────────────────────────
// gh-expression-injection-run
// ──────────────────────────────────────────────────────────────
test("gh-expression-injection-run fires on PR title interpolation into run", () => {
  const yml = [
    "on: [pull_request]",
    "jobs:",
    "  comment:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Echo title",
    "        run: |",
    "          echo \"PR: ${{ github.event.pull_request.title }}\"",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-expression-injection-run"));
});

test("gh-expression-injection-run does NOT fire when title is passed via env", () => {
  const yml = [
    "on: [pull_request]",
    "jobs:",
    "  comment:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Echo title",
    "        env:",
    "          TITLE: ${{ github.event.pull_request.title }}",
    "        run: echo \"PR: $TITLE\"",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-expression-injection-run"));
});

// ──────────────────────────────────────────────────────────────
// gh-head-ref-injection
// ──────────────────────────────────────────────────────────────
test("gh-head-ref-injection fires when github.head_ref is interpolated into run", () => {
  const yml = [
    "on: [pull_request]",
    "jobs:",
    "  b:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: git checkout ${{ github.head_ref }}",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-head-ref-injection"));
});

test("gh-head-ref-injection does not fire when head_ref only used in env var", () => {
  const yml = [
    "on: [pull_request]",
    "jobs:",
    "  b:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - env:",
    "          REF: ${{ github.head_ref }}",
    "        run: git checkout \"$REF\"",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-head-ref-injection"));
});

// ──────────────────────────────────────────────────────────────
// gh-action-not-pinned-sha (third-party)
// ──────────────────────────────────────────────────────────────
test("gh-action-not-pinned-sha fires on third-party action pinned to a tag", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: somevendor/deploy-action@v2",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-action-not-pinned-sha"));
});

test("gh-action-not-pinned-sha does not fire when SHA-pinned", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: somevendor/deploy-action@aabbccddeeff00112233445566778899aabbccdd  # v2.0.1",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-action-not-pinned-sha"));
});

// ──────────────────────────────────────────────────────────────
// gh-action-not-pinned-sha-official
// ──────────────────────────────────────────────────────────────
test("gh-action-not-pinned-sha-official fires on actions/checkout@v4", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-action-not-pinned-sha-official"));
});

test("gh-action-not-pinned-sha-official does not fire when actions/checkout is SHA-pinned", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-action-not-pinned-sha-official"));
});

// ──────────────────────────────────────────────────────────────
// gh-action-from-fork
// ──────────────────────────────────────────────────────────────
test("gh-action-from-fork fires on personal-account action pinned to main", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: randomuser/some-action@main",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-action-from-fork"));
});

test("gh-action-from-fork does not fire on actions/checkout@main", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@main",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-action-from-fork"));
});

// ──────────────────────────────────────────────────────────────
// gh-self-hosted-runner
// ──────────────────────────────────────────────────────────────
test("gh-self-hosted-runner fires on runs-on: self-hosted", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: self-hosted",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-self-hosted-runner"));
});

test("gh-self-hosted-runner does not fire on ubuntu-latest", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-self-hosted-runner"));
});

// ──────────────────────────────────────────────────────────────
// gh-artifact-upload-secrets
// ──────────────────────────────────────────────────────────────
test("gh-artifact-upload-secrets fires when upload-artifact path includes .env", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/upload-artifact@v4",
    "        with:",
    "          name: dump",
    "          path: |",
    "            build/",
    "            **/.env",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(ids(f).has("gh-artifact-upload-secrets"));
});

test("gh-artifact-upload-secrets does not fire on benign upload of a build dir", () => {
  const yml = [
    "on: [push]",
    "jobs:",
    "  x:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/upload-artifact@v4",
    "        with:",
    "          name: build",
    "          path: dist/",
  ].join("\n");
  const f = scanGithubWorkflow(yml);
  assert.ok(!ids(f).has("gh-artifact-upload-secrets"));
});

// ──────────────────────────────────────────────────────────────
// End-to-end via runScanGithub
// ──────────────────────────────────────────────────────────────
test("runScanGithub aggregates findings and skips non-workflow files", async () => {
  const vuln = await fixture("github/pwn-request.yml");
  const out = await runScanGithub({
    files: [
      { path: ".github/workflows/ci.yml", content: vuln },
      { path: "src/server.ts", content: "console.log('hi')" },
    ],
  });
  assert.equal(out.summary.filesScanned, 1);
  assert.ok(out.summary.totalFindings > 0);
  assert.ok(out.summary.bySeverity.critical >= 1);
});
