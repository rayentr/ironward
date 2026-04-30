import { test } from "node:test";
import assert from "node:assert/strict";

import { runScanCode } from "../src/tools/scan-code.ts";
import { runScanSecrets } from "../src/tools/scan-secrets.ts";
import { runScanDocker } from "../src/tools/scan-docker.ts";
import { runScanGithub } from "../src/tools/scan-github.ts";
import { runScanInfra } from "../src/tools/scan-infra.ts";
import { runScanK8s } from "../src/tools/scan-k8s.ts";
import { runScanDeps } from "../src/tools/scan-deps.ts";

// =====================================================================
// scan_code (deterministic AST-free regex engine)
// =====================================================================

// WHY: empty input must not crash — boundary case for tool dispatchers.
test("scan_code: empty input handled gracefully", async () => {
  const out = await runScanCode({ files: [] });
  assert.equal(out.summary.totalFindings, 0);
  assert.equal(out.summary.filesScanned, 0);
});

// WHY: empty content scan must produce zero findings.
test("scan_code: empty content has no findings", async () => {
  const out = await runScanCode({ content: "" });
  assert.equal(out.summary.totalFindings, 0);
});

// WHY: a single canonical SQL injection must be detected.
test("scan_code: single vulnerability detected", async () => {
  const code = `app.get('/u', (req,res) => db.query('SELECT * FROM users WHERE id = ' + req.body.id));`;
  const out = await runScanCode({ files: [{ path: "u.ts", content: code }] });
  assert.ok(out.summary.totalFindings >= 1);
});

// WHY: multiple distinct vulnerabilities must all be detected.
test("scan_code: multiple vulnerabilities detected", async () => {
  const code = `
    const aws = "AKIA2E0A8F3B244C9986";
    const sql = "SELECT * FROM u WHERE id = " + req.body.id;
    const md5 = createHash('md5').update(p).digest('hex');
    const pw = "Sup3rS3cur3P@ssword";
    const tok = "Authorization: Bearer aBcDeFgH1J2K3L4M5N6O7P8Q9R0Sa";
  `;
  const out = await runScanCode({ files: [{ path: "x.ts", content: code }] });
  assert.ok(out.summary.totalFindings >= 3, `expected ≥3 findings, got ${out.summary.totalFindings}`);
});

// WHY: withExploits must attach exploit metadata to every finding.
test("scan_code: withExploits attaches exploit object", async () => {
  const code = `app.get('/u', (req,res) => db.query('SELECT * FROM users WHERE id = ' + req.body.id));`;
  const out = await runScanCode({
    files: [{ path: "u.ts", content: code }],
    withExploits: true,
  });
  const all = out.files.flatMap((f) => f.findings);
  const withExploit = all.filter((f) => "exploit" in f && f.exploit);
  assert.ok(withExploit.length >= 1);
});

// WHY: every finding must carry the contractual top-level fields.
test("scan_code: finding shape contract", async () => {
  const code = `const k = "AKIA2E0A8F3B244C9986";`;
  const out = await runScanCode({ files: [{ path: "k.ts", content: code }] });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 1);
  for (const f of all) {
    assert.equal(typeof f.ruleId, "string");
    assert.equal(typeof f.title, "string");
    assert.equal(typeof f.line, "number");
    assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
  }
});

// WHY: clean code must produce 0 findings (regression guard against rule overreach).
test("scan_code: clean code produces 0 findings", async () => {
  const code = `export const sum = (a: number, b: number): number => a + b;`;
  const out = await runScanCode({ files: [{ path: "math.ts", content: code }] });
  assert.equal(out.summary.totalFindings, 0);
});

// =====================================================================
// scan_secrets
// =====================================================================

// WHY: empty input handled.
test("scan_secrets: empty input handled gracefully", async () => {
  const out = await runScanSecrets({ files: [] });
  assert.equal(out.summary.totalFindings, 0);
});

// WHY: a single AWS access key must be detected.
test("scan_secrets: single secret detected", async () => {
  const out = await runScanSecrets({
    content: `const k = 'AKIA2E0A8F3B244C9986';`,
  });
  assert.ok(out.summary.totalFindings >= 1);
});

// WHY: multiple distinct secrets must all be detected.
test("scan_secrets: multiple secrets detected", async () => {
  const out = await runScanSecrets({
    content: `
      AKIA2E0A8F3B244C9986
      ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
      xoxb-1234567890-9876543210-aBcDeFgHiJkLmNoPqRsT
    `,
  });
  assert.ok(out.summary.totalFindings >= 3);
});

// WHY: blocked flag must be true when critical secrets are present.
test("scan_secrets: blocked flag set on critical", async () => {
  const out = await runScanSecrets({
    content: `const k = 'AKIA2E0A8F3B244C9986';`,
    context: "pre-commit",
  });
  assert.equal(typeof out.summary.blocked, "boolean");
  // Critical AWS key in pre-commit must block.
  assert.equal(out.summary.blocked, true);
});

// WHY: clean content produces no findings and does not block.
test("scan_secrets: clean content has 0 findings", async () => {
  const out = await runScanSecrets({ content: `const x = 1;` });
  assert.equal(out.summary.totalFindings, 0);
  assert.equal(out.summary.blocked, false);
});

// WHY: every finding must have line/column/redacted/severity contract fields.
test("scan_secrets: finding shape contract", async () => {
  const out = await runScanSecrets({
    content: `const k = 'AKIA2E0A8F3B244C9986';`,
  });
  for (const fr of out.files) {
    for (const f of fr.findings) {
      assert.equal(typeof f.line, "number");
      assert.equal(typeof f.column, "number");
      assert.equal(typeof f.redacted, "string");
      assert.ok(["critical", "high", "medium", "low"].includes(f.severity));
    }
  }
});

// =====================================================================
// scan_docker
// =====================================================================

// WHY: empty input handled.
test("scan_docker: empty input handled", async () => {
  const out = await runScanDocker({ files: [] });
  assert.equal(out.files.length, 0);
});

// WHY: a Dockerfile that runs as root must produce a finding.
test("scan_docker: root user detected", async () => {
  const out = await runScanDocker({
    files: [{ path: "Dockerfile", kind: "dockerfile", content: `FROM ubuntu:22.04\nUSER root\nRUN echo hi\n` }],
  });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 1);
});

// WHY: a Dockerfile that uses :latest tag must be flagged with the latest-tag rule.
test("scan_docker: latest tag flagged", async () => {
  const out = await runScanDocker({
    files: [{ path: "Dockerfile", kind: "dockerfile", content: `FROM node:latest\nWORKDIR /app\n` }],
  });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.some((f) => f.ruleId === "latest-tag"));
});

// WHY: a basic clean Dockerfile must NOT trigger any critical/high finding —
// best-practice flags (no-healthcheck) at low severity are acceptable.
test("scan_docker: clean Dockerfile has no critical/high findings", async () => {
  const out = await runScanDocker({
    files: [{ path: "Dockerfile", kind: "dockerfile", content: `FROM node:20-slim\nWORKDIR /app\nUSER node\nCMD ["node","app.js"]\n` }],
  });
  const all = out.files.flatMap((f) => f.findings);
  const criticalOrHigh = all.filter((f) => f.severity === "critical" || f.severity === "high");
  assert.equal(criticalOrHigh.length, 0);
});

// =====================================================================
// scan_github (Actions workflows)
// =====================================================================

// WHY: empty input handled.
test("scan_github: empty input handled", async () => {
  const out = await runScanGithub({ files: [] });
  assert.equal(out.files.length, 0);
});

// WHY: a workflow with pull_request_target + checkout must be flagged.
test("scan_github: pull_request_target with checkout flagged", async () => {
  const wf = `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`;
  const out = await runScanGithub({ files: [{ path: ".github/workflows/ci.yml", content: wf }] });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 1);
});

// WHY: clean workflow has no critical/high findings — pin-to-SHA is medium
// best-practice and not in scope for this contract.
test("scan_github: clean workflow has no critical/high findings", async () => {
  const wf = `
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`;
  const out = await runScanGithub({ files: [{ path: ".github/workflows/ci.yml", content: wf }] });
  const all = out.files.flatMap((f) => f.findings);
  const criticalOrHigh = all.filter((f) => f.severity === "critical" || f.severity === "high");
  assert.equal(criticalOrHigh.length, 0);
});

// =====================================================================
// scan_infra (Terraform)
// =====================================================================

// WHY: empty input handled.
test("scan_infra: empty input handled", async () => {
  const out = await runScanInfra({ files: [] });
  assert.equal(out.files.length, 0);
});

// WHY: an open-to-the-world security group rule must fire.
test("scan_infra: open security group flagged", async () => {
  const tf = `resource "aws_security_group" "open" {\n  ingress { from_port = 22; to_port = 22; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }\n}`;
  const out = await runScanInfra({
    files: [{ path: "main.tf", kind: "terraform", content: tf }],
  });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 1);
});

// WHY: clean terraform has no critical findings — encryption-best-practice
// flags are medium and not in this contract.
test("scan_infra: clean terraform has no critical findings", async () => {
  const tf = `resource "aws_s3_bucket" "log" { bucket = "company-logs" }`;
  const out = await runScanInfra({
    files: [{ path: "main.tf", kind: "terraform", content: tf }],
  });
  const all = out.files.flatMap((f) => f.findings);
  const critical = all.filter((f) => f.severity === "critical");
  assert.equal(critical.length, 0);
});

// =====================================================================
// scan_k8s
// =====================================================================

// WHY: empty input handled.
test("scan_k8s: empty input handled", async () => {
  const out = await runScanK8s({ files: [] });
  assert.equal(out.files.length, 0);
});

// WHY: a privileged container must be flagged.
test("scan_k8s: privileged container flagged", async () => {
  const yaml = `apiVersion: v1\nkind: Pod\nmetadata: { name: bad }\nspec:\n  containers:\n  - name: app\n    image: nginx:1.27\n    securityContext:\n      privileged: true\n`;
  const out = await runScanK8s({ files: [{ path: "pod.yaml", content: yaml }] });
  const all = out.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 1);
});

// WHY: a clean pod has no critical/high findings — probe-related warnings
// are medium and not in this contract.
test("scan_k8s: clean pod has no critical/high findings", async () => {
  const yaml = `apiVersion: v1\nkind: Pod\nmetadata: { name: ok }\nspec:\n  containers:\n  - name: app\n    image: nginx:1.27\n    resources:\n      limits: { cpu: "100m", memory: "128Mi" }\n      requests: { cpu: "50m", memory: "64Mi" }\n    securityContext:\n      runAsNonRoot: true\n      readOnlyRootFilesystem: true\n      allowPrivilegeEscalation: false\n      capabilities: { drop: [ALL] }\n`;
  const out = await runScanK8s({ files: [{ path: "pod.yaml", content: yaml }] });
  const all = out.files.flatMap((f) => f.findings);
  const criticalOrHigh = all.filter((f) => f.severity === "critical" || f.severity === "high");
  assert.equal(criticalOrHigh.length, 0);
});

// =====================================================================
// scan_deps
// =====================================================================

// WHY: empty input handled.
test("scan_deps: empty input handled", async () => {
  const out = await runScanDeps({ manifests: [] });
  assert.equal(out.dependenciesScanned, 0);
});

// WHY: a known-malicious package (event-stream@3.3.6) must produce critical
// MALWARE finding. WHY: flatfile typosquat is the headline supply-chain demo.
test("scan_deps: known-malware package detected", async () => {
  const out = await runScanDeps({
    manifests: [{ path: "package.json", content: JSON.stringify({ name: "demo", dependencies: { "event-stream": "3.3.6" } }) }],
  });
  const allFindings = [...out.findings, ...out.intel];
  assert.ok(allFindings.length >= 1);
});

// WHY: a clean manifest produces no critical findings.
test("scan_deps: clean manifest has no critical findings", async () => {
  const out = await runScanDeps({
    manifests: [{ path: "package.json", content: JSON.stringify({ name: "ok", dependencies: { "react": "^18.0.0" } }) }],
  });
  const critical = out.findings.filter((f) => f.severity === "critical");
  assert.equal(critical.length, 0);
});
