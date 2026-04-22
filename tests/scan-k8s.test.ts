import { test } from "node:test";
import assert from "node:assert/strict";
import { scanK8sManifest, runScanK8s, detectK8s } from "../src/tools/scan-k8s.ts";

function ids(findings: ReturnType<typeof scanK8sManifest>) {
  return new Set(findings.map((f) => f.ruleId));
}

test("detectK8s recognizes a Pod manifest", () => {
  assert.equal(detectK8s("pod.yaml", "apiVersion: v1\nkind: Pod\n"), true);
  assert.equal(detectK8s("deploy.yml", "apiVersion: apps/v1\nkind: Deployment\n"), true);
});

test("detectK8s ignores non-K8s yaml", () => {
  assert.equal(detectK8s("config.yaml", "foo: bar\nbaz: 1\n"), false);
  assert.equal(detectK8s("compose.yml", "services:\n  web:\n    image: nginx\n"), false);
});

test("privileged container fires k8s-privileged-true", () => {
  const yml = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  containers:",
    "  - name: app",
    "    image: nginx:1.25",
    "    securityContext:",
    "      privileged: true",
  ].join("\n");
  assert.ok(ids(scanK8sManifest(yml)).has("k8s-privileged-true"));
});

test("hostNetwork / hostPID / hostIPC fire their rules", () => {
  const yml = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  hostNetwork: true",
    "  hostPID: true",
    "  hostIPC: true",
    "  containers:",
    "  - name: x",
    "    image: nginx:1",
  ].join("\n");
  const s = ids(scanK8sManifest(yml));
  assert.ok(s.has("k8s-host-network"));
  assert.ok(s.has("k8s-host-pid"));
  assert.ok(s.has("k8s-host-ipc"));
});

test("dangerous capability fires k8s-sensitive-capability-added", () => {
  const yml = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  containers:",
    "  - name: x",
    "    image: nginx:1",
    "    securityContext:",
    "      capabilities:",
    "        add: [\"SYS_ADMIN\"]",
  ].join("\n");
  assert.ok(ids(scanK8sManifest(yml)).has("k8s-sensitive-capability-added"));
});

test("image with :latest tag fires k8s-image-latest-tag", () => {
  const yml = [
    "apiVersion: apps/v1",
    "kind: Deployment",
    "spec:",
    "  template:",
    "    spec:",
    "      containers:",
    "      - name: web",
    "        image: nginx:latest",
  ].join("\n");
  assert.ok(ids(scanK8sManifest(yml)).has("k8s-image-latest-tag"));
});

test("allowPrivilegeEscalation: true fires its rule", () => {
  const yml = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  containers:",
    "  - name: x",
    "    image: nginx:1",
    "    securityContext:",
    "      allowPrivilegeEscalation: true",
  ].join("\n");
  assert.ok(ids(scanK8sManifest(yml)).has("k8s-allow-privilege-escalation"));
});

test("runScanK8s ignores non-K8s files", async () => {
  const out = await runScanK8s({ files: [{ path: "foo.txt", content: "hello" }] });
  assert.equal(out.files.length, 0);
});

test("runScanK8s reports a Pod manifest", async () => {
  const yml = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  containers:",
    "  - name: x",
    "    image: nginx:latest",
    "    securityContext:",
    "      privileged: true",
  ].join("\n");
  const out = await runScanK8s({ files: [{ path: "pod.yaml", content: yml }] });
  assert.equal(out.files.length, 1);
  assert.ok(out.summary.totalFindings >= 2);
});
