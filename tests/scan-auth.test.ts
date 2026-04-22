import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runScanAuth, type ScanAuthInput } from "../src/tools/scan-auth.ts";
import type { ClaudeClient, ClaudeRequest } from "../src/engines/claude-client.ts";
import { extractJson } from "../src/engines/claude-client.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

interface Recorder {
  calls: ClaudeRequest[];
}

function mockClient(recorder: Recorder, response: string): ClaudeClient {
  return {
    async analyze(req: ClaudeRequest) {
      recorder.calls.push(req);
      return response;
    },
  };
}

test("pre-filter skips Claude when code has no auth keywords", async () => {
  const rec: Recorder = { calls: [] };
  const client = mockClient(rec, "should-not-be-called");
  const out = await runScanAuth({ code: "function add(a,b){return a+b}", language: "js" }, client);
  assert.equal(out.analyzed, false);
  assert.equal(rec.calls.length, 0);
  assert.ok(out.summary.length > 0);
});

test("pre-filter skips on empty input", async () => {
  const rec: Recorder = { calls: [] };
  const client = mockClient(rec, "never");
  const out = await runScanAuth({ code: "" } as ScanAuthInput, client);
  assert.equal(out.analyzed, false);
  assert.equal(rec.calls.length, 0);
});

test("calls Claude when auth keywords are present and parses structured response", async () => {
  const rec: Recorder = { calls: [] };
  const response = JSON.stringify({
    findings: [
      {
        name: "Backwards auth check on /admin/users/:id/promote",
        severity: "critical",
        line: 5,
        description: "The guard is inverted; unauthenticated requests hit the privileged branch.",
        exploit: "Send POST /admin/users/42/promote with no cookie; the role update runs.",
        fix: "Invert the guard or early-return when no user is present.",
        fixedCode: "if (!user) return res.status(401).end();",
      },
    ],
    summary: "Inverted auth check — critical.",
  });
  const client = mockClient(rec, response);
  const code = await fixture("auth/backwards_check.js");
  const out = await runScanAuth({ code, language: "javascript", path: "backwards.js" }, client);

  assert.equal(out.analyzed, true);
  assert.equal(rec.calls.length, 1);
  assert.ok(rec.calls[0].user.includes("backwards.js"), "prompt should include file path");
  assert.ok(rec.calls[0].user.includes("javascript"), "prompt should include language tag");
  assert.ok(rec.calls[0].user.includes("req.session?.user"), "prompt should include the code");
  assert.ok(rec.calls[0].system.includes("authentication and authorization"), "system prompt scope");

  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].severity, "critical");
  assert.equal(out.findings[0].line, 5);
  assert.ok(out.findings[0].fixedCode?.includes("401"));
});

test("tolerates markdown-fenced JSON from the model", async () => {
  const rec: Recorder = { calls: [] };
  const wrapped = "```json\n" + JSON.stringify({ findings: [], summary: "clean" }) + "\n```";
  const client = mockClient(rec, wrapped);
  const code = await fixture("auth/safe_auth.ts");
  const out = await runScanAuth({ code, language: "typescript" }, client);
  assert.equal(out.analyzed, true);
  assert.equal(out.findings.length, 0);
  assert.match(out.summary, /clean/);
});

test("tolerates prose prefix around JSON", async () => {
  const rec: Recorder = { calls: [] };
  const response =
    "Here is the analysis:\n\n" +
    JSON.stringify({ findings: [{ name: "X", severity: "high", description: "d", exploit: "e", fix: "f" }], summary: "s" });
  const client = mockClient(rec, response);
  const code = await fixture("auth/missing_ownership.py");
  const out = await runScanAuth({ code, language: "python" }, client);
  assert.equal(out.analyzed, true);
  assert.equal(out.findings.length, 1);
});

test("defaults missing fields on a partial model response", async () => {
  const rec: Recorder = { calls: [] };
  const response = JSON.stringify({
    findings: [{ name: "JWT none alg accepted" }],
  });
  const client = mockClient(rec, response);
  const code = await fixture("auth/jwt_none_alg.js");
  const out = await runScanAuth({ code, language: "javascript" }, client);
  assert.equal(out.analyzed, true);
  const f = out.findings[0];
  assert.equal(f.name, "JWT none alg accepted");
  assert.equal(f.severity, "medium");
  assert.equal(f.line, null);
});

test("extractJson: strict JSON", () => {
  const v = extractJson<{ x: number }>('{"x":1}');
  assert.equal(v.x, 1);
});

test("extractJson: throws on garbage", () => {
  assert.throws(() => extractJson("not json at all, no braces"));
});

test("uses the model override when provided", async () => {
  const rec: Recorder = { calls: [] };
  const client = mockClient(rec, JSON.stringify({ findings: [], summary: "ok" }));
  const out = await runScanAuth(
    { code: "const user = req.session.user; if (user) doThing();", language: "js", model: "claude-opus-4-7" },
    client,
  );
  assert.equal(out.analyzed, true);
  assert.equal(rec.calls[0].model, "claude-opus-4-7");
  assert.equal(out.model, "claude-opus-4-7");
});
