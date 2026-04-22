import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { findSqlSuspects } from "../src/engines/sql-prefilter.ts";
import { runScanSqli } from "../src/tools/scan-sqli.ts";
import type { ClaudeClient, ClaudeRequest } from "../src/engines/claude-client.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

function mockClient(calls: ClaudeRequest[], response: string): ClaudeClient {
  return {
    async analyze(req: ClaudeRequest) {
      calls.push(req);
      return response;
    },
  };
}

test("pre-filter flags string concatenation with SELECT", async () => {
  const code = await fixture("sqli/string_concat.js");
  const suspects = findSqlSuspects(code);
  assert.ok(suspects.length > 0, "expected at least one suspect");
  assert.ok(
    suspects.some((s) => /concatenat/i.test(s.reason)),
    "expected a concatenation reason",
  );
});

test("pre-filter flags Python f-string SQL", async () => {
  const code = await fixture("sqli/fstring.py");
  const suspects = findSqlSuspects(code);
  assert.ok(suspects.some((s) => /f-string/i.test(s.reason)), "expected f-string suspect");
});

test("pre-filter flags ORM raw() with interpolation", async () => {
  const code = await fixture("sqli/orm_raw.ts");
  const suspects = findSqlSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/raw|interpolation|template/i.test(reasons), `expected raw/interp reason, got: ${reasons}`);
  assert.ok(suspects.length >= 2, "expected >=2 interpolation suspects");
});

test("pre-filter does NOT flag parameterized queries", async () => {
  const code = await fixture("sqli/safe_parameterized.js");
  const suspects = findSqlSuspects(code);
  assert.equal(suspects.length, 0, `expected 0 suspects, got ${suspects.length}: ${JSON.stringify(suspects)}`);
});

test("tool skips Claude when no SQL patterns present", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, "never");
  const out = await runScanSqli({ code: "function add(a,b){return a+b}", language: "js" }, client);
  assert.equal(out.analyzed, false);
  assert.equal(calls.length, 0);
  assert.equal(out.suspects.length, 0);
});

test("tool skips Claude when code is parameterized (pre-filter miss)", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, "never");
  const code = await fixture("sqli/safe_parameterized.js");
  const out = await runScanSqli({ code, language: "javascript" }, client);
  assert.equal(out.analyzed, false);
  assert.equal(calls.length, 0);
});

test("tool calls Claude when suspects exist and parses a finding", async () => {
  const calls: ClaudeRequest[] = [];
  const response = JSON.stringify({
    findings: [
      {
        name: "SQL injection in /login via string concat",
        severity: "critical",
        line: 5,
        description: "username and password are concatenated directly into the SQL string.",
        exploit: "Send username=' OR 1=1-- with any password; query returns every row.",
        fix: "Use parameterized queries with $1/$2 placeholders.",
        fixedCode: "db.query('SELECT * FROM users WHERE username=$1 AND password_hash=$2', [u, h])",
      },
    ],
    summary: "Critical SQLi in /login.",
  });
  const client = mockClient(calls, response);
  const code = await fixture("sqli/string_concat.js");
  const out = await runScanSqli({ code, language: "javascript", path: "login.js" }, client);

  assert.equal(out.analyzed, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].user.includes("Suspects (from pre-filter):"), "prompt should list suspects");
  assert.ok(calls[0].user.includes("login.js"), "prompt should include path");
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].severity, "critical");
});

test("tool tolerates fenced JSON response", async () => {
  const calls: ClaudeRequest[] = [];
  const wrapped = "```json\n" + JSON.stringify({ findings: [], summary: "clean under review" }) + "\n```";
  const client = mockClient(calls, wrapped);
  const code = await fixture("sqli/orm_raw.ts");
  const out = await runScanSqli({ code, language: "typescript" }, client);
  assert.equal(out.analyzed, true);
  assert.equal(out.findings.length, 0);
  assert.match(out.summary, /clean/);
});

test("model override propagates to Claude request", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, JSON.stringify({ findings: [], summary: "ok" }));
  const code = await fixture("sqli/fstring.py");
  const out = await runScanSqli(
    { code, language: "python", model: "claude-sonnet-4-6" },
    client,
  );
  assert.equal(out.analyzed, true);
  assert.equal(calls[0].model, "claude-sonnet-4-6");
  assert.equal(out.model, "claude-sonnet-4-6");
});
