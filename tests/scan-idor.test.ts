import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { findIdorSuspects, ownershipHintCount } from "../src/engines/idor-prefilter.ts";
import { runScanIdor } from "../src/tools/scan-idor.ts";
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

test("pre-filter flags ORM fetch by request ID (basic IDOR)", async () => {
  const code = await fixture("idor/basic_idor.js");
  const suspects = findIdorSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/ownership check may be missing/i.test(reasons), `expected ownership reason: ${reasons}`);
  assert.ok(/enumerat|UUID|parsing request ID as integer/i.test(reasons), `expected integer-id reason: ${reasons}`);
});

test("pre-filter flags mass assignment via spread and Object.assign", async () => {
  const code = await fixture("idor/mass_assignment.ts");
  const suspects = findIdorSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/mass[-\s]?assignment/i.test(reasons), `expected mass-assignment: ${reasons}`);
  assert.ok(/Object\.assign/i.test(reasons), `expected Object.assign: ${reasons}`);
});

test("pre-filter flags unprotected admin routes and role-from-input", async () => {
  const code = await fixture("idor/admin_no_role.js");
  const suspects = findIdorSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/admin/i.test(reasons), `expected admin route flag: ${reasons}`);
  assert.ok(/Role flag read from user input/i.test(reasons), `expected role-from-input: ${reasons}`);
});

test("ownershipHintCount recognizes proper ownership patterns", async () => {
  const code = await fixture("idor/safe.ts");
  const hints = ownershipHintCount(code);
  assert.ok(hints >= 1, `expected >=1 ownership hint, got ${hints}`);
});

test("tool skips Claude when code has no data-access or admin patterns", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, "never");
  const out = await runScanIdor(
    { code: "export function greet(name){return 'hi ' + name}", language: "ts" },
    client,
  );
  assert.equal(out.analyzed, false);
  assert.equal(calls.length, 0);
});

test("tool calls Opus when IDOR suspects exist and forwards hint count", async () => {
  const calls: ClaudeRequest[] = [];
  const response = JSON.stringify({
    findings: [
      {
        name: "IDOR on GET /api/invoice/:id",
        kind: "missing_ownership",
        severity: "critical",
        line: 5,
        description: "The invoice is fetched by ID without any ownership filter.",
        exploit: "Attacker authenticates as User A and issues GET /api/invoice/42 to read User B's invoice.",
        fix: "Filter the query by both id and userId = req.user.id, or add an explicit ownership check.",
        fixedCode:
          "const inv = await db.invoice.findOne({ id: req.params.id, userId: req.user.id });",
      },
    ],
    summary: "Critical IDOR on invoice endpoints.",
  });
  const client = mockClient(calls, response);
  const code = await fixture("idor/basic_idor.js");
  const out = await runScanIdor({ code, language: "javascript", path: "routes/invoice.js" }, client);

  assert.equal(out.analyzed, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].user.includes("Ownership-hint patterns observed in file:"));
  assert.ok(calls[0].user.includes("routes/invoice.js"));
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].kind, "missing_ownership");
  assert.equal(out.findings[0].severity, "critical");
});

test("tool tolerates markdown-fenced JSON response", async () => {
  const calls: ClaudeRequest[] = [];
  const wrapped = "```json\n" + JSON.stringify({ findings: [], summary: "clean" }) + "\n```";
  const client = mockClient(calls, wrapped);
  const code = await fixture("idor/safe.ts");
  // safe.ts still has findFirst/updateMany which trip pre-filter — good, this tests Claude path.
  const out = await runScanIdor({ code, language: "typescript" }, client);
  assert.equal(out.analyzed, true);
  assert.equal(out.findings.length, 0);
  assert.match(out.summary, /clean/);
});

test("model override propagates to Claude request", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, JSON.stringify({ findings: [], summary: "ok" }));
  const code = await fixture("idor/basic_idor.js");
  const out = await runScanIdor(
    { code, language: "javascript", model: "claude-opus-4-6" },
    client,
  );
  assert.equal(out.analyzed, true);
  assert.equal(calls[0].model, "claude-opus-4-6");
  assert.equal(out.model, "claude-opus-4-6");
});
