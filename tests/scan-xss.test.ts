import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { findXssSuspects } from "../src/engines/xss-prefilter.ts";
import { runScanXss } from "../src/tools/scan-xss.ts";
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

test("pre-filter flags reflected XSS via res.send template literal", async () => {
  const code = await fixture("xss/reflected.js");
  const suspects = findXssSuspects(code);
  assert.ok(suspects.length > 0, "expected at least one suspect");
  assert.ok(suspects.some((s) => /response/i.test(s.reason) || /reflected/i.test(s.reason)));
});

test("pre-filter flags DOM sinks: innerHTML, document.write, eval", async () => {
  const code = await fixture("xss/dom_innerhtml.js");
  const suspects = findXssSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/innerHTML/.test(reasons), `expected innerHTML: ${reasons}`);
  assert.ok(/document\.write/i.test(reasons), `expected document.write: ${reasons}`);
  assert.ok(/eval/i.test(reasons), `expected eval: ${reasons}`);
});

test("pre-filter flags React dangerouslySetInnerHTML", async () => {
  const code = await fixture("xss/react_dangerous.tsx");
  const suspects = findXssSuspects(code);
  assert.ok(suspects.some((s) => /dangerouslySetInnerHTML/i.test(s.reason)));
});

test("pre-filter flags Vue v-html", async () => {
  const code = await fixture("xss/vue_v_html.vue");
  const suspects = findXssSuspects(code);
  assert.ok(suspects.some((s) => /v-html/i.test(s.reason)));
});

test("pre-filter flags EJS <%- %> and Handlebars triple-brace", async () => {
  const code = await fixture("xss/template_injection.js");
  const suspects = findXssSuspects(code);
  const reasons = suspects.map((s) => s.reason).join("|");
  assert.ok(/EJS/i.test(reasons), `expected EJS: ${reasons}`);
  assert.ok(/Handlebars|Mustache|triple-brace/i.test(reasons), `expected Handlebars: ${reasons}`);
});

test("pre-filter does NOT flag DOMPurify-sanitized or textContent usage", async () => {
  const code = await fixture("xss/safe.js");
  const suspects = findXssSuspects(code);
  assert.equal(suspects.length, 0, `expected 0 suspects, got: ${JSON.stringify(suspects)}`);
});

test("tool skips Claude when no XSS sinks present", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, "never");
  const out = await runScanXss(
    { code: "function add(a,b){return a+b}", language: "js" },
    client,
  );
  assert.equal(out.analyzed, false);
  assert.equal(calls.length, 0);
});

test("tool skips Claude on sanitized/safe code", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, "never");
  const code = await fixture("xss/safe.js");
  const out = await runScanXss({ code, language: "javascript" }, client);
  assert.equal(out.analyzed, false);
  assert.equal(calls.length, 0);
});

test("tool calls Claude when suspects exist and parses a finding", async () => {
  const calls: ClaudeRequest[] = [];
  const response = JSON.stringify({
    findings: [
      {
        name: "Reflected XSS in /search via template interpolation",
        kind: "reflected",
        severity: "high",
        line: 5,
        description: "The q query parameter is interpolated directly into the HTML response.",
        exploit: "GET /search?q=<script>alert(document.cookie)</script> executes in the victim's browser.",
        fix: "HTML-escape the value with `he.encode(q)` before interpolation, or use a template engine with escaping on.",
        fixedCode: "res.send(`<h1>Results for: ${he.encode(q)}</h1>`)",
      },
    ],
    summary: "Reflected XSS in /search.",
  });
  const client = mockClient(calls, response);
  const code = await fixture("xss/reflected.js");
  const out = await runScanXss({ code, language: "javascript", path: "routes/search.js" }, client);

  assert.equal(out.analyzed, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].user.includes("Suspects (from pre-filter):"));
  assert.ok(calls[0].user.includes("routes/search.js"));
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].kind, "reflected");
  assert.equal(out.findings[0].severity, "high");
});

test("tool tolerates markdown-fenced JSON response", async () => {
  const calls: ClaudeRequest[] = [];
  const wrapped = "```json\n" + JSON.stringify({ findings: [], summary: "reviewed clean" }) + "\n```";
  const client = mockClient(calls, wrapped);
  const code = await fixture("xss/dom_innerhtml.js");
  const out = await runScanXss({ code, language: "javascript" }, client);
  assert.equal(out.analyzed, true);
  assert.equal(out.findings.length, 0);
  assert.match(out.summary, /clean/);
});

test("model override propagates to Claude request", async () => {
  const calls: ClaudeRequest[] = [];
  const client = mockClient(calls, JSON.stringify({ findings: [], summary: "ok" }));
  const code = await fixture("xss/reflected.js");
  const out = await runScanXss(
    { code, language: "javascript", model: "claude-sonnet-4-6" },
    client,
  );
  assert.equal(out.analyzed, true);
  assert.equal(calls[0].model, "claude-sonnet-4-6");
  assert.equal(out.model, "claude-sonnet-4-6");
});
