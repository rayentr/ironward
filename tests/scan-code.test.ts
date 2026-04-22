import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanCodeRules } from "../src/engines/code-rules.ts";
import { runScanCode } from "../src/tools/scan-code.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => readFile(join(here, "fixtures", name), "utf8");

async function scanFixture(rel: string) {
  const content = await fixture(rel);
  return scanCodeRules(content);
}

test("flags eval, new Function, and exec-with-user-input", async () => {
  const f = await scanFixture("code/dangerous.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("eval-call"));
  assert.ok(ids.has("new-function-constructor"));
  assert.ok(ids.has("child-process-user-input"));
});

test("flags MD5, SHA-1, DES cipher, and Math.random for tokens", async () => {
  const f = await scanFixture("code/weak_crypto.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("md5-hash"), `missing md5: ${[...ids].join(",")}`);
  assert.ok(ids.has("sha1-hash"));
  assert.ok(ids.has("des-cipher"));
  assert.ok(ids.has("math-random-secret"));
});

test("flags SSRF, open redirect, prototype pollution, CORS wildcard, weak JWT", async () => {
  const f = await scanFixture("code/web_flaws.ts");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("ssrf-fetch"), `missing ssrf: ${[...ids].join(",")}`);
  assert.ok(ids.has("open-redirect"));
  assert.ok(ids.has("prototype-pollution-merge"));
  assert.ok(ids.has("cors-wildcard-literal"));
  assert.ok(ids.has("jwt-hardcoded-weak-secret"));
  assert.ok(ids.has("jwt-alg-none"));
});

test("flags debugger, commented secret, console.log secret, insecure HTTP, TODO-security", async () => {
  const f = await scanFixture("code/misc_leaks.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("debugger-statement"));
  assert.ok(ids.has("commented-secret"), `missing commented-secret: ${[...ids].join(",")}`);
  assert.ok(ids.has("console-log-secret"));
  assert.ok(ids.has("insecure-http-fetch"));
  assert.ok(ids.has("todo-security"));
});

test("safe fixture produces zero findings", async () => {
  const f = await scanFixture("code/safe.ts");
  assert.equal(f.length, 0, `expected 0, got: ${JSON.stringify(f.map((x) => `${x.ruleId}@L${x.line}`))}`);
});

test("ignore directive suppresses findings on the same line", () => {
  const code = `const x = eval(req.body.code); // ironward-ignore\n`;
  const f = scanCodeRules(code);
  assert.equal(f.length, 0);
});

test("runScanCode with inline files returns a summary with severity counts", async () => {
  const content = await fixture("code/dangerous.js");
  const out = await runScanCode({ files: [{ path: "dangerous.js", content }] });
  assert.ok(out.summary.totalFindings > 0);
  assert.ok(out.summary.bySeverity.critical > 0);
  assert.equal(out.summary.filesScanned, 1);
});

test("runScanCode skips node_modules and dist", async () => {
  const out = await runScanCode({
    files: [
      { path: "node_modules/evil/index.js", content: "eval(req.body)" },
      { path: "src/index.js", content: "eval(req.body)" },
    ],
  });
  // node_modules path is filtered, only src/ survives.
  assert.equal(out.files.length, 1);
  assert.equal(out.files[0].path, "src/index.js");
});

test("hardcoded JWT secret 'secret' is flagged as critical", () => {
  const code = `const t = jwt.sign({id: u.id}, "secret");`;
  const f = scanCodeRules(code);
  const jwtFinding = f.find((x) => x.ruleId === "jwt-hardcoded-weak-secret");
  assert.ok(jwtFinding);
  assert.equal(jwtFinding!.severity, "critical");
});

test("insecure-http-fetch ignores localhost", () => {
  const code = `const r = await fetch("http://localhost:3000/api");`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "insecure-http-fetch"));
});

test("SQL string concat with request input is flagged critical", () => {
  const code = `db.query("SELECT * FROM users WHERE name=" + req.params.name);`;
  const f = scanCodeRules(code);
  const sql = f.find((x) => x.ruleId === "sql-string-concat");
  assert.ok(sql);
  assert.equal(sql!.severity, "critical");
});

test("path.join with request input is flagged", () => {
  const code = `const p = path.join("/var/data", req.params.file);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "path-join-user-input"));
});
