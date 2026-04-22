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

// ---------------------------------------------------------------------------
// v1.3.0: new rules — injection, crypto, auth, python, info leaks
// ---------------------------------------------------------------------------

test("flags NoSQL injection, LDAP, XXE, header/log injection", async () => {
  const f = await scanFixture("code/injection_extras.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("nosql-mongo-where"), `missing nosql-mongo-where: ${[...ids].join(",")}`);
  assert.ok(ids.has("nosql-mongo-mapreduce"), `missing nosql-mongo-mapreduce: ${[...ids].join(",")}`);
  assert.ok(ids.has("ldap-filter-user-input"), `missing ldap-filter-user-input: ${[...ids].join(",")}`);
  assert.ok(ids.has("xxe-xml-parser"), `missing xxe-xml-parser: ${[...ids].join(",")}`);
  assert.ok(ids.has("header-injection-crlf"), `missing header-injection-crlf: ${[...ids].join(",")}`);
  assert.ok(ids.has("log-injection-user-input"), `missing log-injection-user-input: ${[...ids].join(",")}`);
});

test("flags Handlebars and Pug template injection", async () => {
  const f = await scanFixture("code/templates.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("template-handlebars-compile-user"));
  assert.ok(ids.has("template-pug-user-input"));
});

test("flags Python-specific rules (pickle, yaml, subprocess, assert, flask debug, exec, jinja)", async () => {
  const f = await scanFixture("code/templates.py");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("template-jinja-render-string"), `missing jinja: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-pickle-loads-untrusted"), `missing pickle: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-yaml-load-unsafe"), `missing yaml: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-subprocess-shell-true"), `missing subprocess: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-assert-security-check"), `missing assert: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-flask-debug-true"), `missing flask debug: ${[...ids].join(",")}`);
  assert.ok(ids.has("py-exec-call"), `missing py-exec: ${[...ids].join(",")}`);
});

test("flags Django DEBUG=True in settings", async () => {
  const f = await scanFixture("code/django_settings.py");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("py-django-debug-true"));
});

test("flags extra crypto rules (hardcoded IV, ECB, RSA padding, short keys, bcrypt/scrypt)", async () => {
  const f = await scanFixture("code/crypto_extras.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("crypto-hardcoded-iv"), `missing hardcoded-iv: ${[...ids].join(",")}`);
  assert.ok(ids.has("crypto-ecb-mode"), `missing ecb: ${[...ids].join(",")}`);
  assert.ok(ids.has("crypto-rsa-without-oaep"), `missing rsa-padding: ${[...ids].join(",")}`);
  assert.ok(ids.has("crypto-short-rsa-key"), `missing short-rsa: ${[...ids].join(",")}`);
  assert.ok(ids.has("crypto-short-aes-key"), `missing short-aes: ${[...ids].join(",")}`);
  assert.ok(ids.has("bcrypt-short-salt-rounds"), `missing bcrypt-rounds: ${[...ids].join(",")}`);
  assert.ok(ids.has("scrypt-low-n"), `missing scrypt-n: ${[...ids].join(",")}`);
});

test("flags authentication rules (jwt.decode, cookie samesite, password-in-url, basic-auth, timing)", async () => {
  const f = await scanFixture("code/auth_extras.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("jwt-decode-not-verify"), `missing jwt-decode: ${[...ids].join(",")}`);
  assert.ok(ids.has("cookie-no-samesite"), `missing cookie-samesite: ${[...ids].join(",")}`);
  assert.ok(ids.has("password-in-url-query"), `missing pw-in-url: ${[...ids].join(",")}`);
  assert.ok(ids.has("basic-auth-over-http"), `missing basic-auth: ${[...ids].join(",")}`);
  assert.ok(ids.has("timing-unsafe-comparison"), `missing timing-unsafe: ${[...ids].join(",")}`);
  assert.ok(ids.has("hmac-no-timing-safe"), `missing hmac-timing: ${[...ids].join(",")}`);
});

test("flags Node-specific rules (exec template, require user-input, fs write user-path)", async () => {
  const f = await scanFixture("code/node_extras.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("child-process-exec-template"), `missing exec-template: ${[...ids].join(",")}`);
  assert.ok(ids.has("require-user-input"), `missing require-user: ${[...ids].join(",")}`);
  assert.ok(ids.has("fs-write-user-path"), `missing fs-write: ${[...ids].join(",")}`);
});

test("flags info leaks (source-map reference, stack trace in response)", async () => {
  const f = await scanFixture("code/info_leaks.js");
  const ids = new Set(f.map((x) => x.ruleId));
  assert.ok(ids.has("source-map-reference-in-prod"), `missing sourcemap: ${[...ids].join(",")}`);
  assert.ok(ids.has("stack-trace-in-response"), `missing stack-trace: ${[...ids].join(",")}`);
});

test("safe cookie with sameSite is NOT flagged", () => {
  const code = `res.cookie("s", id, { httpOnly: true, sameSite: "lax", secure: true });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "cookie-no-samesite"));
});

test("jwt.verify is NOT flagged as jwt.decode", () => {
  const code = `const p = jwt.verify(token, secret, { algorithms: ["HS256"] });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-decode-not-verify"));
});

test("yaml.safe_load is NOT flagged", () => {
  const code = `data = yaml.safe_load(content)`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-yaml-load-unsafe"));
});

test("yaml.load with SafeLoader is NOT flagged", () => {
  const code = `data = yaml.load(content, Loader=yaml.SafeLoader)`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-yaml-load-unsafe"));
});

test("subprocess.run without shell=True is NOT flagged", () => {
  const code = `subprocess.run(["git", "status"])`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-subprocess-shell-true"));
});

test("rule.re.exec method call is NOT flagged as py-exec-call", () => {
  const code = `while ((m = rule.re.exec(content)) !== null) { /* ... */ }`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-exec-call"));
});

test("all new categories resolve to a defined rule", () => {
  // Sanity check: confirm the new categories have at least one rule.
  // Ensures the union expansion is backed by real rules.
  const code = `
    $where: req.body.q;
    new DOMParser();
    render_template_string(request.args);
    res.setHeader("X", req.query.v);
    password === req.body.pw;
    pickle.loads(request.data);
  `;
  const f = scanCodeRules(code);
  const categories = new Set(f.map((x) => x.category));
  assert.ok(categories.has("nosql"));
  assert.ok(categories.has("xxe"));
  assert.ok(categories.has("template-injection"));
  assert.ok(categories.has("header-injection"));
  assert.ok(categories.has("timing-attack"));
  assert.ok(categories.has("python"));
});
