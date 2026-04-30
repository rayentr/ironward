import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: vm.runInNewContext is not a security boundary. User code in a vm context
// can break out via constructor walks; we must flag the moment user input
// reaches it.
test("nodejs-depth: vm.runInNewContext with req.body is flagged", () => {
  const code = `vm.runInNewContext(req.body.script, sandbox);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "node-vm-runincontext-user");
  assert.ok(finding, "expected node-vm-runincontext-user");
  assert.equal(finding.severity, "critical");
});

// WHY: runInThisContext is the same risk as runInNewContext — the rule is one
// regex covering all vm.run* variants.
test("nodejs-depth: vm.runInThisContext with request input is flagged", () => {
  const code = `vm.runInThisContext(request.query.code);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-vm-runincontext-user"));
});

// WHY: Object.assign({}, req.body) is the canonical proto-pollution sink — any
// __proto__ key from the body lands on Object.prototype.
test("nodejs-depth: Object.assign({}, req.body) is flagged", () => {
  const code = `const merged = Object.assign({}, req.body);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-prototype-pollution-object-assign"));
});

// WHY: lodash.set walks an arbitrary path string; '__proto__.isAdmin' from the
// user pollutes Object.prototype.
test("nodejs-depth: lodash.set with req.body key is flagged", () => {
  const code = `_.set(target, req.body.path, req.body.value);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-lodash-set-user-key"));
});

// WHY: lodash.setWith follows the same code path; rule covers both names.
test("nodejs-depth: lodash.setWith with req.query key is flagged", () => {
  const code = `lodash.setWith(target, req.query.k, val, Object);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-lodash-set-user-key"));
});

// WHY: lock in current behavior — JSON.parse on a request body field without
// a __proto__-stripping reviver fires the low-confidence rule. If this stops
// firing we want to know.
test("nodejs-depth: JSON.parse on req.body field without reviver is flagged (low)", () => {
  const code = `const obj = JSON.parse(req.body.json);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "node-json-parse-user-no-reviver");
  assert.ok(finding, "expected node-json-parse-user-no-reviver");
  assert.equal(finding.severity, "low");
});

// WHY: nested-quantifier ReDoS — /(a+)+$/ is the textbook catastrophic
// backtracking pattern. The rule should match any nested + or * group.
test("nodejs-depth: regex with nested quantifier (ReDoS) is flagged", () => {
  const code = `const re = /(a+)+$/;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-regex-redos-nested-quantifier"));
});

// WHY: rejectUnauthorized: false on https.Agent disables TLS validation —
// MITM-trivial. Highest-confidence TLS bypass rule.
test("nodejs-depth: rejectUnauthorized: false in https.Agent is flagged", () => {
  const code = `const agent = new https.Agent({ rejectUnauthorized: false });`;
  const f = scanCodeRules(code);
  // Both rules can fire (the bare-field one and the axios httpsAgent one);
  // we only require the field-level rule.
  assert.ok(f.some((x) => x.ruleId === "node-tls-reject-unauthorized-false"));
});

// WHY: NODE_TLS_REJECT_UNAUTHORIZED='0' disables TLS for the WHOLE process —
// critical-severity by design.
test("nodejs-depth: NODE_TLS_REJECT_UNAUTHORIZED = '0' is flagged", () => {
  const code = `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "node-tls-reject-env-zero");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: crypto.createCipher is deprecated — derives key/IV via MD5 with no
// salt. Identical plaintexts encrypt identically.
test("nodejs-depth: crypto.createCipher (no IV) is flagged", () => {
  const code = `const c = crypto.createCipher('aes-256-cbc', passphrase);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "node-create-cipher-no-iv"));
});

// WHY: child_process.exec with template literal interpolation is shell
// concatenation — command injection if any value is user-controlled.
test("nodejs-depth: child_process.exec with template literal is flagged", () => {
  const code = "child_process.exec(`echo ${userVar}`);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "child-process-exec-template"));
});

// WHY: dynamic require with request input loads arbitrary modules.
test("nodejs-depth: require(req.body.module) is flagged", () => {
  const code = `const mod = require(req.body.module);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "require-user-input"));
});

// WHY: fs.readFile with user-controlled path is path traversal — three
// variants must all flag.
test("nodejs-depth: fs.readFile(req.body.x) is flagged", () => {
  const code = `fs.readFile(req.body.path, 'utf8', cb);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "fs-read-user-input"));
});

test("nodejs-depth: fs.readFileSync(req.query.x) is flagged", () => {
  const code = `const buf = fs.readFileSync(req.query.path);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "fs-read-user-input"));
});

test("nodejs-depth: fs.createReadStream(req.params.x) is flagged", () => {
  const code = `const s = fs.createReadStream(req.params.file);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "fs-read-user-input"));
});

// WHY: writes to user-controlled paths can clobber arbitrary files
// (.ssh/authorized_keys, deploy hooks).
test("nodejs-depth: fs.writeFile with req.body.path is flagged", () => {
  const code = `fs.writeFile(req.body.path, data, cb);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "fs-write-user-path"));
});

test("nodejs-depth: fs.appendFile with req.query.path is flagged", () => {
  const code = `fs.appendFile(req.query.target, '\\n', cb);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "fs-write-user-path"));
});

// WHY: NEGATIVE — execFile with a fixed binary and an argv array is the
// recommended safe pattern; must not trip the child-process rule.
test("nodejs-depth: child_process.execFile('git', [a,b]) is NOT flagged", () => {
  const code = `child_process.execFile('git', [arg1, arg2], cb);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "child-process-user-input"));
});

// WHY: NEGATIVE — fs.readFile with a constant base + static name is safe; no
// request input flows in.
test("nodejs-depth: fs.readFile(path.join(SAFE_BASE, 'static.json')) is NOT flagged", () => {
  const code = `fs.readFile(path.join(SAFE_BASE, 'static.json'), 'utf8', cb);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "fs-read-user-input"));
});

// WHY: critical Node rules must really be marked critical so CLI exit codes
// and totals don't silently drift.
test("nodejs-depth: critical-severity Node rules really are critical", () => {
  const ids = [
    "node-vm-runincontext-user",
    "node-tls-reject-env-zero",
    "node-runtime-npm-install-user",
    "node-worker-eval-true",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: nodejs rules (by id-prefix node-*) should carry confidence in the
// documented 50-100 band — one rule sits at 50 (JSON.parse low-confidence).
// Filtering by category alone misses node- rules tagged dangerous-function,
// weak-crypto, insecure-protocol, etc.
test("nodejs-depth: node-* rules carry sensible confidence values", () => {
  const nodeRules = CODE_RULES.filter((r) => r.id.startsWith("node-"));
  assert.ok(nodeRules.length >= 10, `expected >=10 node- rules, got ${nodeRules.length}`);
  for (const r of nodeRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: every node- rule should carry an OWASP A0X:202Y tag, used by SARIF /
// JUnit exports. Defends against an accidental tag-strip during refactor.
test("nodejs-depth: node-* rules have OWASP A0X:202Y tags", () => {
  const nodeRules = CODE_RULES.filter((r) => r.id.startsWith("node-"));
  for (const r of nodeRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{2}:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});
