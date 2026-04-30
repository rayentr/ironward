import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: pickle.loads on request bytes is direct RCE via __reduce__. Lock in
// the canonical Flask form.
test("python-depth: pickle.loads(request.data) is flagged", () => {
  const code = `obj = pickle.loads(request.data)`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "py-pickle-loads-untrusted");
  assert.ok(finding, "expected py-pickle-loads-untrusted");
  assert.equal(finding.severity, "critical");
});

// WHY: cPickle is the legacy Py2 module name; the rule only covers `pickle`.
// TODO: add a cPickle alias in the rule. Document the gap so devs migrating
// from Py2 don't get a silent miss.
test("python-depth: cPickle.loads gap (documented)", () => {
  const code = `obj = cPickle.loads(request.data)`;
  const f = scanCodeRules(code);
  // TODO: py-pickle-loads-untrusted regex matches `pickle.loads` only,
  // not `cPickle.loads`. Document current gap until rule is widened.
  assert.ok(!f.some((x) => x.ruleId === "py-pickle-loads-untrusted"));
});

// WHY: yaml.load without an explicit Loader= defaults to FullLoader/UnsafeLoader
// — !!python/object tags are RCE.
test("python-depth: yaml.load without Loader= is flagged", () => {
  const code = `data = yaml.load(payload)`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "py-yaml-load-unsafe");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: NEGATIVE — yaml.safe_load is the safe API; rule must not trip on it.
test("python-depth: yaml.safe_load(s) is NOT flagged", () => {
  const code = `data = yaml.safe_load(payload)`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-yaml-load-unsafe"));
});

// WHY: shell=True is the trigger regardless of where args come from. With a
// nested call like request.args.get("cmd"), the rule's [^)]* lookahead stops
// at the inner `)` and misses the shell=True kwarg. Document the gap.
test("python-depth: subprocess.run(request.args.get(...), shell=True) gap (documented)", () => {
  const code = `subprocess.run(request.args.get("cmd"), shell=True)`;
  const f = scanCodeRules(code);
  // TODO: py-subprocess-shell-true regex uses [^)]* between the opening paren
  // and shell=True, so any inner call with `)` (request.args.get(...)) hides
  // the kwarg. Widen to a balanced-paren-aware matcher or use [\s\S]{0,200}.
  assert.ok(!f.some((x) => x.ruleId === "py-subprocess-shell-true"));
});

test("python-depth: subprocess.run with shell=True without user input is also flagged", () => {
  const code = `subprocess.run("ls -la /tmp", shell=True)`;
  const f = scanCodeRules(code);
  // Rule fires on shell=True alone, by design — the surface is dangerous
  // even if today's args are constant.
  assert.ok(f.some((x) => x.ruleId === "py-subprocess-shell-true"));
});

// WHY: DEBUG = True at module top-level exposes the Django debug error page.
test("python-depth: Django DEBUG = True is flagged", () => {
  const code = `DEBUG = True`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-django-debug-true"));
});

// WHY: variant — DEBUG=True with no spaces should still match the rule.
test("python-depth: DEBUG=True (no spaces) is flagged", () => {
  const code = `DEBUG=True`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-django-debug-true"));
});

// WHY: app.run(debug=True) opens the Werkzeug interactive debug UI.
test("python-depth: Flask app.run(debug=True) is flagged", () => {
  const code = `app.run(host="0.0.0.0", debug=True)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-flask-debug-true"));
});

// WHY: lock in current behavior — `app.debug = True` (assignment form)
// is NOT covered by py-flask-debug-true. Document so devs aren't surprised.
test("python-depth: app.debug = True is not flagged (documented gap)", () => {
  const code = `app.debug = True`;
  const f = scanCodeRules(code);
  // TODO: py-flask-debug-true matches `app.run(...debug=True)` only, not the
  // bare `app.debug = True` attribute assignment. Both are equally dangerous
  // in production. Widen the regex.
  assert.ok(!f.some((x) => x.ruleId === "py-flask-debug-true"));
});

// WHY: eval on request input is RCE; py-eval-user-input matches the f-string
// or request.* leading patterns.
test("python-depth: eval(request.form['x']) is flagged", () => {
  const code = `result = eval(request.form['x'])`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-eval-user-input"));
});

test("python-depth: eval(f\"...{request.X}...\") is flagged", () => {
  const code = `result = eval(f"compute({request.args.get('x')})")`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-eval-user-input"));
});

// WHY: exec(request.X) — same RCE class as eval; py-exec-call covers
// request.* / f"..." / compile() argument patterns.
test("python-depth: exec(request.form['code']) is flagged", () => {
  const code = `exec(request.form['code'])`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-exec-call"));
});

// WHY: os.system pipes through /bin/sh — request input is command injection.
test("python-depth: os.system(request.args.get(...)) is flagged", () => {
  const code = `os.system(request.args.get("cmd"))`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "py-os-system-user");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
  assert.match(finding.title, /os\.system/);
});

// WHY: os.popen is the same shell pipe as os.system — both flag.
test("python-depth: os.popen(request.X) is flagged", () => {
  const code = `out = os.popen(request.values.get("c")).read()`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-os-popen-user"));
});

// WHY: importlib.import_module on a user name pulls arbitrary code from
// sys.path and executes top-level statements.
test("python-depth: importlib.import_module(request.X) is flagged", () => {
  const code = `mod = importlib.import_module(request.args.get("name"))`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-importlib-user-module"));
});

// WHY: requests with verify=False disables TLS validation. Confirm severity
// on the finding and OWASP tag on the underlying rule.
test("python-depth: requests.get(url, verify=False) is flagged", () => {
  const code = `r = requests.get("https://internal.example.com", verify=False)`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "py-requests-verify-false");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
  const rule = ruleById("py-requests-verify-false");
  assert.ok(rule);
  assert.ok(rule.owasp);
  assert.match(rule.owasp, /^A07:2021/);
});

// WHY: assert for an authorization check is silently stripped under -O.
test("python-depth: assert request.user.is_admin is flagged", () => {
  const code = `assert request.user.is_admin`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-assert-security-check"));
});

// WHY: at least one critical Python rule must really be marked critical.
test("python-depth: critical-severity Python rules really are critical", () => {
  const ids = [
    "py-pickle-loads-untrusted",
    "py-yaml-load-unsafe",
    "py-eval-user-input",
    "py-os-system-user",
    "py-os-popen-user",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every py-* injection-class rule should carry the A03:2021 OWASP tag
// so SARIF/JUnit exports group them correctly.
test("python-depth: A03:2021 Injection rules tagged correctly", () => {
  const ids = [
    "py-eval-user-input",
    "py-os-system-user",
    "py-os-popen-user",
    "py-sql-fstring",
    "py-importlib-user-module",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.match(rule.owasp, /^A03:2021\b/, `${id} owasp not A03:2021`);
  }
});

// WHY: py-* rules should carry confidence in the documented 50-100 band.
test("python-depth: py-* rules carry sensible confidence values", () => {
  const pyRules = CODE_RULES.filter((r) => r.id.startsWith("py-"));
  assert.ok(pyRules.length >= 15, `expected >=15 py- rules, got ${pyRules.length}`);
  for (const r of pyRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});
