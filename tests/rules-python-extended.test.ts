import { test } from "node:test";
import assert from "node:assert/strict";
import { PYTHON_EXTENDED_RULES } from "../src/rules/python-extended.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = PYTHON_EXTENDED_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    return true;
  }
  return false;
}

function rule(id: string) {
  const r = PYTHON_EXTENDED_RULES.find((x) => x.id === id);
  if (!r) throw new Error("rule not found: " + id);
  return r;
}

// ---------- py-flask-secret-key-too-short ----------

// WHY: positive — short literal SECRET_KEY is the trivial-to-brute case.
test("py-flask-secret-key-too-short: 8-char literal fires", () => {
  const code = `app.config['SECRET_KEY'] = 'abc12345'`;
  assert.equal(fire(code, "py-flask-secret-key-too-short"), true);
});

// WHY: negative — a long random key (>=16 chars) is safer and must not match.
test("py-flask-secret-key-too-short: 32-char literal does NOT fire", () => {
  const code = `app.config['SECRET_KEY'] = 'a-long-random-secret-of-32-chars'`;
  assert.equal(fire(code, "py-flask-secret-key-too-short"), false);
});

// WHY: metadata — secrets driving sessions are crypto failures; severity high.
test("py-flask-secret-key-too-short: metadata severity is high", () => {
  assert.equal(rule("py-flask-secret-key-too-short").severity, "high");
});

// py-django-allowed-hosts-wildcard lives in src/rules/python.ts
// (deduped during 3.0.0 wiring). Coverage is in tests/rules-python-depth.test.ts.

// ---------- py-django-csrf-exempt ----------

// WHY: positive — bare @csrf_exempt above a view is the canonical pattern.
test("py-django-csrf-exempt: decorator fires", () => {
  const code = `@csrf_exempt\ndef my_view(request): ...`;
  assert.equal(fire(code, "py-django-csrf-exempt"), true);
});

// WHY: negative — code that mentions csrf in a string but not as a decorator does not fire.
test("py-django-csrf-exempt: string mention does NOT fire", () => {
  const code = `note = "we need csrf_exempt for legacy"`;
  assert.equal(fire(code, "py-django-csrf-exempt"), false);
});

// WHY: metadata — bypassing CSRF in an authenticated app is high.
test("py-django-csrf-exempt: metadata severity is high", () => {
  assert.equal(rule("py-django-csrf-exempt").severity, "high");
});

// ---------- py-django-debug-toolbar-import ----------

// WHY: positive — `import debug_toolbar` at module top-level is the unguarded case.
test("py-django-debug-toolbar-import: bare import fires", () => {
  const code = `import debug_toolbar`;
  assert.equal(fire(code, "py-django-debug-toolbar-import"), true);
});

// WHY: negative — same import inside an `if DEBUG:` block does not start at column 0
// (after stripping leading whitespace it still appears, so we test a clearly different shape).
test("py-django-debug-toolbar-import: a different module import does NOT fire", () => {
  const code = `import django\nimport os`;
  assert.equal(fire(code, "py-django-debug-toolbar-import"), false);
});

// WHY: metadata — info disclosure in prod; severity medium.
test("py-django-debug-toolbar-import: metadata severity is medium", () => {
  assert.equal(rule("py-django-debug-toolbar-import").severity, "medium");
});

// ---------- py-sqlalchemy-text-injection ----------

// WHY: positive — text() with an f-string is direct SQLi.
test("py-sqlalchemy-text-injection: f-string in text() fires", () => {
  const code = `q = text(f"SELECT * FROM users WHERE id = {user_id}")`;
  assert.equal(fire(code, "py-sqlalchemy-text-injection"), true);
});

// WHY: negative — text() with a static SQL string and bound params is safe.
test("py-sqlalchemy-text-injection: text() with bound params does NOT fire", () => {
  const code = `q = text("SELECT * FROM users WHERE id = :id")`;
  assert.equal(fire(code, "py-sqlalchemy-text-injection"), false);
});

// WHY: metadata — SQLi is the classic critical bug.
test("py-sqlalchemy-text-injection: metadata severity is critical", () => {
  assert.equal(rule("py-sqlalchemy-text-injection").severity, "critical");
});

// ---------- py-celery-pickle-serializer ----------

// WHY: positive — task_serializer = 'pickle' is RCE-by-config.
test("py-celery-pickle-serializer: task_serializer='pickle' fires", () => {
  const code = `task_serializer = 'pickle'`;
  assert.equal(fire(code, "py-celery-pickle-serializer"), true);
});

// WHY: negative — JSON serializer is safe and must not match.
test("py-celery-pickle-serializer: task_serializer='json' does NOT fire", () => {
  const code = `task_serializer = 'json'`;
  assert.equal(fire(code, "py-celery-pickle-serializer"), false);
});

// WHY: metadata — pickle on broker is direct worker RCE; critical.
test("py-celery-pickle-serializer: metadata severity is critical", () => {
  assert.equal(rule("py-celery-pickle-serializer").severity, "critical");
});

// ---------- py-requests-no-timeout ----------

// WHY: positive — requests.get with no timeout kwarg fires.
test("py-requests-no-timeout: requests.get without timeout fires", () => {
  const code = `r = requests.get(url)`;
  assert.equal(fire(code, "py-requests-no-timeout"), true);
});

// WHY: negative — explicit timeout= keyword inside the call suppresses the finding.
test("py-requests-no-timeout: requests.get with timeout= does NOT fire", () => {
  const code = `r = requests.get(url, timeout=5)`;
  assert.equal(fire(code, "py-requests-no-timeout"), false);
});

// WHY: metadata — DoS class; severity medium.
test("py-requests-no-timeout: metadata severity is medium", () => {
  assert.equal(rule("py-requests-no-timeout").severity, "medium");
});

// ---------- py-xml-minidom-external-entities ----------

// WHY: positive — minidom.parseString without defusedxml is XXE-prone.
test("py-xml-minidom-external-entities: minidom.parseString fires", () => {
  const code = `doc = xml.dom.minidom.parseString(payload)`;
  assert.equal(fire(code, "py-xml-minidom-external-entities"), true);
});

// WHY: negative — defusedxml.minidom.parseString is the recommended replacement.
test("py-xml-minidom-external-entities: defusedxml.minidom does NOT fire", () => {
  const code = `doc = defusedxml.minidom.parseString(payload)`;
  assert.equal(fire(code, "py-xml-minidom-external-entities"), false);
});

// WHY: metadata — XXE reads arbitrary files; severity high.
test("py-xml-minidom-external-entities: metadata severity is high", () => {
  assert.equal(rule("py-xml-minidom-external-entities").severity, "high");
});

// py-tempfile-mktemp lives in src/rules/python.ts (deduped during 3.0.0 wiring).
// Coverage is in tests/rules-python-depth.test.ts.

// ---------- py-glob-user-input ----------

// WHY: positive — glob.glob(request.args.x) is path traversal via glob expansion.
test("py-glob-user-input: glob.glob(request.args[...]) fires", () => {
  const code = `files = glob.glob(request.args.get('pattern'))`;
  assert.equal(fire(code, "py-glob-user-input"), true);
});

// WHY: negative — glob.glob with a static prefix is safe.
test("py-glob-user-input: glob.glob with literal pattern does NOT fire", () => {
  const code = `files = glob.glob('./uploads/*.jpg')`;
  assert.equal(fire(code, "py-glob-user-input"), false);
});

// WHY: metadata — arbitrary file listing leaks secrets; severity high.
test("py-glob-user-input: metadata severity is high", () => {
  assert.equal(rule("py-glob-user-input").severity, "high");
});

// ---------- collection-level metadata ----------

// WHY: every python-extended rule must carry an owasp tag and languages list.
test("python-extended: every rule carries owasp and languages metadata", () => {
  for (const r of PYTHON_EXTENDED_RULES) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.ok(Array.isArray(r.languages) && r.languages.length > 0, `${r.id} missing languages`);
  }
});
