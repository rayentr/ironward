import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: db.Query with string concatenation is direct SQL injection — the
// driver only binds placeholders, not concatenated string segments.
test("go-depth: db.Query with string concat is flagged", () => {
  const code = `rows, err := db.Query("SELECT * FROM users WHERE id = " + userVar)`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "go-sql-string-concat");
  assert.ok(finding, "expected go-sql-string-concat");
  assert.equal(finding.severity, "critical");
});

// WHY: db.Query with fmt.Sprintf — same injection class.
test("go-depth: db.Query with fmt.Sprintf is flagged", () => {
  const code = `rows, err := db.Query(fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", userVar))`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "go-sql-sprintf");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: lock in current behavior — db.QueryRow with the same patterns also
// fires the same rules (regex covers QueryRow / Exec / *Context).
test("go-depth: db.QueryRow with concat is flagged", () => {
  const code = `row := db.QueryRow("SELECT name FROM t WHERE id = " + idArg)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-sql-string-concat"));
});

test("go-depth: db.Exec with fmt.Sprintf is flagged", () => {
  const code = `_, err := db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %d", idArg))`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-sql-sprintf"));
});

// WHY: http.Redirect with target from query string is open redirect — the
// crafted phishing link uses your domain.
test("go-depth: http.Redirect to r.URL.Query().Get(\"x\") is flagged", () => {
  const code = `http.Redirect(w, r, r.URL.Query().Get("next"), 302)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-http-redirect-user"));
});

// WHY: os.Open with a request value is path traversal.
test("go-depth: os.Open(r.URL.Query().Get(...)) is flagged", () => {
  const code = `f, err := os.Open(r.URL.Query().Get("path"))`;
  const f2 = scanCodeRules(code);
  assert.ok(f2.some((x) => x.ruleId === "go-os-open-user"));
});

// WHY: os.OpenFile with r.FormValue is the same path-traversal class.
test("go-depth: os.OpenFile(r.FormValue(...), ...) is flagged", () => {
  const code = `f, err := os.OpenFile(r.FormValue("p"), os.O_RDONLY, 0)`;
  const f2 = scanCodeRules(code);
  assert.ok(f2.some((x) => x.ruleId === "go-os-open-user"));
});

// WHY: ioutil.ReadFile reads arbitrary file contents — same risk.
test("go-depth: ioutil.ReadFile(r.URL.Query().Get(...)) is flagged", () => {
  const code = `bs, err := ioutil.ReadFile(r.URL.Query().Get("p"))`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-ioutil-readfile-user"));
});

// WHY: exec.Command with user input as the executable lets the request pick
// any binary on PATH.
test("go-depth: exec.Command(r.URL.Query().Get(...)) is flagged", () => {
  const code = `cmd := exec.Command(r.URL.Query().Get("bin"), "--help")`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "go-exec-command-user");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: exec.Command("sh", "-c", userInput) is shell injection regardless of
// what the user value is — the surface is dangerous.
test("go-depth: exec.Command(\"sh\", \"-c\", userInput) is flagged", () => {
  const code = `cmd := exec.Command("sh", "-c", userInput)`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "go-exec-command-shell-c");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: template.HTML(userInput) bypasses the html/template auto-escape — XSS.
test("go-depth: template.HTML(userInput) is flagged", () => {
  const code = `out := template.HTML(userInput)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-template-html-bypass"));
});

// WHY: tls.Config{InsecureSkipVerify: true} disables cert validation.
test("go-depth: tls.Config{InsecureSkipVerify: true} is flagged", () => {
  const code = `cfg := &tls.Config{InsecureSkipVerify: true}`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "go-tls-insecure-skip-verify");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
  assert.match(finding.title, /InsecureSkipVerify/);
});

// WHY: bcrypt cost below 10 is brute-forceable on modern GPUs.
test("go-depth: bcrypt.GenerateFromPassword(pw, 4) is flagged", () => {
  const code = `hash, err := bcrypt.GenerateFromPassword(pw, 4)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "go-bcrypt-low-cost"));
});

// WHY: NEGATIVE — parameterized db.Query with a $1 placeholder must NOT
// flag either of the SQL rules.
test("go-depth: parameterized db.Query with $1 is NOT flagged", () => {
  const code = `rows, err := db.Query("SELECT * FROM t WHERE id = $1", id)`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "go-sql-string-concat"));
  assert.ok(!f.some((x) => x.ruleId === "go-sql-sprintf"));
});

// WHY: NEGATIVE — InsecureSkipVerify: false is the safe value; rule must not
// trip on it.
test("go-depth: tls.Config{InsecureSkipVerify: false} is NOT flagged", () => {
  const code = `cfg := &tls.Config{InsecureSkipVerify: false}`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "go-tls-insecure-skip-verify"));
});

// WHY: critical-severity Go rules really must be critical for exit-code math.
test("go-depth: critical-severity Go rules really are critical", () => {
  const ids = [
    "go-sql-sprintf",
    "go-sql-string-concat",
    "go-exec-command-user",
    "go-exec-command-shell-c",
    "go-jwt-hardcoded-key",
    "go-gorm-raw-concat",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every Go rule should carry languages=['go'] and an OWASP A0X:202Y tag.
test("go-depth: go-* rules carry languages=['go'] and OWASP tags", () => {
  const goRules = CODE_RULES.filter((r) => r.id.startsWith("go-"));
  assert.ok(goRules.length >= 15, `expected >=15 go- rules, got ${goRules.length}`);
  for (const r of goRules) {
    assert.ok(r.languages?.includes("go"), `${r.id} missing language tag`);
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{2}:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});

// WHY: every go-sql-* and go-exec-* rule should be A03:2021 Injection — used
// by SARIF taxonomy mapping.
test("go-depth: go-sql / go-exec / go-gorm rules are A03:2021 Injection", () => {
  const ids = [
    "go-sql-sprintf",
    "go-sql-string-concat",
    "go-exec-command-user",
    "go-exec-command-shell-c",
    "go-gorm-raw-concat",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.match(rule.owasp, /^A03:2021\b/, `${id} owasp not A03:2021`);
  }
});

// WHY: go-* rules should carry confidence in the documented 50-100 band.
test("go-depth: go-* rules carry sensible confidence values", () => {
  const goRules = CODE_RULES.filter((r) => r.id.startsWith("go-"));
  for (const r of goRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});
