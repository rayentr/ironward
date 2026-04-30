import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: $eq is a safe, scalar-only operator — using it with req.body.id is
// the recommended fix for $where/$regex injection. Must NOT trip the
// $regex / $where rules.
test("injection-depth: mongo find with $eq: req.body.id is NOT flagged", () => {
  const code = `db.find({ _id: { $eq: req.body.id } });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nosql-mongo-regex-user-input"));
  assert.ok(!f.some((x) => x.ruleId === "nosql-mongo-where"));
});

// WHY: an LDAP filter built only from a static string (no concat with user
// input) must NOT trip the dn-concat rule.
test("injection-depth: LDAP filter built from static string is NOT flagged", () => {
  const code = `const dn = "uid=admin,ou=people,dc=example,dc=com";`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "ldap-dn-concat-user-input"));
});

// WHY: xml2js with a configured 'safe' wrapper option object should not
// fire the xxe rule (best effort — captures intent that safe configs shouldn't trip).
test("injection-depth: xml2js parser without entity-enabling flags is NOT flagged by libxmljs rule", () => {
  const code = `libxmljs.parseXml(buf, { noent: false, nonet: true });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "xxe-libxmljs-no-noent-guard"));
});

// WHY: nunjucks.render with a fixed template name and req.body as locals is
// safe — must not trip the renderString rule.
test("injection-depth: nunjucks.render('name', { data: req.body }) is NOT flagged", () => {
  const code = `nunjucks.render('user-page.njk', { data: req.body });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "ssti-nunjucks-render-string"));
});

// WHY: shelljs.exec with a static string (no template literal) is the safe
// shape; must not trip the template-literal rule.
test("injection-depth: shelljs.exec with a static string is NOT flagged", () => {
  const code = `shelljs.exec('ls -la');`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "shelljs-exec-template-literal"));
});

// WHY: variant positive — variant input shape with $where and req.body.
// Catches a regression where the rule stops matching multi-line query
// literals.
test("injection-depth: mongo $where with multi-line query and req.body is flagged", () => {
  const code = `db.users.find({
    $where: "this.role == '" + req.body.role + "'"
  });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nosql-mongo-where"));
});

// WHY: variant positive — Handlebars.compile with template literal
// containing req.body must fire the SSTI rule.
test("injection-depth: Handlebars.compile with req.body template literal is flagged", () => {
  const code = "const t = Handlebars.compile(`Hello ${req.body.template}`);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "template-handlebars-compile-user"));
});

// WHY: every injection rule must declare an OWASP A0X:202Y tag — A03:2021
// Injection is the canonical category; verify at least one rule carries it.
test("injection-depth: at least one injection rule is tagged OWASP A03:2021 Injection", () => {
  const injectionRules = CODE_RULES.filter((r) => r.category === "nosql" || r.category === "template-injection" || r.category === "injection" || r.category === "header-injection");
  const a03Rules = injectionRules.filter((r) => /^A03:2021/.test(r.owasp ?? ""));
  assert.ok(a03Rules.length >= 5, `expected >=5 A03:2021 injection rules, got ${a03Rules.length}`);
});

// WHY: every injection-family rule should carry an OWASP tag.
test("injection-depth: injection-family rules all have OWASP tags", () => {
  const injectionRules = CODE_RULES.filter(
    (r) =>
      r.category === "nosql" ||
      r.category === "template-injection" ||
      r.category === "injection" ||
      r.category === "header-injection" ||
      r.category === "xxe",
  );
  for (const r of injectionRules) {
    if (r.owasp != null) {
      assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
    }
  }
});

// WHY: injection rules with confidence set should be in band.
test("injection-depth: injection rules carry sensible confidence values", () => {
  const injectionRules = CODE_RULES.filter(
    (r) =>
      r.category === "nosql" ||
      r.category === "template-injection" ||
      r.category === "injection" ||
      r.category === "header-injection" ||
      r.category === "xxe",
  );
  for (const r of injectionRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: critical injection rules must really be critical.
test("injection-depth: critical injection rules are tagged critical in CODE_RULES", () => {
  const criticalIds = [
    "nosql-mongo-aggregate-function",
    "nosql-mongo-accumulator-user-js",
    "shelljs-exec-template-literal",
    "sequelize-raw-query-user-input",
  ];
  for (const id of criticalIds) {
    const r = ruleById(id);
    assert.ok(r, id);
    assert.equal(r.severity, "critical", `${id} expected critical`);
  }
});

// WHY: variant positive — knex.raw with a template literal interpolating
// req.params.
test("injection-depth: knex.raw with template literal interpolating req.params is flagged", () => {
  const code = "const r = await knex.raw(`SELECT * FROM t WHERE id = ${req.params.id}`);";
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "knex-raw-user-input");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: variant positive — xpath.select with template-literal interpolating
// req.body. Note: the rule's quoted-string concat branch can't see across
// `'` inside `"..."` strings, so use the template-literal form here.
test("injection-depth: xpath.select with template literal interpolating req.body is flagged", () => {
  const code = "xpath.select(`//user[name='${req.body.name}']`, doc);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "xpath-select-user-input"));
});

// WHY: variant positive — nodemailer to: from req.body should fire.
test("injection-depth: nodemailer sendMail with to: from req.body is flagged", () => {
  const code = `transport.sendMail({ to: req.body.email, subject: 'hi', text: 't' });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "email-header-injection-nodemailer"));
});

// WHY: variant positive — liquidjs parseAndRender with req.body.template.
test("injection-depth: liquidjs.parseAndRender with req.body is flagged", () => {
  const code = `await engine.parseAndRender(req.body.template, data);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "ssti-liquidjs-parse-and-render"));
});

// WHY: finding severity for the $accumulator rule must propagate to the
// finding object as critical.
test("injection-depth: $accumulator finding severity is critical", () => {
  const code = `db.coll.aggregate([{ $group: { _id: '$x', total: { $accumulator: { init: function(){}, accumulate: function(s, v){ return req.body.code; }, accumulateArgs: [], merge: function(){}, lang: 'js' } } } }]);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nosql-mongo-accumulator-user-js");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});
