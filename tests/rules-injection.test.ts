import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("injection: flags mongo $regex with request input", () => {
  const code = `await db.find({ name: { $regex: req.body.search } });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nosql-mongo-regex-user-input"));
});

test("injection: flags mongo $function with request input", () => {
  const code = `db.aggregate([{ $function: { body: req.body.fn, args: [], lang: "js" } }]);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nosql-mongo-aggregate-function"));
});

test("injection: flags ldap DN built by concat with user input", () => {
  const code = `const dn = "uid=" + username + ",ou=people";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "ldap-dn-concat-user-input"));
});

test("injection: flags nunjucks renderString with request input", () => {
  const code = `nunjucks.renderString(req.body.template, data);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "ssti-nunjucks-render-string"));
});

test("injection: flags ejs.render with request input as template source", () => {
  const code = `ejs.render(req.body.tpl, data);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "ssti-ejs-render-user-source"));
});

test("injection: flags fast-xml-parser without entity guard", () => {
  const code = `const parser = new XMLParser({ allowBooleanAttributes: true });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "xxe-fast-xml-parser-no-entity-guard"));
});

test("injection: flags shelljs.exec with template literal", () => {
  const code = "shelljs.exec(`ls ${userPath}`);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "shelljs-exec-template-literal"));
});

test("injection: flags sequelize.query with template literal interpolating req", () => {
  const code = "await sequelize.query(`SELECT * FROM users WHERE id = ${req.body.id}`);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "sequelize-raw-query-user-input"));
});

test("injection: does NOT flag mongo $regex with constant string", () => {
  const code = `await db.find({ name: { $regex: "^foo$" } });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nosql-mongo-regex-user-input"));
});

test("injection: does NOT flag fast-xml-parser with processEntities false", () => {
  const code = `const parser = new XMLParser({ allowBooleanAttributes: true, processEntities: false });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "xxe-fast-xml-parser-no-entity-guard"));
});
