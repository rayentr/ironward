import { test } from "node:test";
import assert from "node:assert/strict";
import { PRISMA_ADVANCED_RULES } from "../src/rules/prisma-advanced.ts";

function findingsFor(code: string, ruleId: string): Array<{ index: number }> {
  const rule = PRISMA_ADVANCED_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  const out: Array<{ index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    out.push({ index: m.index });
    if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
  }
  return out;
}

const ruleById = (id: string) => PRISMA_ADVANCED_RULES.find((r) => r.id === id);

// =============== prisma-deletemany-no-where ===============

// WHY: deleteMany() with no args wipes the entire table — must always fire.
test("prisma-deletemany-no-where: deleteMany() is flagged", () => {
  const code = `await prisma.user.deleteMany();`;
  assert.ok(findingsFor(code, "prisma-deletemany-no-where").length >= 1);
});

// WHY: deleteMany with an explicit where is safe.
test("prisma-deletemany-no-where: deleteMany({ where: { id } }) is NOT flagged", () => {
  const code = `await prisma.user.deleteMany({ where: { id: 1 } });`;
  assert.equal(findingsFor(code, "prisma-deletemany-no-where").length, 0);
});

// WHY: severity + owasp lock-in for the destructive deleteMany rule.
test("prisma-deletemany-no-where: metadata is critical + A01", () => {
  const r = ruleById("prisma-deletemany-no-where")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A01:2021 Broken Access Control");
});

// =============== prisma-updatemany-no-where ===============

// WHY: updateMany with data and no where rewrites every row.
test("prisma-updatemany-no-where: updateMany({ data }) is flagged", () => {
  const code = `await prisma.user.updateMany({ data: { role: 'admin' } });`;
  assert.ok(findingsFor(code, "prisma-updatemany-no-where").length >= 1);
});

// WHY: updateMany with where clause is safe; negativePattern must suppress.
test("prisma-updatemany-no-where: updateMany with where is NOT flagged", () => {
  const code = `await prisma.user.updateMany({ where: { id: 1 }, data: { role: 'admin' } });`;
  assert.equal(findingsFor(code, "prisma-updatemany-no-where").length, 0);
});

// WHY: severity + owasp for updateMany.
test("prisma-updatemany-no-where: metadata is critical + A01", () => {
  const r = ruleById("prisma-updatemany-no-where")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A01:2021 Broken Access Control");
});

// =============== prisma-nested-connect-user-input ===============

// WHY: connect: { id: req.body.userId } is the IDOR-via-relation shape.
test("prisma-nested-connect-user-input: connect { id: req.body.x } is flagged", () => {
  const code = `await prisma.post.create({ data: { title: 't', author: { connect: { id: req.body.userId } } } });`;
  assert.ok(findingsFor(code, "prisma-nested-connect-user-input").length >= 1);
});

// WHY: connect with a server-controlled session id is the safe pattern.
test("prisma-nested-connect-user-input: connect { id: session.userId } is NOT flagged", () => {
  const code = `await prisma.post.create({ data: { title: 't', author: { connect: { id: session.userId } } } });`;
  assert.equal(findingsFor(code, "prisma-nested-connect-user-input").length, 0);
});

// WHY: severity + owasp for IDOR-via-connect.
test("prisma-nested-connect-user-input: metadata is high + A01", () => {
  const r = ruleById("prisma-nested-connect-user-input")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A01:2021 Broken Access Control");
});

// =============== prisma-select-password ===============

// WHY: select: { password: true } pulls the hash into memory and often into JSON.
test("prisma-select-password: select { password: true } is flagged", () => {
  const code = `const u = await prisma.user.findUnique({ where: { id }, select: { id: true, password: true } });`;
  assert.ok(findingsFor(code, "prisma-select-password").length >= 1);
});

// WHY: a select that omits password is safe.
test("prisma-select-password: select without password is NOT flagged", () => {
  const code = `const u = await prisma.user.findUnique({ where: { id }, select: { id: true, email: true } });`;
  assert.equal(findingsFor(code, "prisma-select-password").length, 0);
});

// WHY: severity + owasp for password select.
test("prisma-select-password: metadata is high + A03", () => {
  const r = ruleById("prisma-select-password")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A03:2021 Sensitive Data Exposure");
});

// =============== prisma-include-password ===============

// WHY: include: { password: true } on a related record exposes the hash.
test("prisma-include-password: include { password: true } is flagged", () => {
  const code = `const p = await prisma.profile.findUnique({ where: { id }, include: { user: true, password: true } });`;
  assert.ok(findingsFor(code, "prisma-include-password").length >= 1);
});

// WHY: include with only safe relations is fine.
test("prisma-include-password: include without password is NOT flagged", () => {
  const code = `const p = await prisma.profile.findUnique({ where: { id }, include: { user: true, posts: true } });`;
  assert.equal(findingsFor(code, "prisma-include-password").length, 0);
});

// WHY: severity + owasp for password include.
test("prisma-include-password: metadata is high + A03", () => {
  const r = ruleById("prisma-include-password")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A03:2021 Sensitive Data Exposure");
});

// prisma-findmany-no-take lives in src/rules/prisma.ts (deduped during 3.0.0 wiring).
// Tests for that rule are in tests/rules-prisma-depth.test.ts.
