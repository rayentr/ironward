import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("prisma: flags $queryRaw with template interpolation of req data", () => {
  const code = "const rows = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${req.params.id}`;";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-queryraw-template-req"));
});

test("prisma: flags $executeRaw with template interpolation of body", () => {
  const code = "await prisma.$executeRaw`UPDATE users SET name = ${body.name}`;";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-executeraw-template-req"));
});

test("prisma: flags $queryRawUnsafe with user input", () => {
  const code = `const rows = await prisma.$queryRawUnsafe(req.body.sql);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-queryrawunsafe-user-input"));
});

test("prisma: flags $executeRawUnsafe with user input", () => {
  const code = `await prisma.$executeRawUnsafe(req.body.sql);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-executerawunsafe-user-input"));
});

test("prisma: flags update by id with no ownership filter", () => {
  const code = `await prisma.post.update({ where: { id: postId }, data: { title } });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-update-no-ownership"));
});

test("prisma: flags delete by id with no ownership filter", () => {
  const code = `await prisma.post.delete({ where: { id: postId } });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-delete-no-ownership"));
});

test("prisma: flags drizzle sql template with user input", () => {
  const code = "await db.run(sql`SELECT * FROM t WHERE n = ${req.body.name}`);";
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "drizzle-sql-template-user-input"));
});

test("prisma: flags create with spread of req.body (mass assignment)", () => {
  const code = `await prisma.user.create({ data: { ...req.body } });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "prisma-create-spread-body"));
});

test("prisma: does NOT flag $queryRaw with no interpolation", () => {
  const code = "const rows = await prisma.$queryRaw`SELECT count(*) FROM users`;";
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "prisma-queryraw-template-req"));
});

test("prisma: does NOT flag explicit field create (not spread)", () => {
  const code = `await prisma.user.create({ data: { name: req.body.name, userId: session.user.id } });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "prisma-create-spread-body"));
});
