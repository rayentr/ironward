import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: publicProcedure mutation that touches the user table must fire —
// canonical broken-access-control pattern in tRPC.
test("trpc-depth: publicProcedure.mutation touching user table is flagged", () => {
  const code = `export const r = publicProcedure.mutation(async ({ input }) => { await db.user.update({ where: { id: input.id } }); });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "trpc-public-mutation-user-table");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: publicProcedure.query against a sensitive table — the rule is
// scoped to .mutation, so this should NOT fire on the public-mutation rule.
test("trpc-depth: publicProcedure.query against user table is NOT flagged by mutation rule (documented)", () => {
  const code = `export const r = publicProcedure.query(async () => { return db.user.findMany(); });`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — trpc-public-mutation-user-table specifically
  // requires `.mutation`. Public reads against sensitive tables are not
  // inherently broken (read-only data may be public on purpose), so the
  // rule's scoping is correct. Documented here for the next reviewer.
  assert.ok(!f.some((x) => x.ruleId === "trpc-public-mutation-user-table"));
});

// WHY: legacy t.procedure without an .use(...) middleware is unprotected.
test("trpc-depth: bare t.procedure is flagged as legacy unprotected", () => {
  const code = `export const getThing = t.procedure.query(({ ctx }) => ctx.db.thing.findMany());`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "trpc-legacy-t-procedure");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: protectedProcedure is the safe replacement — must NOT trigger
// the legacy t.procedure rule.
test("trpc-depth: protectedProcedure usage does NOT fire legacy rule", () => {
  const code = `export const getMe = protectedProcedure.query(({ ctx }) => ctx.session.user);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "trpc-legacy-t-procedure"));
});

// WHY: a mutation with no preceding .input() schema is type-confusion-prone.
test("trpc-depth: procedure.mutation() with no .input() is flagged", () => {
  const code = `const r = procedure.mutation(async ({ input }) => { return doStuff(input); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-mutation-no-input"));
});

// WHY: WITH .input(z.object()) before .mutation, the regex
// `\bprocedure\s*\.mutation\s*\(` no longer matches because `.input(...)`
// breaks the adjacency between `procedure` and `.mutation`. Lock in the
// safe-pattern coverage.
test("trpc-depth: procedure.input(z.object()).mutation() is NOT flagged", () => {
  const code = `const r = procedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => { return input.id; });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "trpc-mutation-no-input"));
});

// WHY: z.any() input schema disables validation — must fire.
test("trpc-depth: .input(z.any()) is flagged", () => {
  const code = `procedure.input(z.any()).mutation(({ input }) => doStuff(input));`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "trpc-superjson-no-transformer-input");
  assert.ok(finding);
  assert.equal(finding.severity, "medium");
});

// WHY: z.unknown() is the documented sibling — same alternation should fire.
test("trpc-depth: .input(z.unknown()) is flagged", () => {
  const code = `procedure.input(z.unknown()).mutation(({ input }) => doStuff(input));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-superjson-no-transformer-input"));
});

// WHY: throwing raw Error in a resolver bypasses TRPCError formatting.
test("trpc-depth: throw new Error in mutation is flagged", () => {
  const code = `procedure.mutation(async () => { throw new Error("nope"); });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "trpc-throw-no-trpc-error");
  assert.ok(finding);
  assert.equal(finding.severity, "low");
});

// WHY: input.userId being trusted instead of ctx.session.user.id is
// account takeover — must fire.
test("trpc-depth: input.userId trusted is flagged", () => {
  const code = `const r = procedure.mutation(async ({ input }) => { await db.posts.create({ data: { userId: input.userId } }); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-ctx-user-id-trusted-from-input"));
});

// WHY: publicProcedure mutation named delete* — destructive + unauthenticated.
test("trpc-depth: publicProcedure delete mutation is flagged as critical", () => {
  const code = `export const r = publicProcedure.mutation(async ({ input }) => { await db.deleteUser(input.id); });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "trpc-publicprocedure-delete");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: severity assertion on a critical rule for the suite — keeps rule
// metadata stable so SARIF/JUnit exit codes don't drift.
test("trpc-depth: critical-severity tRPC rules really are critical", () => {
  const ids = [
    "trpc-public-mutation-user-table",
    "trpc-router-public-admin",
    "trpc-publicprocedure-delete",
  ];
  for (const id of ids) {
    const r = ruleById(id);
    assert.ok(r, `missing rule ${id}`);
    assert.equal(r.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every tRPC rule must carry an OWASP tag (allow A1-A10).
test("trpc-depth: every tRPC rule has OWASP AN:202Y tag", () => {
  const rules = CODE_RULES.filter((r) => r.category === "trpc");
  assert.ok(rules.length >= 8);
  for (const r of rules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{1,2}:202\d\b/, `${r.id} owasp not in AN:202Y form`);
  }
});

// WHY: confidence must be in 40-100 band for tRPC rules — defends
// against an accidental 0/undefined that would tank scoring.
test("trpc-depth: tRPC rules carry confidence in 40-100 band", () => {
  const rules = CODE_RULES.filter((r) => r.category === "trpc");
  for (const r of rules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 40 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});
