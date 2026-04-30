import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("trpc: flags publicProcedure mutation against user table", () => {
  const code = `export const userRouter = createTRPCRouter({
  remove: publicProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    await db.user.delete({ where: { id: input.id } });
  }),
});`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-public-mutation-user-table"));
});

test("trpc: flags mutation with no preceding .input()", () => {
  const code = `const r = procedure.mutation(async ({ input }) => { return doStuff(input); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-mutation-no-input"));
});

test("trpc: flags legacy t.procedure usage", () => {
  const code = `export const getThing = t.procedure.query(({ ctx }) => ctx.db.thing.findMany());`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-legacy-t-procedure"));
});

test("trpc: flags publicProcedure delete mutation", () => {
  const code = `export const r = publicProcedure.mutation(async ({ input }) => { await db.deleteUser(input.id); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-publicprocedure-delete"));
});

test("trpc: flags input.userId trusted from caller", () => {
  const code = `const r = procedure.mutation(async ({ input }) => { await db.posts.create({ data: { userId: input.userId } }); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-ctx-user-id-trusted-from-input"));
});

test("trpc: flags z.any input schema", () => {
  const code = `procedure.input(z.any()).mutation(({ input }) => doStuff(input));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-superjson-no-transformer-input"));
});

test("trpc: flags raw Error thrown in resolver", () => {
  const code = `procedure.mutation(async () => { throw new Error("nope"); });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "trpc-throw-no-trpc-error"));
});

test("trpc: does NOT flag protectedProcedure usage", () => {
  const code = `export const getMe = protectedProcedure.query(({ ctx }) => ctx.session.user);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "trpc-legacy-t-procedure"));
});
