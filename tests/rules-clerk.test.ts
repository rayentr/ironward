import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("clerk: flags publicRoutes containing /api/admin", () => {
  const code = `clerkMiddleware({ publicRoutes: ["/api/admin/users"] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-public-routes-admin"));
});

test("clerk: flags publicRoutes containing /api/payment", () => {
  const code = `authMiddleware({ publicRoutes: ["/api/payment/charge"] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-public-routes-payment"));
});

test("clerk: flags publicRoutes containing /api/billing", () => {
  const code = `clerkMiddleware({ publicRoutes: ["/api/billing"] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-public-routes-billing"));
});

test("clerk: flags webhook handler missing svix verify", () => {
  const code = `
    // webhook
    export async function POST(req) {
      const body = await req.json();
      await processEvent(body);
      return new Response("ok");
    }
  `;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-webhook-no-svix-verify"));
});

test("clerk: flags currentUser() result not checked", () => {
  const code = `const data = await currentUser();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-currentuser-result-unchecked"));
});

test("clerk: flags auth() destructured userId without check", () => {
  const code = `const { userId } = await auth();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "clerk-auth-await-no-check"));
});

test("clerk: does NOT flag publicRoutes with safe path", () => {
  const code = `clerkMiddleware({ publicRoutes: ["/sign-in"] });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-admin"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-payment"));
  assert.ok(!f.some((x) => x.ruleId === "clerk-public-routes-billing"));
});
