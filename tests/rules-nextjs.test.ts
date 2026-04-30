import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("nextjs: flags NEXT_PUBLIC_SECRET env var", () => {
  const code = `const s = process.env.NEXT_PUBLIC_SECRET;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-public-secret-env"));
});

test("nextjs: flags NEXT_PUBLIC_API_KEY env var", () => {
  const code = `const k = process.env.NEXT_PUBLIC_API_KEY;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-public-api-key-env"));
});

test("nextjs: flags NEXT_PUBLIC_DATABASE_URL", () => {
  const code = `const url = process.env.NEXT_PUBLIC_DATABASE_URL;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-public-database-url"));
});

test("nextjs: flags NEXT_PUBLIC_PRIVATE_TOKEN", () => {
  const code = `const t = process.env.NEXT_PUBLIC_PRIVATE_TOKEN;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-public-private-env"));
});

test("nextjs: flags dangerouslySetInnerHTML with searchParams", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: searchParams.q }} />`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-search-params"));
});

test("nextjs: flags dangerouslySetInnerHTML with req data", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: req.body.html }} />`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-req"));
});

test("nextjs: flags 'use server' action without auth", () => {
  const code = `'use server'
export async function deletePost(id) {
  await db.posts.delete({ where: { id } });
}`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-server-action-no-auth"));
});

test("nextjs: flags NextResponse.json leaking process.env", () => {
  const code = `return NextResponse.json({ key: process.env.SECRET_KEY });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-edge-leak-process-env"));
});

test("nextjs: does NOT flag a normal NEXT_PUBLIC_API_URL var", () => {
  const code = `const url = process.env.NEXT_PUBLIC_API_URL;`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-api-key-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-secret-env"));
});

test("nextjs: does NOT flag dangerouslySetInnerHTML with static content", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: trustedStaticHtml }} />`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-req"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-search-params"));
});
