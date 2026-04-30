import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: NEXT_PUBLIC_API_URL is just a URL — non-secret and a typical
// configuration. Must NOT trip the api-key / secret rules.
test("nextjs-depth: NEXT_PUBLIC_API_URL is NOT flagged", () => {
  const code = `const url = process.env.NEXT_PUBLIC_API_URL;`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-api-key-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-secret-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-private-env"));
});

// WHY: Google Analytics measurement ID is meant to be public. Must NOT
// fire any of the secret-leak rules.
test("nextjs-depth: NEXT_PUBLIC_GA_MEASUREMENT_ID is NOT flagged", () => {
  const code = `const id = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-api-key-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-secret-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-private-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-password-env"));
});

// WHY: Sentry DSN is documented as safe-to-expose. Must NOT fire.
test("nextjs-depth: NEXT_PUBLIC_SENTRY_DSN is NOT flagged", () => {
  const code = `const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-api-key-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-secret-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-private-env"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-public-password-env"));
});

// WHY: NEXT_PUBLIC_PASSWORD must always fire — names matter.
test("nextjs-depth: NEXT_PUBLIC_PASSWORD is flagged", () => {
  const code = `const p = process.env.NEXT_PUBLIC_PASSWORD;`; // ironward-ignore
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nextjs-public-password-env");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: NEXT_PUBLIC_PRIVATE_KEY contradicts itself; must fire the
// public-private rule.
test("nextjs-depth: NEXT_PUBLIC_PRIVATE_KEY is flagged", () => {
  const code = `const k = process.env.NEXT_PUBLIC_PRIVATE_KEY;`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nextjs-public-private-env");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: 'use server' Server Action with auth() inside should NOT trip the
// no-auth rule.
test("nextjs-depth: Server Action with auth() inside is NOT flagged", () => {
  const code = `'use server'
export async function deletePost(id) {
  const session = await auth();
  if (!session) throw new Error('unauthorized');
  await db.posts.delete({ where: { id } });
}`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-server-action-no-auth"));
});

// WHY: 'use server' without any auth call must fire.
test("nextjs-depth: Server Action with no auth call is flagged", () => {
  const code = `'use server'
export async function deleteAll() {
  await db.posts.deleteMany({});
}`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nextjs-server-action-no-auth");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
});

// WHY: API route handler with getServerSession at the top should NOT fire
// the no-auth rules.
test("nextjs-depth: App Router GET with getServerSession is NOT flagged", () => {
  const code = `export async function GET(req) {
  const session = await getServerSession();
  if (!session) return new Response('unauthorized', { status: 401 });
  return Response.json({ ok: true });
}`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-app-route-get-no-auth"));
});

// WHY: API route handler that throws on bad input but never authenticates
// should fire the no-auth rule (validation is not authentication).
test("nextjs-depth: App Router POST that validates input but never auth-checks is flagged", () => {
  const code = `export async function POST(req) {
  const body = await req.json();
  if (!body.id) throw new Error('missing id');
  await db.notes.delete({ where: { id: body.id } });
  return Response.json({ ok: true });
}`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "nextjs-app-route-post-no-auth"));
});

// WHY: dangerouslySetInnerHTML with a constant string is safe; must NOT
// fire either of the dangerouslySetInnerHTML rules.
test("nextjs-depth: dangerouslySetInnerHTML with a constant string is NOT flagged", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: '<b>Hello</b>' }} />`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-req"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-search-params"));
});

// WHY: dangerouslySetInnerHTML wrapping DOMPurify.sanitize is the
// recommended fix; must NOT fire.
test("nextjs-depth: dangerouslySetInnerHTML with DOMPurify.sanitize is NOT flagged", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(maybeHtml) }} />`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-req"));
  assert.ok(!f.some((x) => x.ruleId === "nextjs-dangerously-set-inner-html-search-params"));
});

// WHY: dangerouslySetInnerHTML with req.body.html directly must fire.
test("nextjs-depth: dangerouslySetInnerHTML with req.body.html is flagged", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: req.body.html }} />`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nextjs-dangerously-set-inner-html-req");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: critical nextjs rules must really be tagged critical.
test("nextjs-depth: critical-severity nextjs rules carry that severity in CODE_RULES", () => {
  const ids = [
    "nextjs-public-secret-env",
    "nextjs-public-api-key-env",
    "nextjs-public-private-env",
    "nextjs-public-password-env",
    "nextjs-public-database-url",
    "nextjs-public-stripe-secret",
    "nextjs-dangerously-set-inner-html-req",
    "nextjs-edge-leak-process-env",
    "nextjs-getserversideprops-leak-env",
  ];
  for (const id of ids) {
    const r = ruleById(id);
    assert.ok(r, id);
    assert.equal(r.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every nextjs rule should declare a confidence in band.
test("nextjs-depth: nextjs rules carry sensible confidence values", () => {
  const nextjsRules = CODE_RULES.filter((r) => r.category === "nextjs");
  assert.ok(nextjsRules.length >= 20);
  for (const r of nextjsRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: every nextjs rule must have an OWASP A0X:202Y tag.
test("nextjs-depth: nextjs rules have OWASP A0X:202Y tags", () => {
  const nextjsRules = CODE_RULES.filter((r) => r.category === "nextjs");
  for (const r of nextjsRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});

// WHY: variant positive — NEXT_PUBLIC_STRIPE_SECRET_KEY contains the
// stripe-secret-leaking pattern; must fire the dedicated nextjs rule.
test("nextjs-depth: NEXT_PUBLIC_STRIPE_SECRET_KEY is flagged", () => {
  const code = `const s = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "nextjs-public-stripe-secret");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: revalidatePath called with a string literal (no req. / params.) must
// NOT fire.
test("nextjs-depth: revalidatePath with a string literal is NOT flagged", () => {
  const code = `revalidatePath('/dashboard');`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "nextjs-revalidate-path-user-input"));
});
