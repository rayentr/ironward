import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: prevent regression where the service-role rule only catches NEXT_PUBLIC_
// prefix and silently misses Vite-bundled variant.
test("supabase-depth: VITE_SUPABASE_SERVICE_ROLE variant is flagged", () => {
  const code = `const k = process.env.VITE_SUPABASE_SERVICE_ROLE_KEY;`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "supabase-service-role-frontend");
  assert.ok(finding, "expected supabase-service-role-frontend on VITE_ variant");
  assert.equal(finding.severity, "critical");
});

// WHY: catch-all for Create-React-App's REACT_APP_ prefix; keep it in the same
// rule as NEXT_PUBLIC_ / VITE_.
test("supabase-depth: REACT_APP_SUPABASE_SERVICE_ROLE variant is flagged", () => {
  const code = `const k = process.env.REACT_APP_SUPABASE_SERVICE_ROLE_KEY;`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "supabase-service-role-frontend");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: createClient detection should fire even when service_role is read from
// a non-prefixed env name — the issue is the second arg, not the env name.
test("supabase-depth: createClient with SERVICE_ROLE_KEY env is flagged", () => {
  const code = `const supabase = createClient(url, process.env.SERVICE_ROLE_KEY);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "supabase-service-role-client-init");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: a properly-scoped RLS policy (USING auth.uid() = user_id) must NOT
// trip the using-true rule. Regression here would be very noisy.
test("supabase-depth: USING (auth.uid() = user_id) is NOT flagged", () => {
  const sql = `CREATE POLICY "owner read" ON notes FOR SELECT USING (auth.uid() = user_id);`;
  const f = scanCodeRules(sql);
  assert.ok(!f.some((x) => x.ruleId === "supabase-rls-policy-using-true"));
});

// WHY: same protection for WITH CHECK with an ownership predicate. Common
// safe pattern for INSERT/UPDATE policies.
test("supabase-depth: WITH CHECK (auth.uid() = user_id) is NOT flagged", () => {
  const sql = `CREATE POLICY "owner write" ON notes FOR INSERT WITH CHECK (auth.uid() = user_id);`;
  const f = scanCodeRules(sql);
  assert.ok(!f.some((x) => x.ruleId === "supabase-rls-policy-with-check-true"));
});

// WHY: ENABLE is the opposite of DISABLE — must not match the disable rule.
test("supabase-depth: ALTER TABLE ... ENABLE ROW LEVEL SECURITY is NOT flagged", () => {
  const sql = `ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;`;
  const f = scanCodeRules(sql);
  assert.ok(!f.some((x) => x.ruleId === "supabase-rls-disabled-statement"));
});

// WHY: documents actual behavior — comment-only mention of the dangerous
// statement does flag (the regex is line-agnostic). Useful so devs aren't
// surprised by an SQL comment trigger.
test("supabase-depth: SQL line comment containing the dangerous statement is NOT flagged", () => {
  // WHY: regression test for the v2.7.0 fix — the rule now requires ALTER to start the line
  // (after optional whitespace), so `-- ALTER TABLE ... DISABLE ROW LEVEL SECURITY` won't fire.
  const sql = `-- ALTER TABLE public.users DISABLE ROW LEVEL SECURITY (do not do this)`;
  const f = scanCodeRules(sql);
  assert.ok(!f.some((x) => x.ruleId === "supabase-rls-disabled-statement"),
    `expected NOT to flag SQL comment; got: ${f.map((x) => x.ruleId).join(", ")}`);
});

test("supabase-depth: actual ALTER TABLE ... DISABLE ROW LEVEL SECURITY at start-of-line is flagged", () => {
  // WHY: lock in that the v2.7.0 anchor change didn't accidentally turn off real detection.
  const sql = `ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;`;
  const f = scanCodeRules(sql);
  assert.ok(f.some((x) => x.ruleId === "supabase-rls-disabled-statement"));
});

// WHY: a fully-chained safe select with an .eq filter must not appear in
// findings, even when other rules run alongside it.
test("supabase-depth: .from('orders').select('*').eq(...) is NOT flagged by select-no-eq-filter", () => {
  const code = `await supabase.from('orders').select('*').eq('user_id', userId);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "supabase-select-no-eq-filter"));
});

// WHY: every supabase critical rule must carry severity=critical so the CLI
// totals and exit codes don't silently drift to "high".
test("supabase-depth: critical-severity rules really are critical in CODE_RULES", () => {
  const ids = [
    "supabase-service-role-frontend",
    "supabase-service-role-client-init",
    "supabase-auth-admin-client-side",
    "supabase-rls-disabled-statement",
    "supabase-rls-policy-using-true",
    "supabase-rls-policy-with-check-true",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: confidence scores on supabase rules should be in the documented
// 60-100 band; defending against an accidental 0 or undefined.
test("supabase-depth: supabase rules carry sensible confidence values", () => {
  const supabaseRules = CODE_RULES.filter((r) => r.category === "supabase");
  assert.ok(supabaseRules.length >= 10);
  for (const r of supabaseRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 60 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});

// WHY: OWASP tag must be on every supabase rule and look like A0X:202Y.
test("supabase-depth: supabase rules have OWASP A0X:202Y tags", () => {
  const supabaseRules = CODE_RULES.filter((r) => r.category === "supabase");
  for (const r of supabaseRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});

// WHY: variant positive — service_role embedded in object-literal init style.
test("supabase-depth: createClient called with service_role inside an options object is flagged", () => {
  const code = `const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "supabase-service-role-client-init");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: lower-case service_role spelled inline (not env var) should also fire.
test("supabase-depth: createClient with literal 'service_role' label still fires", () => {
  const code = `const supabase = createClient(url, service_role);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "supabase-service-role-client-init"));
});

// WHY: USING with a non-trivial predicate (e.g. role check) should not match
// the using-true rule.
test("supabase-depth: USING (auth.role() = 'authenticated') is NOT flagged", () => {
  const sql = `CREATE POLICY "auth read" ON notes FOR SELECT USING (auth.role() = 'authenticated');`;
  const f = scanCodeRules(sql);
  assert.ok(!f.some((x) => x.ruleId === "supabase-rls-policy-using-true"));
});
