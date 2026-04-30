import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("supabase: flags service_role key in NEXT_PUBLIC_ env", () => {
  const code = `
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
  `;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "supabase-service-role-frontend"));
});

test("supabase: flags createClient with service_role", () => {
  const code = `const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "supabase-service-role-client-init"));
});

test("supabase: flags supabase.auth.admin in client", () => {
  const code = `await supabase.auth.admin.deleteUser(userId);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "supabase-auth-admin-client-side"));
});

test("supabase: flags public bucket creation", () => {
  const code = `await supabase.storage.createBucket('photos', { public: true });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "supabase-storage-public-bucket"));
});

test("supabase: flags ALTER TABLE ... DISABLE ROW LEVEL SECURITY", () => {
  const sql = `ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;`;
  const f = scanCodeRules(sql);
  assert.ok(f.some((x) => x.ruleId === "supabase-rls-disabled-statement"));
});

test("supabase: flags RLS policy USING (true)", () => {
  const sql = `CREATE POLICY "all read" ON users FOR SELECT USING (true);`;
  const f = scanCodeRules(sql);
  assert.ok(f.some((x) => x.ruleId === "supabase-rls-policy-using-true"));
});

test("supabase: does NOT flag .from('x').select with .eq filter", () => {
  const code = `await supabase.from('orders').select('*').eq('user_id', userId);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "supabase-select-no-eq-filter"));
});

test("supabase: confidence is set on supabase rules", () => {
  const code = `const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "supabase-service-role-frontend");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});
