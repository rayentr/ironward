import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic SCM tokens.
// GH tokens require exactly 36 chars after the prefix; pattern uses \b so extras break it.
const GH_PAT_CLASSIC = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";  // ghp_ + 36
const GH_OAUTH       = "gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";  // gho_ + 36
const GH_USR_TO_SRV  = "ghu_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";  // ghu_ + 36
const GH_SRV_TO_SRV  = "ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";  // ghs_ + 36
const GH_FINE_PAT    = "github_pat_" + "A".repeat(82);                 // 82-char body — won't fire (placeholder)
// Build a varied 82-char body so the placeholder filter doesn't drop it.
const GH_FINE_PAT_VARIED = "github_pat_" +
  "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH2I";  // 82 chars
const GL_PAT         = "glpat-" + "AbCdEfGh1J2K3L4M5N6O";              // glpat- + exactly 20

// ============================================================
// github_pat_classic (ghp_)
// ============================================================

// WHY: basic.
test("github_pat_classic: basic detection", async () => {
  const code = `const tok = '${GH_PAT_CLASSIC}';`;
  const f = await findFor(code, "github_pat_classic");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("github_pat_classic: object property", async () => {
  const code = `const cfg = { github: { token: '${GH_PAT_CLASSIC}' } };`;
  const f = await findFor(code, "github_pat_classic");
  assert.ok(f);
});

// WHY: template literal.
test("github_pat_classic: template literal", async () => {
  const code = "const a = `Bearer " + GH_PAT_CLASSIC + "`;";
  const f = await findFor(code, "github_pat_classic");
  assert.ok(f);
});

// WHY: placeholder.
test("github_pat_classic: placeholder NOT flagged", async () => {
  const code = `const tok = 'ghp_YOUR_GITHUB_PAT_HERE_PLACEHOLDER_VALUE';`;
  const f = await findFor(code, "github_pat_classic");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("github_pat_classic: env reference NOT flagged", async () => {
  const code = `const tok = process.env.GITHUB_PAT;`;
  const f = await findFor(code, "github_pat_classic");
  assert.equal(f, undefined);
});

// ============================================================
// github_oauth (gho_)
// ============================================================

// WHY: basic.
test("github_oauth: basic detection", async () => {
  const code = `const t = '${GH_OAUTH}';`;
  const f = await findFor(code, "github_oauth");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("github_oauth: object property", async () => {
  const code = `const cfg = { github: { oauth: '${GH_OAUTH}' } };`;
  const f = await findFor(code, "github_oauth");
  assert.ok(f);
});

// WHY: template literal.
test("github_oauth: template literal", async () => {
  const code = "const a = `token " + GH_OAUTH + "`;";
  const f = await findFor(code, "github_oauth");
  assert.ok(f);
});

// WHY: placeholder.
test("github_oauth: placeholder NOT flagged", async () => {
  const code = `const t = 'gho_YOUR_OAUTH_TOKEN_HERE_PLACEHOLDER_VALUE';`;
  const f = await findFor(code, "github_oauth");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("github_oauth: env reference NOT flagged", async () => {
  const code = `const t = process.env.GITHUB_OAUTH_TOKEN;`;
  const f = await findFor(code, "github_oauth");
  assert.equal(f, undefined);
});

// ============================================================
// github_user_to_server (ghu_)
// ============================================================

// WHY: basic.
test("github_user_to_server: basic detection", async () => {
  const code = `const t = '${GH_USR_TO_SRV}';`;
  const f = await findFor(code, "github_user_to_server");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("github_user_to_server: object property", async () => {
  const code = `const cfg = { gh: { ghu: '${GH_USR_TO_SRV}' } };`;
  const f = await findFor(code, "github_user_to_server");
  assert.ok(f);
});

// WHY: template literal.
test("github_user_to_server: template literal", async () => {
  const code = "const a = `Bearer " + GH_USR_TO_SRV + "`;";
  const f = await findFor(code, "github_user_to_server");
  assert.ok(f);
});

// WHY: placeholder.
test("github_user_to_server: placeholder NOT flagged", async () => {
  const code = `const t = 'ghu_YOUR_GH_USER_TOKEN_HERE_PLACEHOLDER';`;
  const f = await findFor(code, "github_user_to_server");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("github_user_to_server: env reference NOT flagged", async () => {
  const code = `const t = process.env.GITHUB_USER_TO_SERVER_TOKEN;`;
  const f = await findFor(code, "github_user_to_server");
  assert.equal(f, undefined);
});

// ============================================================
// github_server_to_server (ghs_)
// ============================================================

// WHY: basic.
test("github_server_to_server: basic detection", async () => {
  const code = `const t = '${GH_SRV_TO_SRV}';`;
  const f = await findFor(code, "github_server_to_server");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("github_server_to_server: object property", async () => {
  const code = `const cfg = { gh: { ghs: '${GH_SRV_TO_SRV}' } };`;
  const f = await findFor(code, "github_server_to_server");
  assert.ok(f);
});

// WHY: template literal.
test("github_server_to_server: template literal", async () => {
  const code = "const a = `Bearer " + GH_SRV_TO_SRV + "`;";
  const f = await findFor(code, "github_server_to_server");
  assert.ok(f);
});

// WHY: placeholder.
test("github_server_to_server: placeholder NOT flagged", async () => {
  const code = `const t = 'ghs_YOUR_GH_SERVER_TOKEN_HERE_PLACEHOLDER';`;
  const f = await findFor(code, "github_server_to_server");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("github_server_to_server: env reference NOT flagged", async () => {
  const code = `const t = process.env.GITHUB_SERVER_TO_SERVER_TOKEN;`;
  const f = await findFor(code, "github_server_to_server");
  assert.equal(f, undefined);
});

// ============================================================
// github_fine_grained_pat (github_pat_<82>)
// ============================================================

// WHY: basic.
test("github_fine_grained_pat: basic detection", async () => {
  const code = `const t = '${GH_FINE_PAT_VARIED}';`;
  const f = await findFor(code, "github_fine_grained_pat");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("github_fine_grained_pat: object property", async () => {
  const code = `const cfg = { gh: { fineGrained: '${GH_FINE_PAT_VARIED}' } };`;
  const f = await findFor(code, "github_fine_grained_pat");
  assert.ok(f);
});

// WHY: template literal.
test("github_fine_grained_pat: template literal", async () => {
  const code = "const a = `Bearer " + GH_FINE_PAT_VARIED + "`;";
  const f = await findFor(code, "github_fine_grained_pat");
  assert.ok(f);
});

// WHY: placeholder — engine drops 6+ identical chars (the placeholder heuristic).
test("github_fine_grained_pat: placeholder NOT flagged", async () => {
  const code = `const t = '${GH_FINE_PAT}';`;  // 82 'A's
  const f = await findFor(code, "github_fine_grained_pat");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("github_fine_grained_pat: env reference NOT flagged", async () => {
  const code = `const t = process.env.GITHUB_FINE_GRAINED_PAT;`;
  const f = await findFor(code, "github_fine_grained_pat");
  assert.equal(f, undefined);
});

// ============================================================
// gitlab_pat (glpat-)
// ============================================================

// WHY: basic — glpat- + exactly 20 chars.
test("gitlab_pat: basic detection", async () => {
  const code = `const t = '${GL_PAT}';`;
  const f = await findFor(code, "gitlab_pat");
  assert.ok(f);
  assert.ok(["critical", "high"].includes(f.severity));
});

// WHY: nested object.
test("gitlab_pat: object property", async () => {
  const code = `const cfg = { gitlab: { token: '${GL_PAT}' } };`;
  const f = await findFor(code, "gitlab_pat");
  assert.ok(f);
});

// WHY: template literal.
test("gitlab_pat: template literal", async () => {
  const code = "const a = `Bearer " + GL_PAT + "`;";
  const f = await findFor(code, "gitlab_pat");
  assert.ok(f);
});

// WHY: placeholder.
test("gitlab_pat: placeholder NOT flagged", async () => {
  const code = `const t = 'glpat-YOUR_PLACEHOLDER';`;
  const f = await findFor(code, "gitlab_pat");
  assert.equal(f, undefined);
});

// WHY: env reference.
test("gitlab_pat: env reference NOT flagged", async () => {
  const code = `const t = process.env.GITLAB_PAT;`;
  const f = await findFor(code, "gitlab_pat");
  assert.equal(f, undefined);
});
