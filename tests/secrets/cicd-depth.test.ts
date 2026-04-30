import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

// Synthetic CI/CD tokens. Hex values use varied alphabets to dodge the
// placeholder filter (6+ identical chars).
const HEX_40 = "0123456789abcdef0123456789abcdef01234567"; // 40 hex
const HEX_32 = "0123456789abcdef0123456789abcdef"; // 32 hex
const UUID = "01234567-89ab-cdef-0123-456789abcdef";

const CIRCLECI_USER = HEX_40;
const BUILDKITE = "bkua_" + HEX_40;
const CODECOV = UUID; // 36 chars including dashes
const TRAVIS = "aBcDeFgHiJkLmNoPqRsTuV"; // 22 chars
const JENKINS = HEX_32;
const SONAR_PROJECT = "sqp_" + HEX_40;
const SONAR_USER = "sqa_" + HEX_40;
const SONAR_GLOBAL = "sqb_" + HEX_40;
const SNYK = UUID;

// ============================================================
// circleci_user_token
// ============================================================

// WHY: contextual circleci_token = '40-hex' is the canonical form.
test("circleci_user_token: basic detection", async () => {
  const f = await findFor(`circleci_token = '${CIRCLECI_USER}'`, "circleci_user_token");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property nesting is common in CI helper modules.
test("circleci_user_token: object property", async () => {
  const f = await findFor(`const cfg = { circleci_token: '${CIRCLECI_USER}' };`, "circleci_user_token");
  assert.ok(f);
});

// WHY: kebab-case variant must also fire.
test("circleci_user_token: kebab-case", async () => {
  const f = await findFor(`circleci-token = '${CIRCLECI_USER}'`, "circleci_user_token");
  assert.ok(f);
});

// WHY: env reference is the safe pattern.
test("circleci_user_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.CIRCLECI_TOKEN;`, "circleci_user_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("circleci_user_token: placeholder NOT flagged", async () => {
  const f = await findFor(`circleci_token = 'YOUR_CIRCLECI_TOKEN_PLACEHOLDER_X'`, "circleci_user_token");
  assert.equal(f, undefined);
});

// ============================================================
// buildkite_token (bkua_ + 40 hex)
// ============================================================

// WHY: bkua_ prefix is canonical Buildkite API token format.
test("buildkite_token: basic detection", async () => {
  const f = await findFor(`const tok = '${BUILDKITE}';`, "buildkite_token");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: token nested in object property.
test("buildkite_token: object property", async () => {
  const f = await findFor(`const cfg = { buildkite: { token: '${BUILDKITE}' } };`, "buildkite_token");
  assert.ok(f);
});

// WHY: token in template literal — Authorization header.
test("buildkite_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + BUILDKITE + "`;", "buildkite_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("buildkite_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.BUILDKITE_TOKEN;`, "buildkite_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("buildkite_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'bkua_YOUR_BUILDKITE_TOKEN_PLACEHOLDR';`, "buildkite_token");
  assert.equal(f, undefined);
});

// ============================================================
// codecov_token (UUID)
// ============================================================

// WHY: contextual codecov_token = 'uuid' shape.
test("codecov_token: basic detection", async () => {
  const f = await findFor(`codecov_token = '${CODECOV}'`, "codecov_token");
  assert.ok(f);
  assert.equal(f.severity, "medium");
});

// WHY: object property variant.
test("codecov_token: object property", async () => {
  const f = await findFor(`const cfg = { codecov_token: '${CODECOV}' };`, "codecov_token");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("codecov_token: kebab-case", async () => {
  const f = await findFor(`codecov-token = '${CODECOV}'`, "codecov_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("codecov_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.CODECOV_TOKEN;`, "codecov_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("codecov_token: placeholder NOT flagged", async () => {
  const f = await findFor(`codecov_token = 'YOUR_CODECOV_TOKEN_PLACEHOLDER_X'`, "codecov_token");
  assert.equal(f, undefined);
});

// ============================================================
// travis_token (22 chars, contextual)
// ============================================================

// WHY: contextual travis_token = '22-char' shape.
test("travis_token: basic detection", async () => {
  const f = await findFor(`travis_token = '${TRAVIS}'`, "travis_token");
  assert.ok(f);
});

// WHY: travis_ci_token alias variant.
test("travis_token: ci alias", async () => {
  const f = await findFor(`travis_ci_token = '${TRAVIS}'`, "travis_token");
  assert.ok(f);
});

// WHY: object property variant.
test("travis_token: object property", async () => {
  const f = await findFor(`const cfg = { travis_token: '${TRAVIS}' };`, "travis_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("travis_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.TRAVIS_TOKEN;`, "travis_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("travis_token: placeholder NOT flagged", async () => {
  const f = await findFor(`travis_token = 'YOUR_TRAVIS_TOKEN_PLACR'`, "travis_token");
  assert.equal(f, undefined);
});

// ============================================================
// jenkins_api_token (32+ hex, contextual)
// ============================================================

// WHY: contextual jenkins_api_token = '32-hex' shape.
test("jenkins_api_token: basic detection", async () => {
  const f = await findFor(`jenkins_api_token = '${JENKINS}'`, "jenkins_api_token");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

// WHY: object property variant.
test("jenkins_api_token: object property", async () => {
  const f = await findFor(`const cfg = { jenkins_api_token: '${JENKINS}' };`, "jenkins_api_token");
  assert.ok(f);
});

// WHY: kebab-case variant.
test("jenkins_api_token: kebab-case", async () => {
  const f = await findFor(`jenkins-api-token = '${JENKINS}'`, "jenkins_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("jenkins_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.JENKINS_API_TOKEN;`, "jenkins_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("jenkins_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`jenkins_api_token = 'YOUR_JENKINS_API_TOKEN_PLACEHOLDR_X'`, "jenkins_api_token");
  assert.equal(f, undefined);
});

// ============================================================
// sonar_token (sqp_ + 40 hex)
// ============================================================

// WHY: sqp_ project token format is canonical.
test("sonar_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SONAR_PROJECT}';`, "sonar_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token nested in CI config object.
test("sonar_token: object property", async () => {
  const f = await findFor(`const cfg = { sonarToken: '${SONAR_PROJECT}' };`, "sonar_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("sonar_token: template literal", async () => {
  const f = await findFor("const a = `-Dsonar.login=" + SONAR_PROJECT + "`;", "sonar_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("sonar_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SONAR_TOKEN;`, "sonar_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("sonar_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'sqp_YOUR_SONARQUBE_TOKEN_PLACEHOLDR';`, "sonar_token");
  assert.equal(f, undefined);
});

// ============================================================
// sonar_user_token (sqa_ + 40 hex)
// ============================================================

// WHY: sqa_ user token format is canonical.
test("sonar_user_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SONAR_USER}';`, "sonar_user_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("sonar_user_token: object property", async () => {
  const f = await findFor(`const cfg = { sonarUserToken: '${SONAR_USER}' };`, "sonar_user_token");
  assert.ok(f);
});

// WHY: token in Authorization template literal.
test("sonar_user_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + SONAR_USER + "`;", "sonar_user_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("sonar_user_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SONAR_USER_TOKEN;`, "sonar_user_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("sonar_user_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'sqa_YOUR_SONARQUBE_USER_TOKEN_PLACE';`, "sonar_user_token");
  assert.equal(f, undefined);
});

// ============================================================
// sonar_global_token (sqb_ + 40 hex)
// ============================================================

// WHY: sqb_ global token grants org-wide access — canonical detection.
test("sonar_global_token: basic detection", async () => {
  const f = await findFor(`const tok = '${SONAR_GLOBAL}';`, "sonar_global_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("sonar_global_token: object property", async () => {
  const f = await findFor(`const cfg = { sonarGlobalToken: '${SONAR_GLOBAL}' };`, "sonar_global_token");
  assert.ok(f);
});

// WHY: token in template literal.
test("sonar_global_token: template literal", async () => {
  const f = await findFor("const a = `Authorization: Bearer " + SONAR_GLOBAL + "`;", "sonar_global_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("sonar_global_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SONAR_GLOBAL_TOKEN;`, "sonar_global_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("sonar_global_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const tok = 'sqb_YOUR_SONARQUBE_GLOBAL_TOKEN_X';`, "sonar_global_token");
  assert.equal(f, undefined);
});

// ============================================================
// snyk_api_token (UUID, contextual)
// ============================================================

// WHY: contextual snyk_api_token = 'uuid' shape.
test("snyk_api_token: basic detection", async () => {
  const f = await findFor(`snyk_api_token = '${SNYK}'`, "snyk_api_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: snyk_token alias.
test("snyk_api_token: snyk_token alias", async () => {
  const f = await findFor(`snyk_token = '${SNYK}'`, "snyk_api_token");
  assert.ok(f);
});

// WHY: object property variant.
test("snyk_api_token: object property", async () => {
  const f = await findFor(`const cfg = { snyk_api_token: '${SNYK}' };`, "snyk_api_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("snyk_api_token: env reference NOT flagged", async () => {
  const f = await findFor(`const tok = process.env.SNYK_TOKEN;`, "snyk_api_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("snyk_api_token: placeholder NOT flagged", async () => {
  const f = await findFor(`snyk_api_token = 'YOUR_SNYK_API_TOKEN_PLACEHOLDR_X'`, "snyk_api_token");
  assert.equal(f, undefined);
});
