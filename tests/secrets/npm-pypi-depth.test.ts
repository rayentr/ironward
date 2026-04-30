import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const NPM = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"; // npm_ + 36
const PYPI = "pypi-AgEIcHlwaS5vcmc" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ012aBcDe"; // 70 chars after prefix
const RUBYGEMS = "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef"; // rubygems_ + 48 hex
const DOCKERHUB = "dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwXyZ0";  // dckr_pat_ + 27
const NUGET = "oy2abcdefghijklmnopqrstuvwxyz0123456789abcdefg";  // oy2 + 43 lowercase alnum

// ============================================================
// npm_token (npm_ + 36)
// ============================================================

// WHY: npm_ prefix is canonical npm classic auth token.
test("npm_token: basic detection", async () => {
  const f = await findFor(`const k = '${NPM}';`, "npm_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("npm_token: object property", async () => {
  const f = await findFor(`const cfg = { npm: { token: '${NPM}' } };`, "npm_token");
  assert.ok(f);
});

// WHY: token in template literal — Authorization header.
test("npm_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + NPM + "`;", "npm_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("npm_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.NPM_TOKEN;`, "npm_token");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("npm_token: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'npm_YOUR_NPM_AUTH_TOKEN_PLACEHOLDR_X1';`, "npm_token");
  assert.equal(f, undefined);
});

// ============================================================
// pypi_token (pypi-AgEIcHlwaS5vcmc + 70+)
// ============================================================

// WHY: pypi-AgEIcHlwaS5vcmc prefix is canonical PyPI API token.
test("pypi_token: basic detection", async () => {
  const f = await findFor(`const k = '${PYPI}';`, "pypi_token");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: token in object property.
test("pypi_token: object property", async () => {
  const f = await findFor(`const cfg = { pypi: { token: '${PYPI}' } };`, "pypi_token");
  assert.ok(f);
});

// WHY: token in template literal — pip publish flow.
test("pypi_token: template literal", async () => {
  const f = await findFor("const a = `Bearer " + PYPI + "`;", "pypi_token");
  assert.ok(f);
});

// WHY: env reference safe.
test("pypi_token: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.PYPI_TOKEN;`, "pypi_token");
  assert.equal(f, undefined);
});

// WHY: TWINE_PASSWORD env name (PyPI conventional) safe.
test("pypi_token: TWINE_PASSWORD env NOT flagged", async () => {
  const f = await findFor(`const k = process.env.TWINE_PASSWORD;`, "pypi_token");
  assert.equal(f, undefined);
});

// ============================================================
// rubygems_key (rubygems_ + 48 hex)
// ============================================================

// WHY: rubygems_ prefix is canonical RubyGems API key.
test("rubygems_key: basic detection", async () => {
  const f = await findFor(`const k = '${RUBYGEMS}';`, "rubygems_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("rubygems_key: object property", async () => {
  const f = await findFor(`const cfg = { rubygems: { key: '${RUBYGEMS}' } };`, "rubygems_key");
  assert.ok(f);
});

// WHY: in template literal.
test("rubygems_key: template literal", async () => {
  const f = await findFor("const a = `Authorization: " + RUBYGEMS + "`;", "rubygems_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("rubygems_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.RUBYGEMS_API_KEY;`, "rubygems_key");
  assert.equal(f, undefined);
});

// WHY: GEM_HOST_API_KEY env name safe.
test("rubygems_key: GEM_HOST_API_KEY env NOT flagged", async () => {
  const f = await findFor(`const k = process.env.GEM_HOST_API_KEY;`, "rubygems_key");
  assert.equal(f, undefined);
});

// ============================================================
// dockerhub_pat (dckr_pat_ + 27+)
// ============================================================

// WHY: dckr_pat_ prefix is canonical Docker Hub PAT.
test("dockerhub_pat: basic detection", async () => {
  const f = await findFor(`const k = '${DOCKERHUB}';`, "dockerhub_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("dockerhub_pat: object property", async () => {
  const f = await findFor(`const cfg = { dockerhub: { token: '${DOCKERHUB}' } };`, "dockerhub_pat");
  assert.ok(f);
});

// WHY: in docker login template literal.
test("dockerhub_pat: docker login template", async () => {
  const f = await findFor("const cmd = `docker login -u user -p " + DOCKERHUB + "`;", "dockerhub_pat");
  assert.ok(f);
});

// WHY: env reference safe.
test("dockerhub_pat: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DOCKERHUB_TOKEN;`, "dockerhub_pat");
  assert.equal(f, undefined);
});

// WHY: DOCKER_PASSWORD env name safe.
test("dockerhub_pat: DOCKER_PASSWORD env NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DOCKER_PASSWORD;`, "dockerhub_pat");
  assert.equal(f, undefined);
});

// ============================================================
// nuget_api_key (oy2 + 43)
// ============================================================

// WHY: oy2 prefix is canonical NuGet API key.
test("nuget_api_key: basic detection", async () => {
  const f = await findFor(`const k = '${NUGET}';`, "nuget_api_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: in object property.
test("nuget_api_key: object property", async () => {
  const f = await findFor(`const cfg = { nuget: { apiKey: '${NUGET}' } };`, "nuget_api_key");
  assert.ok(f);
});

// WHY: in template literal — dotnet nuget push.
test("nuget_api_key: template literal", async () => {
  const f = await findFor("const cmd = `dotnet nuget push --api-key " + NUGET + "`;", "nuget_api_key");
  assert.ok(f);
});

// WHY: env reference safe.
test("nuget_api_key: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.NUGET_API_KEY;`, "nuget_api_key");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("nuget_api_key: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'oy2YOURNUGETAPIKEYPLACEHOLDR1234567890abcdefgh';`, "nuget_api_key");
  assert.equal(f, undefined);
});

// ============================================================
// dockerhub_pat — extra coverage shapes
// ============================================================

// WHY: token in Bearer header.
test("dockerhub_pat: bearer header", async () => {
  const f = await findFor("const a = `Bearer " + DOCKERHUB + "`;", "dockerhub_pat");
  assert.ok(f);
});

// WHY: token in CI step env value.
test("dockerhub_pat: env-style value", async () => {
  const f = await findFor(`const yaml = "DOCKERHUB_TOKEN: ${DOCKERHUB}";`, "dockerhub_pat");
  assert.ok(f);
});

// WHY: in JSON config blob.
test("dockerhub_pat: in JSON blob", async () => {
  const f = await findFor(`const cfg = {"auth":{"token":"${DOCKERHUB}"}};`, "dockerhub_pat");
  assert.ok(f);
});

// WHY: env reference for legacy DOCKER_AUTH safe.
test("dockerhub_pat: legacy DOCKER_AUTH env NOT flagged", async () => {
  const f = await findFor(`const k = process.env.DOCKER_AUTH;`, "dockerhub_pat");
  assert.equal(f, undefined);
});

// WHY: placeholder must not fire.
test("dockerhub_pat: placeholder NOT flagged", async () => {
  const f = await findFor(`const k = 'dckr_pat_YOUR_DOCKERHUB_TOKEN_PLACE';`, "dockerhub_pat");
  assert.equal(f, undefined);
});
