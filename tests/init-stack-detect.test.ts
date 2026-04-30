import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectStack, buildInitialConfig, detectedRuleCategories } from "../src/integrations/project-config.ts";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "iw-init-stack-"));
}

test("init-stack: package.json with @supabase/supabase-js → hasSupabase", async () => {
  // WHY: the highest-stakes integration. Auto-enabling supabase rules saves manual config.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }));
    const s = await detectStack(d);
    assert.equal(s.hasSupabase, true);
    assert.equal(s.hasPackageJson, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: package.json with stripe → hasStripe", async () => {
  // WHY: payment security is a top concern; missing this detection means missed default rules.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies: { stripe: "^14" } }));
    const s = await detectStack(d);
    assert.equal(s.hasStripe, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: @clerk/nextjs in devDependencies → hasClerk (covers all dep sections)", async () => {
  // WHY: dependencies can live in dev/optional/peer too — the detector must check all of them.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ devDependencies: { "@clerk/nextjs": "^4" } }));
    const s = await detectStack(d);
    assert.equal(s.hasClerk, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: @prisma/client → hasPrisma", async () => {
  // WHY: Prisma raw query rules are critical and stack-specific.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies: { "@prisma/client": "^5" } }));
    const s = await detectStack(d);
    assert.equal(s.hasPrisma, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: @trpc/server → hasTrpc", async () => {
  // WHY: tRPC publicProcedure misuse is a common access-control bug — must auto-enable.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies: { "@trpc/server": "^10" } }));
    const s = await detectStack(d);
    assert.equal(s.hasTrpc, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: firebase-admin → hasFirebase", async () => {
  // WHY: firebase-admin in client code is a critical leak — must trigger firebase rules.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies: { "firebase-admin": "^12" } }));
    const s = await detectStack(d);
    assert.equal(s.hasFirebase, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: go.mod present → hasGoMod", async () => {
  // WHY: go.mod is the canonical Go project marker.
  const d = await tmp();
  try {
    await writeFile(join(d, "go.mod"), "module x\n\ngo 1.22\n");
    const s = await detectStack(d);
    assert.equal(s.hasGoMod, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: requirements.txt → hasRequirementsTxt + hasPythonSources", async () => {
  // WHY: a manifest is enough to mark this as a Python project.
  const d = await tmp();
  try {
    await writeFile(join(d, "requirements.txt"), "flask==2.0.0\n");
    const s = await detectStack(d);
    assert.equal(s.hasRequirementsTxt, true);
    assert.equal(s.hasPythonSources, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: pyproject.toml also marks Python project", async () => {
  // WHY: modern Python projects use pyproject.toml — must not require requirements.txt.
  const d = await tmp();
  try {
    await writeFile(join(d, "pyproject.toml"), "[project]\nname='x'\n");
    const s = await detectStack(d);
    assert.equal(s.hasPythonSources, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: .java file in src tree → hasJavaSources", async () => {
  // WHY: Java is detected by file extension, not by build manifest (Maven/Gradle vary).
  const d = await tmp();
  try {
    await mkdir(join(d, "src"), { recursive: true });
    await writeFile(join(d, "src", "Foo.java"), "class Foo {}\n");
    const s = await detectStack(d);
    assert.equal(s.hasJavaSources, true);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: combined stack — Next.js + Supabase + Stripe + Prisma + Docker", async () => {
  // WHY: realistic SaaS stack. All categories should be detected together.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), JSON.stringify({
      dependencies: { "@supabase/supabase-js": "^2", stripe: "^14", "@prisma/client": "^5", next: "^14" },
    }));
    await writeFile(join(d, "Dockerfile"), "FROM node:20\n");
    await writeFile(join(d, "next.config.js"), "module.exports = {};\n");
    const s = await detectStack(d);
    assert.equal(s.hasNextJs, true);
    assert.equal(s.hasSupabase, true);
    assert.equal(s.hasStripe, true);
    assert.equal(s.hasPrisma, true);
    assert.equal(s.hasDockerfile, true);
    const cats = detectedRuleCategories(s);
    assert.ok(cats.includes("nextjs"));
    assert.ok(cats.includes("supabase"));
    assert.ok(cats.includes("stripe"));
    assert.ok(cats.includes("prisma-drizzle"));
    assert.ok(cats.includes("react"));
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: empty directory → no specific stack, defaults are sane", async () => {
  // WHY: a fresh project shouldn't crash; the resulting config should still be a valid baseline.
  const d = await tmp();
  try {
    const s = await detectStack(d);
    assert.equal(s.hasPackageJson, false);
    const cfg = buildInitialConfig(s);
    assert.ok(cfg.enabledScanners?.includes("secrets"));
    assert.ok(cfg.enabledScanners?.includes("code"));
    // No deps scanner (no manifest), no docker, no infra
    assert.ok(!cfg.enabledScanners?.includes("deps"));
    assert.ok(!cfg.enabledScanners?.includes("docker"));
    // No rule categories detected → field is omitted (or empty)
    assert.ok(!cfg.rules?.enabledCategories || cfg.rules.enabledCategories.length === 0);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: malformed package.json doesn't crash detectStack", async () => {
  // WHY: hardened input — corrupt manifests in the wild shouldn't blow up the init flow.
  const d = await tmp();
  try {
    await writeFile(join(d, "package.json"), "{ this is not json");
    const s = await detectStack(d);
    assert.equal(s.hasPackageJson, true);
    // npm-driven flags should be false (no parseable deps)
    assert.equal(s.hasSupabase, false);
    assert.equal(s.hasStripe, false);
  } finally { await rm(d, { recursive: true, force: true }); }
});

test("init-stack: detectedRuleCategories deduplicates", async () => {
  // WHY: hasNextJs adds both 'nextjs' and 'react' — the function should never return dupes
  // even when called with overlapping signals.
  const cats = detectedRuleCategories({
    hasNextJs: true, hasDockerfile: false, hasTerraform: false, hasGithubActions: false,
    hasPackageJson: true, hasPipfile: false, hasRequirementsTxt: false, hasGoMod: false,
    hasJavaSources: false, hasPythonSources: false,
    hasSupabase: false, hasStripe: false, hasClerk: false, hasPrisma: false, hasTrpc: false, hasFirebase: false,
  });
  const unique = new Set(cats);
  assert.equal(cats.length, unique.size, `expected no duplicates in ${cats.join(",")}`);
});
