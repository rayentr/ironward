import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectDepConfusion,
  parseNpmrc,
  HttpConfusionFetcher,
  KNOWN_SAFE_SCOPES,
  type ConfusionFetcher,
} from "../src/engines/dep-confusion.ts";

function fetcherFromMap(map: Record<string, boolean | null>): ConfusionFetcher {
  return {
    async exists(name: string) {
      return name in map ? map[name] : null;
    },
  };
}

test("flags @company/internal HIGH when not on public npm", async () => {
  const findings = await detectDepConfusion({
    packages: [{ name: "@company/internal", version: "1.0.0", source: "package.json" }],
    fetcher: fetcherFromMap({ "@company/internal": false }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].package, "@company/internal");
  assert.match(findings[0].summary, /dependency confusion/i);
  assert.match(findings[0].evidence ?? "", /\.npmrc/);
});

test("does NOT flag @stripe/stripe-js (KNOWN_SAFE_SCOPES) regardless of fetcher", async () => {
  // Even if the mock fetcher would have flagged it, the safe-scope check skips entirely.
  let called = false;
  const fetcher: ConfusionFetcher = {
    async exists() {
      called = true;
      return false;
    },
  };
  const findings = await detectDepConfusion({
    packages: [{ name: "@stripe/stripe-js", version: "1.0.0", source: "package.json" }],
    fetcher,
  });
  assert.equal(findings.length, 0);
  assert.equal(called, false);
});

test("does NOT flag scope bound by .npmrc", async () => {
  const npmrc = "@company:registry=https://internal.example.com/npm/\n";
  let called = false;
  const fetcher: ConfusionFetcher = {
    async exists() {
      called = true;
      return false;
    },
  };
  const findings = await detectDepConfusion({
    packages: [{ name: "@company/auth", version: "1.0.0", source: "package.json" }],
    npmrc,
    fetcher,
  });
  assert.equal(findings.length, 0);
  assert.equal(called, false);
});

test("flags @company/foo MEDIUM when public npm has a package by that name", async () => {
  const findings = await detectDepConfusion({
    packages: [{ name: "@company/foo", version: "2.3.4", source: "package.json" }],
    fetcher: fetcherFromMap({ "@company/foo": true }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "medium");
  assert.match(findings[0].summary, /also exists on public npm/i);
});

test("never flags unscoped packages", async () => {
  let called = false;
  const fetcher: ConfusionFetcher = {
    async exists() {
      called = true;
      return false;
    },
  };
  const findings = await detectDepConfusion({
    packages: [
      { name: "react", version: "18.2.0", source: "package.json" },
      { name: "lodash", version: "4.17.21", source: "package.json" },
    ],
    fetcher,
  });
  assert.equal(findings.length, 0);
  assert.equal(called, false);
});

test("network error (null) emits no finding", async () => {
  const findings = await detectDepConfusion({
    packages: [{ name: "@company/mystery", version: "1.0.0", source: "package.json" }],
    fetcher: fetcherFromMap({ "@company/mystery": null }),
  });
  assert.equal(findings.length, 0);
});

test("parseNpmrc extracts scopes from a multi-line .npmrc", () => {
  const body = [
    "# private registry config",
    "@company:registry=https://internal.example.com/npm/",
    "@another-org:registry=https://other.example.org/registry/",
    "@MixedCase:registry=https://mc.example.com/",
    "registry=https://registry.npmjs.org/",
    "//internal.example.com/npm/:_authToken=abc",
    "",
    "@empty:registry=", // no url -> should NOT be added
  ].join("\n");
  const parsed = parseNpmrc(body);
  assert.ok(parsed.scopedToPrivateRegistry.has("@company"));
  assert.ok(parsed.scopedToPrivateRegistry.has("@another-org"));
  assert.ok(parsed.scopedToPrivateRegistry.has("@mixedcase"));
  assert.ok(!parsed.scopedToPrivateRegistry.has("@empty"));
  assert.equal(parsed.scopedToPrivateRegistry.size, 3);
});

test("KNOWN_SAFE_SCOPES contains expected entries", () => {
  assert.ok(KNOWN_SAFE_SCOPES.has("@stripe"));
  assert.ok(KNOWN_SAFE_SCOPES.has("@types"));
  assert.ok(KNOWN_SAFE_SCOPES.has("@anthropic"));
  assert.ok(!KNOWN_SAFE_SCOPES.has("@company"));
});

test("HttpConfusionFetcher: 200 -> true", async () => {
  const fakeFetch = (async () => ({ status: 200 })) as unknown as typeof fetch;
  const f = new HttpConfusionFetcher({ fetchImpl: fakeFetch });
  assert.equal(await f.exists("@company/foo"), true);
});

test("HttpConfusionFetcher: 404 -> false", async () => {
  const fakeFetch = (async () => ({ status: 404 })) as unknown as typeof fetch;
  const f = new HttpConfusionFetcher({ fetchImpl: fakeFetch });
  assert.equal(await f.exists("@company/foo"), false);
});

test("HttpConfusionFetcher: thrown error -> null", async () => {
  const fakeFetch = (async () => {
    throw new Error("network down");
  }) as unknown as typeof fetch;
  const f = new HttpConfusionFetcher({ fetchImpl: fakeFetch });
  assert.equal(await f.exists("@company/foo"), null);
});

test("HttpConfusionFetcher: non-200/non-404 status -> null", async () => {
  const fakeFetch = (async () => ({ status: 500 })) as unknown as typeof fetch;
  const f = new HttpConfusionFetcher({ fetchImpl: fakeFetch });
  assert.equal(await f.exists("@company/foo"), null);
});

test("HttpConfusionFetcher: url-encodes the slash for npm registry", async () => {
  let observedUrl = "";
  const fakeFetch = (async (url: string) => {
    observedUrl = String(url);
    return { status: 200 };
  }) as unknown as typeof fetch;
  const f = new HttpConfusionFetcher({ fetchImpl: fakeFetch });
  await f.exists("@company/auth");
  assert.match(observedUrl, /@company%2Fauth$/);
});

test("integration: mixed package set with .npmrc", async () => {
  const npmrc = "@private:registry=https://internal.example.com/npm/";
  const findings = await detectDepConfusion({
    packages: [
      { name: "react", version: "18", source: "package.json" }, // unscoped, skipped
      { name: "@stripe/stripe-js", version: "1", source: "package.json" }, // safe scope
      { name: "@private/foo", version: "1", source: "package.json" }, // npmrc-bound
      { name: "@unknown/bar", version: "1", source: "package.json" }, // 404 -> HIGH
      { name: "@unknown/baz", version: "1", source: "package.json" }, // 200 -> MEDIUM
      { name: "@unknown/err", version: "1", source: "package.json" }, // null -> none
    ],
    npmrc,
    fetcher: fetcherFromMap({
      "@unknown/bar": false,
      "@unknown/baz": true,
      "@unknown/err": null,
    }),
  });
  assert.equal(findings.length, 2);
  const sorted = [...findings].sort((a, b) => a.package.localeCompare(b.package));
  assert.equal(sorted[0].package, "@unknown/bar");
  assert.equal(sorted[0].severity, "high");
  assert.equal(sorted[1].package, "@unknown/baz");
  assert.equal(sorted[1].severity, "medium");
});
