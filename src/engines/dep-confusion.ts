import type { DepIntelFinding } from "./dep-intel.js";

// ──────────────────────────────────────────────────────────────
// Dependency confusion detection.
//
// Threat: company uses internal `@company/auth` from a private registry.
// Attacker publishes `@company/auth` on public npm. If `.npmrc` doesn't
// pin the `@company` scope to the private registry, npm resolves the
// public (malicious) one.
// ──────────────────────────────────────────────────────────────

export const KNOWN_SAFE_SCOPES: ReadonlySet<string> = Object.freeze(new Set([
  "@google", "@microsoft", "@stripe", "@vercel", "@prisma", "@supabase", "@anthropic",
  "@openai", "@aws-sdk", "@aws-cdk", "@babel", "@types", "@jest", "@testing-library",
  "@angular", "@vue", "@nuxt", "@sveltejs", "@mui", "@radix-ui", "@tanstack", "@trpc",
  "@clerk", "@auth0", "@sentry", "@datadog", "@grafana", "@azure", "@gcloud",
  "@firebase", "@react-native", "@reduxjs", "@apollo", "@nestjs", "@nx", "@turbo",
  "@swc", "@rollup", "@vitejs", "@rspack", "@hapi", "@fastify", "@ionic", "@capacitor",
  "@adobe", "@atlaskit", "@atlassian", "@cloudflare", "@upstash", "@planetscale",
  "@neondatabase", "@octokit", "@shopify", "@paypal", "@twilio", "@sendgrid",
  "@segment", "@sourcemap", "@typescript-eslint", "@eslint", "@smithy",
]));

export interface NpmrcRegistries {
  /** Set of `@scope` (lowercase, including the @) bound to a non-default registry. */
  scopedToPrivateRegistry: Set<string>;
}

/**
 * Parse a .npmrc body and return the set of scopes explicitly routed to a
 * non-default registry. Lines look like:
 *   @scope:registry=https://internal.example.com/npm/
 */
export function parseNpmrc(content: string): NpmrcRegistries {
  const out: NpmrcRegistries = { scopedToPrivateRegistry: new Set<string>() };
  if (!content) return out;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split(/(?<!:)#/)[0].trim();
    if (!line) continue;
    // @scope:registry=URL
    const m = line.match(/^(@[a-z0-9][a-z0-9._-]*)\s*:\s*registry\s*=\s*(\S+)/i);
    if (!m) continue;
    const scope = m[1].toLowerCase();
    const url = m[2].trim();
    if (!url) continue;
    out.scopedToPrivateRegistry.add(scope);
  }
  return out;
}

export interface ConfusionFetcher {
  /** true: package exists on public npm; false: 404; null: network/error. */
  exists(scopedName: string): Promise<boolean | null>;
}

export class HttpConfusionFetcher implements ConfusionFetcher {
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  constructor(opts?: { timeoutMs?: number; fetchImpl?: typeof fetch }) {
    this.timeoutMs = opts?.timeoutMs ?? 5000;
    this.fetchImpl = opts?.fetchImpl ?? fetch;
  }
  async exists(scopedName: string): Promise<boolean | null> {
    // npm registry expects the slash url-encoded as %2F.
    const encoded = scopedName.replace("/", "%2F");
    const url = `https://registry.npmjs.org/${encoded}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        headers: { Accept: "application/vnd.npm.install-v1+json" },
        signal: controller.signal,
      });
      if (res.status === 200) return true;
      if (res.status === 404) return false;
      return null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface DepConfusionInput {
  packages: Array<{ name: string; version: string; source: string }>;
  npmrc?: string;
  fetcher?: ConfusionFetcher;
}

function scopeOf(name: string): string | null {
  if (!name.startsWith("@")) return null;
  const slash = name.indexOf("/");
  if (slash < 0) return null;
  return name.slice(0, slash).toLowerCase();
}

const MAX_CONCURRENCY = 8;

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners: Promise<void>[] = [];
  const n = Math.min(limit, items.length);
  for (let i = 0; i < n; i++) {
    runners.push((async () => {
      while (true) {
        const idx = next++;
        if (idx >= items.length) return;
        results[idx] = await worker(items[idx]);
      }
    })());
  }
  await Promise.all(runners);
  return results;
}

export async function detectDepConfusion(input: DepConfusionInput): Promise<DepIntelFinding[]> {
  const findings: DepIntelFinding[] = [];
  const npmrcSafe = input.npmrc ? parseNpmrc(input.npmrc).scopedToPrivateRegistry : new Set<string>();
  const fetcher = input.fetcher ?? new HttpConfusionFetcher();

  // Dedupe by package name (no need to repeat lookups for same name across versions).
  const byName = new Map<string, { name: string; version: string; source: string }>();
  for (const pkg of input.packages) {
    const scope = scopeOf(pkg.name);
    if (!scope) continue;
    if (KNOWN_SAFE_SCOPES.has(scope)) continue;
    if (npmrcSafe.has(scope)) continue;
    if (!byName.has(pkg.name)) byName.set(pkg.name, pkg);
  }

  const candidates = Array.from(byName.values());
  const outcomes = await runWithConcurrency(candidates, MAX_CONCURRENCY, async (pkg) => {
    const result = await fetcher.exists(pkg.name);
    return { pkg, result };
  });

  for (const { pkg, result } of outcomes) {
    if (result === null) continue;
    if (result === false) {
      findings.push({
        package: pkg.name,
        version: pkg.version,
        ecosystem: "npm",
        source: pkg.source,
        kind: "dep-confusion" as any,
        severity: "high",
        summary: `${pkg.name} is a scoped private package not registered on public npm — attacker can publish that name and trigger dependency confusion.`,
        evidence: "Add @scope:registry=... to .npmrc to lock this scope to your private registry.",
      });
    } else {
      findings.push({
        package: pkg.name,
        version: pkg.version,
        ecosystem: "npm",
        source: pkg.source,
        kind: "dep-confusion" as any,
        severity: "medium",
        summary: `${pkg.name} is a scoped package and a package by that name also exists on public npm — review whether this is the intended source.`,
        evidence: "Verify @scope:registry= in .npmrc points to your private registry, not the public one.",
      });
    }
  }

  return findings;
}
