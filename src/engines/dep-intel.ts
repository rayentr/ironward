import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { OsvEcosystem } from "./osv-client.js";

export interface DepIntelFinding {
  package: string;
  version: string;
  ecosystem: OsvEcosystem;
  source: string;
  kind: "typosquat" | "abandoned" | "malware" | "license" | "unlicensed";
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  evidence?: string;
  references?: string[];
}

// ──────────────────────────────────────────────────────────────
// Typosquat: 100 most-depended-upon npm packages
// Source: npm registry popularity rankings. Intentionally hardcoded to
// keep scan offline.
// ──────────────────────────────────────────────────────────────
export const POPULAR_NPM_PACKAGES: readonly string[] = Object.freeze([
  "lodash", "react", "react-dom", "chalk", "express", "commander", "axios", "moment",
  "request", "webpack", "async", "debug", "fs-extra", "glob", "typescript", "yargs",
  "minimist", "bluebird", "inquirer", "mkdirp", "rimraf", "underscore", "uuid", "tslib",
  "prop-types", "classnames", "dotenv", "body-parser", "jsonwebtoken", "bcrypt",
  "bcryptjs", "mongoose", "pg", "mysql2", "redis", "socket.io", "nodemon", "cors",
  "helmet", "morgan", "multer", "passport", "joi", "zod", "ajv", "cheerio", "puppeteer",
  "playwright", "prettier", "eslint", "jest", "mocha", "chai", "sinon", "vitest",
  "supertest", "nock", "cross-env", "concurrently", "husky", "lint-staged",
  "semver", "ora", "ws", "node-fetch", "form-data", "qs", "body-parser",
  "cookie-parser", "express-session", "connect-redis", "tailwindcss", "postcss",
  "autoprefixer", "sass", "rollup", "vite", "esbuild", "babel-core", "@babel/core",
  "@babel/preset-env", "@babel/preset-react", "@types/node", "@types/react",
  "ts-node", "tsx", "swc", "next", "nuxt", "vue", "@vue/cli", "svelte",
  "gatsby", "jquery", "redux", "react-redux", "@reduxjs/toolkit", "zustand",
  "immer", "date-fns", "dayjs", "luxon", "ramda", "rxjs", "graphql", "apollo-server",
  "@apollo/client", "drizzle-orm", "prisma", "sequelize", "knex", "mongodb",
  "stripe", "twilio", "openai", "@anthropic-ai/sdk",
  // Top 100-500 (curated): build / bundlers / runtime tooling
  "@swc/core", "terser", "uglify-js", "lerna", "turbo", "nx", "pnpm", "yarn", "npm",
  "rspack", "@rspack/core", "@rsbuild/core", "ts-loader", "babel-loader", "css-loader",
  "style-loader", "html-webpack-plugin", "mini-css-extract-plugin", "fork-ts-checker-webpack-plugin",
  "@types/lodash", "@types/express", "@types/jest", "@types/jsonwebtoken", "@types/bcrypt",
  "@types/cors", "@types/uuid", "@types/ws", "@types/yargs", "@types/glob", "@types/minimist",
  // React ecosystem
  "react-router", "react-router-dom", "react-query", "@tanstack/react-query", "@tanstack/query-core",
  "react-hook-form", "formik", "yup", "react-icons", "@heroicons/react", "react-spring",
  "framer-motion", "react-transition-group", "react-helmet", "react-helmet-async",
  "@emotion/react", "@emotion/styled", "styled-components", "@mui/material", "@mui/icons-material",
  "@chakra-ui/react", "antd", "@radix-ui/react-dialog", "@radix-ui/react-popover",
  "@radix-ui/react-tooltip", "@radix-ui/react-dropdown-menu", "react-toastify", "react-hot-toast",
  "react-table", "@tanstack/react-table", "recharts", "react-chartjs-2", "chart.js",
  // Vue / Svelte / Angular
  "vue-router", "vuex", "pinia", "@vueuse/core", "@vue/composition-api",
  "@sveltejs/kit", "@angular/core", "@angular/common", "@angular/router", "@angular/forms",
  "rxjs-compat", "@ngrx/store",
  // Node server / framework
  "fastify", "@fastify/cors", "@fastify/helmet", "@fastify/jwt", "koa", "koa-router",
  "@hapi/hapi", "nestjs", "@nestjs/core", "@nestjs/common", "@nestjs/platform-express",
  "@nestjs/typeorm", "@nestjs/jwt", "@nestjs/passport", "feathers", "@feathersjs/feathers",
  "express-validator", "express-async-errors", "compression", "express-rate-limit",
  "rate-limiter-flexible", "@trpc/server", "@trpc/client", "@trpc/react-query",
  // ORMs and DB
  "typeorm", "@prisma/client", "prisma-client-js", "kysely", "objection", "@databases/pg",
  "mysql", "pg-pool", "pg-promise", "ioredis", "dynamodb", "@aws-sdk/client-dynamodb",
  // Testing and mocking
  "@playwright/test", "cypress", "puppeteer-core", "msw", "@testing-library/react",
  "@testing-library/jest-dom", "@testing-library/user-event", "@vitest/ui", "@vitest/coverage-v8",
  "ts-jest", "jest-environment-jsdom", "jest-environment-node", "babel-jest",
  // Auth / security
  "passport-local", "passport-jwt", "passport-oauth2", "passport-google-oauth20",
  "passport-github2", "next-auth", "@auth/core", "@clerk/nextjs", "@clerk/clerk-sdk-node",
  "firebase", "firebase-admin", "@supabase/supabase-js", "@supabase/auth-helpers-nextjs",
  // CLI / tooling
  "chokidar", "fast-glob", "globby", "execa", "shelljs", "boxen", "cli-table3",
  "cli-progress", "listr", "listr2", "enquirer", "prompts", "kleur", "picocolors",
  "fs-jetpack", "del", "tempy", "tmp", "tmp-promise",
  // Cloud / SDKs
  "aws-sdk", "@aws-sdk/client-s3", "@aws-sdk/client-sqs", "@aws-sdk/client-sns",
  "@aws-sdk/client-secrets-manager", "@aws-sdk/client-lambda", "@google-cloud/storage",
  "@azure/storage-blob", "@vercel/analytics", "@vercel/edge", "@cloudflare/workers-types",
  // Date / utils / parsing
  "date-fns-tz", "moment-timezone", "humanize-duration", "ms", "pretty-bytes",
  "fast-deep-equal", "fast-diff", "deep-equal", "deepmerge", "lodash-es",
  "lodash.merge", "lodash.get", "lodash.set", "lodash.debounce", "lodash.throttle",
  "lodash.isequal", "validator", "is-email", "email-validator", "libphonenumber-js",
  "country-data", "iso-3166-1", "currency-symbol-map", "big.js", "bignumber.js",
  "decimal.js", "long",
  // HTTP clients
  "got", "ky", "needle", "superagent", "phin", "undici", "@nestjs/axios",
  // Streaming / CSV / Parsing
  "csv-parse", "csv-stringify", "papaparse", "xml2js", "fast-xml-parser",
  "iconv-lite", "encoding", "node-html-parser", "jsdom", "happy-dom",
  // GraphQL
  "graphql-tag", "@apollo/server", "apollo-server-express", "@graphql-tools/schema",
  "@graphql-tools/load", "graphql-yoga", "@urql/core", "urql",
  // OpenAI / LLM
  "@anthropic-ai/sdk", "openai", "@google/generative-ai", "@huggingface/inference",
  "langchain", "@langchain/openai", "@langchain/anthropic", "@langchain/community",
  "ai", "@ai-sdk/openai", "@ai-sdk/anthropic",
  // Misc widely-used
  "winston", "pino", "bunyan", "log4js", "consola", "loglevel",
  "node-cron", "agenda", "bullmq", "bull", "p-queue", "p-limit", "p-retry",
  "p-map", "p-all", "p-timeout",
  "yauzl", "yazl", "tar", "tar-fs", "archiver", "adm-zip",
  "sharp", "jimp", "image-size", "exif-reader",
  "marked", "markdown-it", "remark", "rehype", "unified",
  "@sentry/node", "@sentry/react", "@sentry/nextjs", "@datadog/browser-logs",
]);

function levenshtein(a: string, b: string, limit: number): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  const m = a.length, n = b.length;
  const dp: number[] = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    let rowMin = dp[0];
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      if (a.charCodeAt(i - 1) === b.charCodeAt(j - 1)) {
        dp[j] = prev;
      } else {
        dp[j] = 1 + Math.min(prev, dp[j], dp[j - 1]);
      }
      prev = tmp;
      if (dp[j] < rowMin) rowMin = dp[j];
    }
    if (rowMin > limit) return limit + 1;
  }
  return dp[n];
}

export function detectTyposquat(name: string, popular: readonly string[] = POPULAR_NPM_PACKAGES): string | null {
  if (popular.includes(name)) return null;
  if (name.startsWith("@")) return null;
  if (name.length < 3) return null;
  for (const pop of popular) {
    if (pop.startsWith("@")) continue;
    if (pop === name) return null;
    const d = levenshtein(name, pop, 2);
    if (d > 0 && d <= 2) return pop;
  }
  return null;
}

// ──────────────────────────────────────────────────────────────
// Advanced typosquat detection: combosquatting, homoglyph, scope-mimic
// ──────────────────────────────────────────────────────────────

const COMBOSQUAT_SUFFIXES: readonly string[] = Object.freeze([
  "utils", "util", "helper", "helpers", "tools", "lib", "core",
  "extra", "extras", "plus", "pro", "fast", "lite", "mini", "micro",
  "next", "nextjs", "ng", "v2", "v3", "alt", "free", "official",
]);

const COMBOSQUAT_PREFIXES: readonly string[] = Object.freeze([
  "real", "true", "official", "node", "the", "fast", "easy",
]);

// Returns the popular package this combosquats, or null.
export function detectCombosquat(name: string, popular: readonly string[] = POPULAR_NPM_PACKAGES): string | null {
  if (popular.includes(name)) return null;
  if (name.startsWith("@")) return null;
  for (const pop of popular) {
    if (pop.startsWith("@")) continue;
    if (pop === name) return null;
    for (const sfx of COMBOSQUAT_SUFFIXES) {
      if (name === `${pop}-${sfx}` || name === `${pop}.${sfx}` || name === `${pop}${sfx}`) return pop;
    }
    for (const pfx of COMBOSQUAT_PREFIXES) {
      if (name === `${pfx}-${pop}` || name === `${pfx}.${pop}` || name === `${pfx}${pop}`) return pop;
    }
  }
  return null;
}

// Substitute homoglyph-style lookalikes back to canonical chars and re-check vs popular.
const HOMOGLYPH_MAP: Record<string, string> = {
  "1": "l", "0": "o", "5": "s", "rn": "m", "vv": "w", "II": "ll",
};

export function detectHomoglyph(name: string, popular: readonly string[] = POPULAR_NPM_PACKAGES): string | null {
  if (popular.includes(name)) return null;
  if (name.startsWith("@")) return null;
  // Try character-substitution lookalikes first.
  let normalized = name;
  for (const [from, to] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.split(from).join(to);
  }
  if (normalized !== name) {
    for (const pop of popular) {
      if (pop.startsWith("@")) continue;
      if (pop === normalized) return pop;
    }
  }
  // Then try repeated-letter swap. Two cases:
  //   "expresss" (3+ run) → "express" (collapse 3+ to 2)
  //   "lodassh"  (extra letter) → "lodash" (collapse 2 to 1)
  // We try both transformations and check each against popular.
  const candidates: string[] = [];
  const collapse3to2 = name.replace(/(.)\1{2,}/g, "$1$1");
  if (collapse3to2 !== name) candidates.push(collapse3to2);
  const collapse2to1 = name.replace(/(.)\1+/g, "$1");
  if (collapse2to1 !== name && collapse2to1 !== collapse3to2) candidates.push(collapse2to1);
  for (const cand of candidates) {
    for (const pop of popular) {
      if (pop.startsWith("@")) continue;
      if (pop === cand) return pop;
    }
  }
  return null;
}

// Unscoped package mimicking a popular scoped one: "stripe-js" vs "@stripe/stripe-js".
export function detectScopeMimic(name: string, popular: readonly string[] = POPULAR_NPM_PACKAGES): string | null {
  if (name.startsWith("@")) return null;
  if (popular.includes(name)) return null;
  for (const pop of popular) {
    if (!pop.startsWith("@")) continue;
    const slash = pop.indexOf("/");
    if (slash < 0) continue;
    const scope = pop.slice(1, slash); // e.g. "stripe"
    const inner = pop.slice(slash + 1); // e.g. "stripe-js"
    if (name === inner || name === `${scope}-${inner}` || name === `${scope}.${inner}` || name === `${scope}${inner}`) {
      return pop;
    }
  }
  return null;
}

export type AdvancedTyposquatKind = "edit-distance" | "combosquat" | "homoglyph" | "scope-mimic";

export interface AdvancedTyposquatHit {
  kind: AdvancedTyposquatKind;
  match: string;
}

export function detectAdvancedTyposquat(
  name: string,
  popular: readonly string[] = POPULAR_NPM_PACKAGES,
): AdvancedTyposquatHit | null {
  const editMatch = detectTyposquat(name, popular);
  if (editMatch) return { kind: "edit-distance", match: editMatch };
  const combo = detectCombosquat(name, popular);
  if (combo) return { kind: "combosquat", match: combo };
  const homo = detectHomoglyph(name, popular);
  if (homo) return { kind: "homoglyph", match: homo };
  const mimic = detectScopeMimic(name, popular);
  if (mimic) return { kind: "scope-mimic", match: mimic };
  return null;
}

// ──────────────────────────────────────────────────────────────
// Known malware — hardcoded list sourced from Socket.dev / GHSA
// malware advisories. Conservative: only packages with active
// or recently-active malicious publication confirmed.
// ──────────────────────────────────────────────────────────────
export const KNOWN_MALWARE_NPM: ReadonlySet<string> = Object.freeze(new Set([
  "event-stream", "flatmap-stream", "eslint-scope", "rc", "ua-parser-js",
  "coa", "electron-native-notify", "getcookies", "http-fetch-cookies",
  "http-fetch-cookies-2", "crossenv", "cross-env.js", "d3.js", "fabric-js",
  "jquery.js", "mariadb", "mongose", "mssql.js", "mssql-node", "mysqljs",
  "node-fabric", "node-opencv", "node-opensl", "node-sqlite", "nodecaffe",
  "nodefabric", "nodeffmpeg", "nodemailer-js", "nodemailer.js", "nodemssql",
  "node-openssl", "noderequest", "nodesass", "nodesqlite", "opencv.js",
  "openssl.js", "proxy.js", "shadowsock", "smb", "sqlite.js", "sqliter",
  "sqlserver", "tkinter", "colors", "faker", "chalk-next", "discord.dll",
  "ionicons", "babelcli", "ffmepg", "mumblerpc",
  "rustdecimal", "rustyloader", "py-binance-api", "pymocks", "pythonkafka",
  "flatmapstream", "bignum.js", "@fintechiq/pay", "protobufjs-ax",
  "web3x-js", "web3provider-rpc", "eth-signer-js",
]));

export function detectKnownMalware(name: string, ecosystem: OsvEcosystem): boolean {
  if (ecosystem !== "npm") return false;
  if (KNOWN_MALWARE_NPM.has(name)) return true;
  // Also consult the rich DB once it's loaded synchronously via priming.
  if (MALWARE_DB_BY_NAME.has(name)) return true;
  return false;
}

// ──────────────────────────────────────────────────────────────
// Rich malware database (loaded from patterns/malware-packages.json)
// ──────────────────────────────────────────────────────────────

export interface MalwareEntry {
  name: string;
  /** specific tainted version; absent → flag any version of this name */
  version?: string;
  reason: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  date?: string;
}

export interface MalwareLookup {
  entry: MalwareEntry;
  /** true when the dep version exactly matches a tainted version */
  exact: boolean;
}

const MALWARE_DB_BY_NAME = new Map<string, MalwareEntry[]>();
let MALWARE_DB_LOADED = false;

export async function loadMalwareDb(): Promise<MalwareEntry[]> {
  if (MALWARE_DB_LOADED) return [...MALWARE_DB_BY_NAME.values()].flat();
  let here: string | null = null;
  try {
    if (typeof import.meta?.url === "string") here = dirname(fileURLToPath(import.meta.url));
  } catch { /* ignore */ }
  const candidates: string[] = here ? [
    join(here, "../../patterns/malware-packages.json"),
    join(here, "../patterns/malware-packages.json"),
  ] : [];
  let raw: string | null = null;
  for (const p of candidates) {
    try {
      raw = await readFile(p, "utf8");
      break;
    } catch { /* try next */ }
  }
  MALWARE_DB_LOADED = true;
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as { packages?: MalwareEntry[] };
    for (const e of parsed.packages ?? []) {
      const list = MALWARE_DB_BY_NAME.get(e.name) ?? [];
      list.push(e);
      MALWARE_DB_BY_NAME.set(e.name, list);
    }
    return parsed.packages ?? [];
  } catch {
    return [];
  }
}

/** Returns null when the dep is not in the DB. Otherwise returns the entry + whether the version matched exactly. */
export function lookupMalware(name: string, version: string, ecosystem: OsvEcosystem = "npm"): MalwareLookup | null {
  if (ecosystem !== "npm") return null;
  const entries = MALWARE_DB_BY_NAME.get(name);
  if (!entries || entries.length === 0) return null;
  const exact = entries.find((e) => e.version === version);
  if (exact) return { entry: exact, exact: true };
  // Name match without version → return the first entry as a representative; flag as non-exact.
  return { entry: entries[0], exact: false };
}

// ──────────────────────────────────────────────────────────────
// Abandoned package: last publish > 2 years ago = warn,
// > 4 years = high. Requires a fetcher (npm registry).
// ──────────────────────────────────────────────────────────────
export interface RegistryFetcher {
  lastPublished(name: string): Promise<Date | null>;
}

export class NpmRegistryFetcher implements RegistryFetcher {
  async lastPublished(name: string): Promise<Date | null> {
    try {
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
        headers: { Accept: "application/vnd.npm.install-v1+json" },
      });
      if (!res.ok) return null;
      const data = (await res.json()) as { time?: Record<string, string>; modified?: string };
      const modified = data.modified ?? data.time?.modified;
      return modified ? new Date(modified) : null;
    } catch {
      return null;
    }
  }
}

export function classifyAbandonment(lastPublished: Date | null, now: Date = new Date()): "active" | "stale" | "abandoned" | null {
  if (!lastPublished) return null;
  const days = (now.getTime() - lastPublished.getTime()) / 86400000;
  if (days < 730) return "active";
  if (days < 1460) return "stale";
  return "abandoned";
}

// ──────────────────────────────────────────────────────────────
// License compliance
// Copyleft licenses in production can force open-sourcing.
// ──────────────────────────────────────────────────────────────
export const COPYLEFT_LICENSES: ReadonlySet<string> = Object.freeze(new Set([
  "GPL-1.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
  "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
  "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
  "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL-2.0-only", "LGPL-2.1-only",
  "LGPL-3.0-only", "LGPL-2.1-or-later", "LGPL-3.0-or-later",
]));

export function classifyLicense(raw: string | undefined | null): "permissive" | "copyleft" | "unlicensed" | "unknown" {
  if (!raw) return "unlicensed";
  const normalized = raw.trim().replace(/[()]/g, "").toUpperCase();
  if (normalized === "UNLICENSED" || normalized === "NONE" || normalized === "SEE LICENSE IN LICENSE") {
    return "unlicensed";
  }
  for (const l of COPYLEFT_LICENSES) {
    if (normalized.includes(l.toUpperCase())) return "copyleft";
  }
  // Common permissive licenses
  if (/\b(MIT|APACHE-2\.0|BSD-[23]-CLAUSE|ISC|0BSD|UNLICENSE|CC0-1\.0|WTFPL)\b/.test(normalized)) {
    return "permissive";
  }
  return "unknown";
}

// ──────────────────────────────────────────────────────────────
// Transitive resolution from package-lock.json / pnpm-lock
// Returns a map from transitive package → direct parent(s) that pulled it in.
// ──────────────────────────────────────────────────────────────
export interface LockfileEntry {
  name: string;
  version: string;
  direct: boolean;
  parents: string[];
}

export function parsePackageLock(content: string): Map<string, LockfileEntry> {
  const out = new Map<string, LockfileEntry>();
  let data: {
    dependencies?: Record<string, { version?: string; requires?: Record<string, string>; dependencies?: Record<string, unknown> }>;
    packages?: Record<string, { version?: string; dependencies?: Record<string, string>; dev?: boolean }>;
  };
  try {
    data = JSON.parse(content);
  } catch {
    return out;
  }
  if (data.packages) {
    // npm v7+ lockfile format
    const root = data.packages[""];
    const directSet = new Set<string>();
    if (root && typeof root === "object" && "dependencies" in root && root.dependencies) {
      for (const dep of Object.keys(root.dependencies as Record<string, string>)) directSet.add(dep);
    }
    for (const [path, meta] of Object.entries(data.packages)) {
      if (!path) continue;
      const idx = path.lastIndexOf("node_modules/");
      if (idx < 0) continue;
      const name = path.slice(idx + "node_modules/".length);
      if (!name || !meta.version) continue;
      const key = `${name}@${meta.version}`;
      if (!out.has(key)) {
        out.set(key, { name, version: meta.version, direct: directSet.has(name), parents: [] });
      }
    }
  }
  return out;
}

export function findTransitiveParents(
  lock: Map<string, LockfileEntry>,
  vulnerableName: string,
  vulnerableVersion: string,
): string[] {
  const entry = lock.get(`${vulnerableName}@${vulnerableVersion}`);
  if (!entry) return [];
  return entry.direct ? [] : entry.parents;
}

/**
 * Build a richer dependency graph from a package-lock.json (npm v7+).
 * Returns:
 *   - directDeps: set of direct dependency names
 *   - paths: for each `name`, an array of human path strings like "express > body-parser > qs"
 *     leading from a direct dependency to that name. Useful for "which direct dep pulled this in".
 */
export interface DependencyGraph {
  directDeps: Set<string>;
  paths: Map<string, string[]>;
}

export function buildDependencyGraph(lockContent: string): DependencyGraph {
  const directDeps = new Set<string>();
  const paths = new Map<string, string[]>();
  let data: {
    packages?: Record<string, { version?: string; dependencies?: Record<string, string>; dev?: boolean }>;
  };
  try {
    data = JSON.parse(lockContent);
  } catch {
    return { directDeps, paths };
  }
  const pkgs = data.packages;
  if (!pkgs) return { directDeps, paths };

  // Build adjacency: name -> set of names it depends on (using top-level node_modules entries).
  const root = pkgs[""];
  if (root && typeof root === "object" && "dependencies" in root && root.dependencies) {
    for (const name of Object.keys(root.dependencies as Record<string, string>)) directDeps.add(name);
  }
  const adj = new Map<string, Set<string>>();
  for (const [path, meta] of Object.entries(pkgs)) {
    if (!path) continue;
    // Use the top-level installation only (e.g. "node_modules/express") to keep the graph small.
    const segs = path.split("node_modules/");
    if (segs.length !== 2 || segs[0] !== "") continue;
    const name = segs[1];
    if (!name || !meta.dependencies) continue;
    const set = adj.get(name) ?? new Set<string>();
    for (const dep of Object.keys(meta.dependencies)) set.add(dep);
    adj.set(name, set);
  }

  // BFS from each direct dep, recording the path to every reachable transitive package.
  for (const direct of directDeps) {
    const visited = new Set<string>([direct]);
    const queue: Array<{ node: string; trail: string[] }> = [{ node: direct, trail: [direct] }];
    while (queue.length) {
      const { node, trail } = queue.shift()!;
      const children = adj.get(node);
      if (!children) continue;
      for (const child of children) {
        if (visited.has(child)) continue;
        visited.add(child);
        const newTrail = [...trail, child];
        const trailStr = newTrail.join(" > ");
        const list = paths.get(child) ?? [];
        if (!list.includes(trailStr)) list.push(trailStr);
        paths.set(child, list);
        queue.push({ node: child, trail: newTrail });
      }
    }
  }
  return { directDeps, paths };
}
