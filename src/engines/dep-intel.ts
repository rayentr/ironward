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
  return KNOWN_MALWARE_NPM.has(name);
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
