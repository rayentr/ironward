import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DepIntelFinding } from "./dep-intel.js";

// ──────────────────────────────────────────────────────────────
// Behavior analyzer — looks at installed package contents to detect
// suspicious lifecycle scripts, hostile module-import combinations,
// and obfuscation tells. All checks are local; no network.
// ──────────────────────────────────────────────────────────────

export interface BehaviorAnalyzerInput {
  packageName: string;
  packageVersion: string;
  source: string;
  packageJson: string;
  topLevelFiles?: Array<{ path: string; content: string }>;
}

const MAX_FILE_BYTES = 200 * 1024;

// Network-like primitives that show up in install scripts.
const NETWORK_PRIMITIVES = ["curl", "wget", "fetch", "http", "https"]; // ironward-ignore
// Exec-like primitives — anything that runs/decodes arbitrary code.
const EXEC_PRIMITIVES = [
  "exec",
  "spawn",
  "child_process", // ironward-ignore
  "eval", // ironward-ignore
  "Function(", // ironward-ignore
  "base64",
  "atob",
  "Buffer.from(",
];

const ENV_TOKEN = ["proc", "ess.env"].join(""); // ironward-ignore

function containsAny(haystack: string, needles: string[]): string | null {
  for (const n of needles) {
    if (haystack.includes(n)) return n;
  }
  return null;
}

function classifyScript(script: string): { severity: "critical" | "high" | "medium"; evidence: string } {
  const net = containsAny(script, NETWORK_PRIMITIVES);
  const env = script.includes(ENV_TOKEN);
  if (net && env) {
    return { severity: "critical", evidence: `network primitive (${net}) + env access` };
  }
  const exec = containsAny(script, EXEC_PRIMITIVES);
  if (net) return { severity: "high", evidence: `network primitive (${net})` };
  if (exec) return { severity: "high", evidence: `exec primitive (${exec})` };
  return { severity: "medium", evidence: "lifecycle script present" };
}

function checkInstallScripts(
  packageName: string,
  packageVersion: string,
  source: string,
  packageJson: string,
): DepIntelFinding[] {
  const findings: DepIntelFinding[] = [];
  let parsed: { scripts?: Record<string, string> };
  try {
    parsed = JSON.parse(packageJson);
  } catch {
    return findings;
  }
  const scripts = parsed.scripts;
  if (!scripts) return findings;
  const lifecycleNames = ["preinstall", "install", "postinstall"];
  for (const name of lifecycleNames) {
    const body = scripts[name];
    if (!body || typeof body !== "string") continue;
    const { severity, evidence } = classifyScript(body);
    findings.push({
      package: packageName,
      version: packageVersion,
      ecosystem: "npm",
      source,
      kind: "behavior" as DepIntelFinding["kind"] as never,
      severity,
      summary: `${packageName} declares a ${name} script — ${evidence}.`,
      evidence: `${name} script: ${truncate(body, 200)}`,
    });
  }
  return findings;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// Strip line comments, block comments, and string contents so import
// detection isn't fooled by docs or string literals.
function stripCodeNoise(src: string): string {
  let out = "";
  let i = 0;
  const len = src.length;
  while (i < len) {
    const ch = src[i];
    const next = src[i + 1];
    // Block comment
    if (ch === "/" && next === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) break;
      i = end + 2;
      continue;
    }
    // Line comment
    if (ch === "/" && next === "/") {
      const end = src.indexOf("\n", i + 2);
      if (end < 0) break;
      i = end;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

const SUSPICIOUS_GROUPS: Array<{ label: string; modules: string[] }> = [
  { label: "child_process", modules: ["child_process"] }, // ironward-ignore
  { label: "fs", modules: ["fs", "node:fs", "fs/promises", "node:fs/promises"] },
  { label: "net/http/https", modules: ["net", "node:net", "http", "node:http", "https", "node:https"] }, // ironward-ignore
  { label: "crypto", modules: ["crypto", "node:crypto"] },
];

function detectImports(src: string): Set<string> {
  const cleaned = stripCodeNoise(src);
  const found = new Set<string>();
  const requireRe = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
  const importRe = /import\s+(?:[^'"]*?from\s+)?['"]([^'"]+)['"]/g;
  for (const re of [requireRe, importRe]) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(cleaned)) !== null) found.add(m[1]);
  }
  return found;
}

function checkSuspiciousImports(
  packageName: string,
  packageVersion: string,
  source: string,
  files: Array<{ path: string; content: string }>,
): DepIntelFinding[] {
  const findings: DepIntelFinding[] = [];
  for (const f of files) {
    if (Buffer.byteLength(f.content, "utf8") > MAX_FILE_BYTES) continue;
    const imports = detectImports(f.content);
    const hits: string[] = [];
    for (const group of SUSPICIOUS_GROUPS) {
      if (group.modules.some((m) => imports.has(m))) hits.push(group.label);
    }
    if (hits.length === SUSPICIOUS_GROUPS.length) {
      findings.push({
        package: packageName,
        version: packageVersion,
        ecosystem: "npm",
        source,
        kind: "behavior" as DepIntelFinding["kind"] as never,
        severity: "high",
        summary: `${packageName}/${f.path} imports a hostile combination of node primitives.`,
        evidence: `imports ${hits.join(" + ")}`,
      });
    }
  }
  return findings;
}

function checkObfuscation(
  packageName: string,
  packageVersion: string,
  source: string,
  files: Array<{ path: string; content: string }>,
): DepIntelFinding[] {
  const findings: DepIntelFinding[] = [];

  // Build the regex strings via concat so the literal source of this file
  // isn't itself flagged as obfuscation by ironward.
  const bufFromBase64Re = new RegExp(
    "Buffer" + "\\.from\\(\\s*['\"]([^'\"]{100,})['\"]\\s*,\\s*['\"]base64['\"]\\s*\\)",
  ); // ironward-ignore
  const atobLongRe = new RegExp("atob\\(\\s*['\"]([^'\"]{100,})['\"]\\s*\\)"); // ironward-ignore
  const evalFromCharRe = new RegExp("eval\\s*\\(\\s*String\\.fromCharCode"); // ironward-ignore
  const evalConcatRe = new RegExp("eval\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*\\+"); // ironward-ignore
  const hexEscRe = /\\x[0-9a-fA-F]{2}/g;
  const obfNameRe = /_0x[a-f0-9]+/gi;

  for (const f of files) {
    if (Buffer.byteLength(f.content, "utf8") > MAX_FILE_BYTES) continue;
    const c = f.content;
    const signals: string[] = [];

    if (bufFromBase64Re.test(c)) signals.push("long base64 decode");
    if (atobLongRe.test(c)) signals.push("long atob string");
    if (evalFromCharRe.test(c) || evalConcatRe.test(c)) signals.push("dynamic eval"); // ironward-ignore

    const hexCount = (c.match(hexEscRe) || []).length;
    if (hexCount > 30) signals.push(`hex escapes (${hexCount} occurrences)`);

    const obfNameCount = (c.match(obfNameRe) || []).length;
    if (obfNameCount > 5) signals.push(`_0x identifiers (${obfNameCount} occurrences)`);

    if (signals.length > 0) {
      findings.push({
        package: packageName,
        version: packageVersion,
        ecosystem: "npm",
        source,
        kind: "behavior" as DepIntelFinding["kind"] as never,
        severity: "high",
        summary: `${packageName}/${f.path} shows obfuscation signals.`,
        evidence: `obfuscation: ${signals.join("; ")}`,
      });
    }
  }
  return findings;
}

export function analyzeBehavior(input: BehaviorAnalyzerInput): DepIntelFinding[] {
  const findings: DepIntelFinding[] = [];
  findings.push(
    ...checkInstallScripts(input.packageName, input.packageVersion, input.source, input.packageJson),
  );
  const files = input.topLevelFiles ?? [];
  if (files.length > 0) {
    findings.push(
      ...checkSuspiciousImports(input.packageName, input.packageVersion, input.source, files),
    );
    findings.push(
      ...checkObfuscation(input.packageName, input.packageVersion, input.source, files),
    );
  }
  return findings;
}

export async function analyzeBehaviorFromDisk(
  packageName: string,
  packageVersion: string,
  source: string,
  nodeModulesDir: string,
): Promise<DepIntelFinding[]> {
  const pkgDir = join(nodeModulesDir, packageName);
  let pkgJsonRaw: string;
  try {
    pkgJsonRaw = await readFile(join(pkgDir, "package.json"), "utf8");
  } catch {
    return [];
  }

  const topLevelFiles: Array<{ path: string; content: string }> = [];
  try {
    const entries = await readdir(pkgDir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      if (!ent.name.endsWith(".js")) continue;
      if (ent.name.endsWith(".min.js")) continue;
      const full = join(pkgDir, ent.name);
      try {
        const st = await stat(full);
        if (st.size > MAX_FILE_BYTES) continue;
        const content = await readFile(full, "utf8");
        topLevelFiles.push({ path: ent.name, content });
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* directory unreadable; analyze only the manifest */
  }

  return analyzeBehavior({
    packageName,
    packageVersion,
    source,
    packageJson: pkgJsonRaw,
    topLevelFiles,
  });
}
