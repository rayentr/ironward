import { readFile } from "node:fs/promises";
import {
  OsvClient,
  highestSeverity,
  fixedVersions,
  type OsvEcosystem,
  type OsvVuln,
} from "../engines/osv-client.js";
import {
  detectTyposquat,
  detectAdvancedTyposquat,
  detectKnownMalware,
  classifyAbandonment,
  classifyLicense,
  loadMalwareDb,
  lookupMalware,
  parsePackageLock,
  findTransitiveParents,
  buildDependencyGraph as buildDependencyGraphImport,
  NpmRegistryFetcher,
  type RegistryFetcher,
  type DepIntelFinding,
} from "../engines/dep-intel.js";
import { analyzeBehavior } from "../engines/behavior-analyzer.js";
import { CachingNpmReputationFetcher, scorePackage, scoreToFinding, type ReputationFetcher } from "../engines/reputation-scorer.js";
import { detectDepConfusion, HttpConfusionFetcher, type ConfusionFetcher } from "../engines/dep-confusion.js";

export type DepSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export interface DepDeclaration {
  name: string;
  version: string;
  ecosystem: OsvEcosystem;
  source: string;
  license?: string | null;
}

export interface DepFinding {
  package: string;
  version: string;
  ecosystem: OsvEcosystem;
  vulnerabilityId: string;
  aliases: string[];
  severity: DepSeverity;
  summary: string;
  fixedIn: string[];
  references: string[];
  source: string;
  pulledInBy?: string[];
}

export interface ScanDepsInput {
  paths?: string[];
  manifests?: Array<{ path: string; content: string }>;
  lockfiles?: Array<{ path: string; content: string }>;
  /** Optional .npmrc body — used by dep-confusion check to determine private-scope routing. */
  npmrc?: string;
  /** node_modules root for behavior analysis (reads top-level files). */
  nodeModulesDir?: string;
  checkAbandoned?: boolean;
  /** Run behavior analysis (install scripts + suspicious imports + obfuscation). */
  withBehavior?: boolean;
  /** Run reputation scoring against npm registry (with cache). */
  withReputation?: boolean;
  /** Build dep graph from lockfile and tag CVEs with which direct dep pulled them in. */
  withTransitive?: boolean;
  /** Run dep-confusion detection (scoped packages on public npm). */
  withConfusion?: boolean;
}

export interface ScanDepsOutput {
  dependenciesScanned: number;
  findings: DepFinding[];
  intel: DepIntelFinding[];
  summary: string;
}

export function parsePackageJson(content: string, source: string): DepDeclaration[] {
  let data: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  const out: DepDeclaration[] = [];
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"] as const) {
    const obj = data[section];
    if (!obj) continue;
    for (const [name, raw] of Object.entries(obj)) {
      const version = normalizeSemver(raw);
      if (!version) continue;
      out.push({ name, version, ecosystem: "npm", source });
    }
  }
  return out;
}

export function isDirectProdDep(packageJsonContent: string, depName: string): boolean {
  try {
    const data = JSON.parse(packageJsonContent) as { dependencies?: Record<string, string> };
    return Boolean(data.dependencies && depName in data.dependencies);
  } catch {
    return false;
  }
}

export function parseRequirementsTxt(content: string, source: string): DepDeclaration[] {
  const out: DepDeclaration[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-") || line.startsWith("http")) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+\-]+)/);
    if (!m) continue;
    out.push({ name: m[1], version: m[2], ecosystem: "PyPI", source });
  }
  return out;
}

export function parsePipfileLock(content: string, source: string): DepDeclaration[] {
  let data: Record<string, Record<string, { version?: string }>>;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  const out: DepDeclaration[] = [];
  for (const section of ["default", "develop"]) {
    const pkgs = data[section];
    if (!pkgs) continue;
    for (const [name, meta] of Object.entries(pkgs)) {
      const ver = meta.version?.replace(/^==/, "");
      if (!ver) continue;
      out.push({ name, version: ver, ecosystem: "PyPI", source });
    }
  }
  return out;
}

function normalizeSemver(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith("file:") || trimmed.startsWith("link:") || trimmed.startsWith("git")) return null;
  if (trimmed.startsWith("npm:")) return null;
  const m = trimmed.match(/\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9.]+)?/);
  return m ? m[0] : null;
}

export function detectManifestKind(path: string): "package.json" | "requirements.txt" | "Pipfile.lock" | null {
  const lower = path.toLowerCase();
  if (lower.endsWith("/package.json") || lower === "package.json") return "package.json";
  if (lower.endsWith("/requirements.txt") || lower === "requirements.txt") return "requirements.txt";
  if (lower.endsWith("/pipfile.lock") || lower === "pipfile.lock") return "Pipfile.lock";
  return null;
}

export function parseManifest(path: string, content: string): DepDeclaration[] {
  const kind = detectManifestKind(path);
  if (kind === "package.json") return parsePackageJson(content, path);
  if (kind === "requirements.txt") return parseRequirementsTxt(content, path);
  if (kind === "Pipfile.lock") return parsePipfileLock(content, path);
  return [];
}

export interface ScanDepsExtras {
  reputationFetcher?: ReputationFetcher;
  confusionFetcher?: ConfusionFetcher;
}

export async function runScanDeps(
  input: ScanDepsInput,
  osv: OsvClient = new OsvClient(),
  registry: RegistryFetcher | null = null,
  extras: ScanDepsExtras = {},
): Promise<ScanDepsOutput> {
  const declarations: DepDeclaration[] = [];
  const manifestContents = new Map<string, string>();

  if (input.manifests) {
    for (const m of input.manifests) {
      manifestContents.set(m.path, m.content);
      declarations.push(...parseManifest(m.path, m.content));
    }
  }
  if (input.paths) {
    for (const p of input.paths) {
      try {
        const content = await readFile(p, "utf8");
        manifestContents.set(p, content);
        declarations.push(...parseManifest(p, content));
      } catch {
        /* ignore */
      }
    }
  }

  // Build dep graph from lockfile if requested
  let depGraph: ReturnType<typeof buildDependencyGraphImport> | null = null;
  if (input.withTransitive && input.lockfiles && input.lockfiles.length > 0) {
    for (const lf of input.lockfiles) {
      depGraph = buildDependencyGraphImport(lf.content);
      // Add all reachable transitive deps to declarations so OSV scans them too.
      for (const [name, paths] of depGraph.paths) {
        if (depGraph.directDeps.has(name)) continue;
        // Pull the version from the lockfile if available
        try {
          const data = JSON.parse(lf.content) as { packages?: Record<string, { version?: string }> };
          const pkg = data.packages?.[`node_modules/${name}`];
          const version = pkg?.version;
          if (version) {
            declarations.push({ name, version, ecosystem: "npm", source: lf.path });
          }
        } catch { /* ignore */ }
        // Suppress unused-var warning by referencing paths
        void paths;
      }
      break; // first lockfile only
    }
  }

  const unique = new Map<string, DepDeclaration>();
  for (const d of declarations) unique.set(`${d.ecosystem}:${d.name}@${d.version}`, d);

  const findings: DepFinding[] = [];
  for (const dep of unique.values()) {
    let vulns: OsvVuln[] = [];
    try {
      vulns = await osv.query({ package: { name: dep.name, ecosystem: dep.ecosystem }, version: dep.version });
    } catch {
      continue;
    }
    for (const v of vulns) {
      const transitivePath = depGraph?.paths.get(dep.name);
      findings.push({
        package: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        vulnerabilityId: v.id,
        aliases: v.aliases ?? [],
        severity: highestSeverity(v),
        summary: v.summary ?? v.details?.slice(0, 200) ?? "",
        fixedIn: fixedVersions(v, dep.ecosystem, dep.name),
        references: (v.references ?? []).map((r) => r.url ?? "").filter(Boolean),
        source: dep.source,
        ...(transitivePath && transitivePath.length > 0 && !depGraph?.directDeps.has(dep.name)
          ? { pulledInBy: transitivePath }
          : {}),
      });
    }
  }

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.package.localeCompare(b.package));

  // Prime the rich malware DB so lookupMalware works synchronously below.
  await loadMalwareDb();

  const intel: DepIntelFinding[] = [];
  for (const dep of unique.values()) {
    if (dep.ecosystem !== "npm") continue;
    // Advanced typosquat (edit-distance + combosquat + homoglyph + scope-mimic)
    const adv = detectAdvancedTyposquat(dep.name);
    if (adv) {
      const kindLabel: Record<typeof adv.kind, string> = {
        "edit-distance": "Levenshtein distance ≤ 2 from",
        "combosquat": "combosquatting variant of",
        "homoglyph": "homoglyph / lookalike of",
        "scope-mimic": "unscoped mimic of scoped package",
      };
      intel.push({
        package: dep.name, version: dep.version, ecosystem: dep.ecosystem, source: dep.source,
        kind: "typosquat", severity: "high",
        summary: `"${dep.name}" looks like a typosquat of "${adv.match}" (${adv.kind}).`,
        evidence: `${kindLabel[adv.kind]} ${adv.match}`,
      });
    }
    // Rich malware DB: prefer exact-version match (CRITICAL) over name-only (HIGH).
    const malware = lookupMalware(dep.name, dep.version, dep.ecosystem);
    if (malware) {
      intel.push({
        package: dep.name, version: dep.version, ecosystem: dep.ecosystem, source: dep.source,
        kind: "malware",
        severity: malware.exact ? "critical" : "high",
        summary: malware.exact
          ? `"${dep.name}@${dep.version}" is on the known-malware list. ${malware.entry.reason}`
          : `"${dep.name}" had a previously malicious version (${malware.entry.version ?? "unspecified"}) — verify this version is clean. Reason: ${malware.entry.reason}`,
        evidence: `Source: ${malware.entry.source}${malware.entry.date ? ` (${malware.entry.date})` : ""}`,
        references: ["https://socket.dev/advisories", "https://github.com/advisories"],
      });
    } else if (detectKnownMalware(dep.name, dep.ecosystem)) {
      // Backwards-compat: hardcoded set still flags name matches not in JSON DB.
      intel.push({
        package: dep.name, version: dep.version, ecosystem: dep.ecosystem, source: dep.source,
        kind: "malware", severity: "critical",
        summary: `"${dep.name}" appears on the known-malware list. Remove it immediately.`,
        references: ["https://socket.dev/advisories", "https://github.com/advisories"],
      });
    }
  }

  // Behavior analysis — opt-in. Requires nodeModulesDir on disk.
  if (input.withBehavior && input.nodeModulesDir) {
    const { readFile, readdir } = await import("node:fs/promises");
    const { join, dirname } = await import("node:path");
    void dirname;
    for (const dep of unique.values()) {
      if (dep.ecosystem !== "npm") continue;
      const pkgDir = join(input.nodeModulesDir, dep.name);
      let pkgJson = "";
      try { pkgJson = await readFile(join(pkgDir, "package.json"), "utf8"); } catch { continue; }
      const topFiles: Array<{ path: string; content: string }> = [];
      try {
        const entries = await readdir(pkgDir, { withFileTypes: true });
        for (const e of entries) {
          if (!e.isFile()) continue;
          if (!e.name.endsWith(".js") || e.name.endsWith(".min.js")) continue;
          try {
            const content = await readFile(join(pkgDir, e.name), "utf8");
            if (content.length > 200_000) continue;
            topFiles.push({ path: e.name, content });
          } catch { /* skip */ }
        }
      } catch { /* no readable dir — skip */ }
      const behaviorFindings = analyzeBehavior({
        packageName: dep.name,
        packageVersion: dep.version,
        source: dep.source,
        packageJson: pkgJson,
        topLevelFiles: topFiles,
      });
      intel.push(...behaviorFindings);
    }
  }

  // Reputation scoring — opt-in. Uses provided fetcher or defaults to caching HTTP fetcher.
  if (input.withReputation) {
    const fetcher: ReputationFetcher = extras.reputationFetcher ?? new CachingNpmReputationFetcher();
    const npmDeps = [...unique.values()].filter((d) => d.ecosystem === "npm");
    // Bounded concurrency
    const CONC = 10;
    let i = 0;
    const workers = Array.from({ length: Math.min(CONC, npmDeps.length) }, async () => {
      while (i < npmDeps.length) {
        const dep = npmDeps[i++];
        const meta = await fetcher.fetch(dep.name);
        if (!meta) continue;
        const score = scorePackage(meta);
        const f = scoreToFinding(dep.name, dep.version, dep.source, score);
        if (f) intel.push(f);
      }
    });
    await Promise.all(workers);
  }

  // Dependency confusion — opt-in.
  if (input.withConfusion) {
    const fetcher: ConfusionFetcher = extras.confusionFetcher ?? new HttpConfusionFetcher();
    const pkgList = [...unique.values()]
      .filter((d) => d.ecosystem === "npm")
      .map((d) => ({ name: d.name, version: d.version, source: d.source }));
    const confusion = await detectDepConfusion({
      packages: pkgList,
      npmrc: input.npmrc,
      fetcher,
    });
    intel.push(...confusion);
  }

  // Abandoned check — only if registry fetcher available and user opts in.
  if (registry && input.checkAbandoned !== false) {
    for (const dep of unique.values()) {
      if (dep.ecosystem !== "npm") continue;
      const last = await registry.lastPublished(dep.name);
      const state = classifyAbandonment(last);
      if (state === "abandoned") {
        intel.push({
          package: dep.name, version: dep.version, ecosystem: dep.ecosystem, source: dep.source,
          kind: "abandoned", severity: "high",
          summary: `"${dep.name}" has not been published in over 4 years.`,
          evidence: last ? `Last publish: ${last.toISOString().slice(0, 10)}` : undefined,
        });
      } else if (state === "stale") {
        intel.push({
          package: dep.name, version: dep.version, ecosystem: dep.ecosystem, source: dep.source,
          kind: "abandoned", severity: "medium",
          summary: `"${dep.name}" has not been published in over 2 years.`,
          evidence: last ? `Last publish: ${last.toISOString().slice(0, 10)}` : undefined,
        });
      }
    }
  }

  // License check — checks the root package.json's own "license" field for UNLICENSED.
  for (const [path, content] of manifestContents) {
    if (!path.toLowerCase().endsWith("package.json")) continue;
    try {
      const parsed = JSON.parse(content) as { name?: string; license?: string | { type?: string } };
      const licenseStr = typeof parsed.license === "string" ? parsed.license : parsed.license?.type;
      const classification = classifyLicense(licenseStr);
      if (classification === "unlicensed") {
        intel.push({
          package: parsed.name ?? "(root)", version: "-", ecosystem: "npm", source: path,
          kind: "unlicensed", severity: "medium",
          summary: `${path} declares no license field — consumers cannot legally redistribute it.`,
        });
      } else if (classification === "copyleft") {
        intel.push({
          package: parsed.name ?? "(root)", version: "-", ecosystem: "npm", source: path,
          kind: "license", severity: "low",
          summary: `${path} uses copyleft license "${licenseStr}" — may require open-sourcing derived works.`,
        });
      }
    } catch {
      /* ignore malformed */
    }
  }

  intel.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.package.localeCompare(b.package));

  const counts: Record<DepSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) counts[f.severity]++;
  for (const f of intel) counts[f.severity]++;

  let summary: string;
  if (findings.length === 0 && intel.length === 0) {
    summary = `No known vulnerabilities across ${unique.size} dependencies.`;
  } else if (findings.length > 0 && intel.length === 0) {
    summary = `${findings.length} vulnerabilities across ${unique.size} dependencies — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.unknown} unscored.`;
  } else {
    summary = `${findings.length} CVE${findings.length === 1 ? "" : "s"} + ${intel.length} supply-chain finding${intel.length === 1 ? "" : "s"} across ${unique.size} dependencies — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low.`;
  }

  return { dependenciesScanned: unique.size, findings, intel, summary };
}

function severityRank(s: DepSeverity): number {
  return ({ critical: 5, high: 4, medium: 3, low: 2, unknown: 1 } as const)[s];
}

export function formatDepsReport(out: ScanDepsOutput): string {
  const lines = [out.summary, ""];
  if (out.findings.length === 0 && out.intel.length === 0) return out.summary;

  for (const f of out.findings) {
    const aliases = f.aliases.length ? ` (${f.aliases.join(", ")})` : "";
    const fixed = f.fixedIn.length ? ` — fixed in ${f.fixedIn.join(", ")}` : "";
    const via = f.pulledInBy && f.pulledInBy.length ? `  (transitive via ${f.pulledInBy.join(", ")})` : "";
    lines.push(`[${f.severity.toUpperCase()}] ${f.package}@${f.version}  ${f.vulnerabilityId}${aliases}${fixed}${via}`);
    if (f.summary) lines.push(`  ${f.summary}`);
    if (f.references[0]) lines.push(`  ref: ${f.references[0]}`);
  }

  if (out.intel.length > 0) {
    lines.push("");
    lines.push("── supply-chain intel ──");
    for (const f of out.intel) {
      const tag = f.kind.toUpperCase();
      lines.push(`[${f.severity.toUpperCase()}] ${tag}  ${f.package}@${f.version}`);
      lines.push(`  ${f.summary}`);
      if (f.evidence) lines.push(`  ${f.evidence}`);
      if (f.references?.[0]) lines.push(`  ref: ${f.references[0]}`);
    }
  }
  return lines.join("\n").trimEnd();
}
