import { readFile, writeFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

export interface ProjectConfig {
  version?: "1";
  threshold?: "critical" | "high" | "medium" | "low";
  offline?: boolean;
  excludePaths?: string[];
  enabledScanners?: Array<"secrets" | "code" | "deps" | "docker" | "k8s" | "infra" | "github" | "url">;
  rules?: {
    disable?: string[];
    downgrade?: Record<string, "high" | "medium" | "low" | "info">;
    /** Categories auto-detected at init time. Future versions may use this to scope scans. */
    enabledCategories?: string[];
  };
  slack?: { threshold?: "critical" | "high" | "medium" | "low" | "all" };
  badge?: { target?: number };
}

export const PROJECT_CONFIG_FILENAME = ".ironward.json";

export async function loadProjectConfig(cwd: string = process.cwd()): Promise<ProjectConfig | null> {
  try {
    const raw = await readFile(resolve(cwd, PROJECT_CONFIG_FILENAME), "utf8");
    return JSON.parse(raw) as ProjectConfig;
  } catch {
    return null;
  }
}

export async function saveProjectConfig(cfg: ProjectConfig, cwd: string = process.cwd()): Promise<void> {
  await writeFile(resolve(cwd, PROJECT_CONFIG_FILENAME), JSON.stringify(cfg, null, 2) + "\n", "utf8");
}

export interface DetectedStack {
  hasNextJs: boolean;
  hasDockerfile: boolean;
  hasTerraform: boolean;
  hasGithubActions: boolean;
  hasPackageJson: boolean;
  hasPipfile: boolean;
  hasRequirementsTxt: boolean;
  hasGoMod: boolean;
  hasJavaSources: boolean;
  hasPythonSources: boolean;
  // npm dependency-driven flags
  hasSupabase: boolean;
  hasStripe: boolean;
  hasClerk: boolean;
  hasPrisma: boolean;
  hasTrpc: boolean;
  hasFirebase: boolean;
}

async function npmHasDep(cwd: string, deps: string[]): Promise<boolean> {
  try {
    const { readFile } = await import("node:fs/promises");
    const raw = await readFile(resolve(cwd, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.optionalDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    return deps.some((d) => Object.prototype.hasOwnProperty.call(all, d));
  } catch {
    return false;
  }
}

async function hasFileWithExtension(cwd: string, ext: string, maxDepth = 2): Promise<boolean> {
  // Cheap heuristic: walk a small depth looking for ANY file ending in `ext`.
  const { readdir } = await import("node:fs/promises");
  type DirEntry = { name: string; isFile: () => boolean; isDirectory: () => boolean };
  const stack: Array<{ path: string; depth: number }> = [{ path: cwd, depth: 0 }];
  const skip = new Set(["node_modules", ".git", "dist", "build", ".next", "venv", ".venv"]);
  while (stack.length) {
    const { path, depth } = stack.pop()!;
    let entries: DirEntry[] = [];
    try { entries = (await readdir(path, { withFileTypes: true })) as unknown as DirEntry[]; } catch { continue; }
    for (const e of entries) {
      if (skip.has(e.name)) continue;
      const child = resolve(path, e.name);
      if (e.isFile() && e.name.endsWith(ext)) return true;
      if (e.isDirectory() && depth < maxDepth) stack.push({ path: child, depth: depth + 1 });
    }
  }
  return false;
}

export async function detectStack(cwd: string = process.cwd()): Promise<DetectedStack> {
  const exists = async (rel: string): Promise<boolean> => {
    try { await stat(resolve(cwd, rel)); return true; } catch { return false; }
  };
  const hasNextJs = (await exists("next.config.js"))
    || (await exists("next.config.ts"))
    || (await exists("next.config.mjs"));
  const hasDockerfile = (await exists("Dockerfile")) || (await exists("docker-compose.yml")) || (await exists("docker-compose.yaml"));
  const hasGithubActions = await exists(".github/workflows");
  const hasPackageJson = await exists("package.json");
  const hasPipfile = await exists("Pipfile.lock");
  const hasRequirementsTxt = (await exists("requirements.txt")) || (await exists("setup.py")) || (await exists("pyproject.toml"));
  const hasTerraform = (await exists("main.tf")) || (await exists("terraform.tf")) || await hasFileWithExtension(cwd, ".tf", 1);
  const hasGoMod = await exists("go.mod");
  const hasJavaSources = await hasFileWithExtension(cwd, ".java", 2);
  const hasPythonSources = hasPipfile || hasRequirementsTxt || (await hasFileWithExtension(cwd, ".py", 2));
  // npm dependency-driven flags
  const hasSupabase = hasPackageJson && await npmHasDep(cwd, ["@supabase/supabase-js", "@supabase/auth-helpers-nextjs", "@supabase/ssr"]);
  const hasStripe = hasPackageJson && await npmHasDep(cwd, ["stripe", "@stripe/stripe-js"]);
  const hasClerk = hasPackageJson && await npmHasDep(cwd, ["@clerk/nextjs", "@clerk/clerk-sdk-node", "@clerk/clerk-react", "@clerk/backend"]);
  const hasPrisma = hasPackageJson && await npmHasDep(cwd, ["@prisma/client", "prisma"]);
  const hasTrpc = hasPackageJson && await npmHasDep(cwd, ["@trpc/server", "@trpc/client", "@trpc/react-query", "@trpc/next"]);
  const hasFirebase = hasPackageJson && await npmHasDep(cwd, ["firebase", "firebase-admin"]);
  return {
    hasNextJs, hasDockerfile, hasTerraform, hasGithubActions,
    hasPackageJson, hasPipfile, hasRequirementsTxt, hasGoMod,
    hasJavaSources, hasPythonSources,
    hasSupabase, hasStripe, hasClerk, hasPrisma, hasTrpc, hasFirebase,
  };
}

/**
 * Map a DetectedStack into the rule categories that are most relevant. The runtime engine
 * doesn't currently filter by category, but writing this list to the config makes the
 * developer's stack explicit and gives future versions a hook to scope scans.
 */
export function detectedRuleCategories(d: DetectedStack): string[] {
  const cats: string[] = [];
  if (d.hasNextJs) cats.push("nextjs", "react");
  if (d.hasSupabase) cats.push("supabase");
  if (d.hasStripe) cats.push("stripe");
  if (d.hasClerk) cats.push("clerk-auth");
  if (d.hasPrisma) cats.push("prisma-drizzle");
  if (d.hasTrpc) cats.push("trpc");
  if (d.hasFirebase) cats.push("firebase");
  if (d.hasPythonSources) cats.push("python");
  if (d.hasJavaSources) cats.push("java");
  if (d.hasGoMod) cats.push("go");
  return [...new Set(cats)];
}

/** Build a sensible default ProjectConfig based on detected stack. */
export function buildInitialConfig(detected: DetectedStack): ProjectConfig {
  const enabledScanners: ProjectConfig["enabledScanners"] = ["secrets", "code"];
  if (detected.hasPackageJson || detected.hasPipfile || detected.hasRequirementsTxt) enabledScanners.push("deps");
  if (detected.hasDockerfile) enabledScanners.push("docker");
  if (detected.hasTerraform) enabledScanners.push("infra");
  if (detected.hasGithubActions) enabledScanners.push("github");
  const ruleCats = detectedRuleCategories(detected);
  return {
    version: "1",
    threshold: "high",
    offline: false,
    excludePaths: ["tests/", "dist/", "build/", "node_modules/", "*.min.js", "*.map"],
    enabledScanners,
    rules: {
      disable: [],
      downgrade: {},
      ...(ruleCats.length ? { enabledCategories: ruleCats } : {}),
    },
  };
}

/** True if a project config disables this scanner. */
export function scannerEnabled(cfg: ProjectConfig | null, scanner: string): boolean {
  if (!cfg || !cfg.enabledScanners) return true;
  return cfg.enabledScanners.includes(scanner as any);
}

/** True if a project config disables this rule id. */
export function ruleDisabled(cfg: ProjectConfig | null, ruleId: string): boolean {
  if (!cfg || !cfg.rules?.disable) return false;
  return cfg.rules.disable.includes(ruleId);
}

export function downgradeFor(cfg: ProjectConfig | null, ruleId: string): string | null {
  if (!cfg || !cfg.rules?.downgrade) return null;
  return cfg.rules.downgrade[ruleId] ?? null;
}
