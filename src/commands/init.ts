import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
  buildInitialConfig,
  detectStack,
  saveProjectConfig,
  PROJECT_CONFIG_FILENAME,
} from "../integrations/project-config.js";

export async function runInit(rest: string[]): Promise<number> {
  const force = rest.includes("--force") || rest.includes("-f");
  const cwd = process.cwd();
  const configPath = resolve(cwd, PROJECT_CONFIG_FILENAME);
  try {
    const existing = await stat(configPath).catch(() => null);
    if (existing && !force) {
      console.error(`${PROJECT_CONFIG_FILENAME} already exists. Re-run with --force to overwrite.`);
      return 2;
    }
  } catch { /* fall through */ }

  const detected = await detectStack(cwd);
  const cfg = buildInitialConfig(detected);
  await saveProjectConfig(cfg, cwd);

  console.log(`Created ${PROJECT_CONFIG_FILENAME}\n`);
  console.log("Detected stack:");
  const lines: string[] = [];
  if (detected.hasNextJs) lines.push("✅ Next.js → nextjs + react rules enabled");
  if (detected.hasSupabase) lines.push("✅ Supabase → supabase rules enabled");
  if (detected.hasStripe) lines.push("✅ Stripe → stripe rules enabled");
  if (detected.hasClerk) lines.push("✅ Clerk → clerk-auth rules enabled");
  if (detected.hasPrisma) lines.push("✅ Prisma → prisma-drizzle rules enabled");
  if (detected.hasTrpc) lines.push("✅ tRPC → trpc rules enabled");
  if (detected.hasFirebase) lines.push("✅ Firebase → firebase rules enabled");
  if (detected.hasDockerfile) lines.push("✅ Docker → scan-docker enabled");
  if (detected.hasTerraform) lines.push("✅ Terraform → scan-infra enabled");
  if (detected.hasGithubActions) lines.push("✅ GitHub Actions → scan-github enabled");
  if (detected.hasPythonSources) lines.push("✅ Python → python rules enabled");
  if (detected.hasJavaSources) lines.push("✅ Java → java rules enabled");
  if (detected.hasGoMod) lines.push("✅ Go (go.mod) → go rules enabled");
  if (lines.length === 0) {
    console.log("  (no specific stack detected — running with default rule set)");
  } else {
    for (const l of lines) console.log("  " + l);
  }
  const ruleCats = cfg.rules?.enabledCategories?.length ?? 0;
  console.log("");
  if (ruleCats > 0) {
    console.log(`${ruleCats} rule categor${ruleCats === 1 ? "y" : "ies"} auto-enabled based on your project dependencies.`);
  }
  console.log(`Scanners: ${cfg.enabledScanners?.join(", ") ?? "(default)"}.`);
  console.log("\nNext steps: ironward scan .   (or)   ironward doctor");
  return 0;
}
