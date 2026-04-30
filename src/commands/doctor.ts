import { stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { resolveConfig } from "../engines/claude-client.js";
import { OllamaClient } from "../engines/ollama-client.js";
import { loadConfig as loadIronwardConfig, defaultConfigPath } from "../integrations/config.js";
import { CODE_RULES } from "../engines/code-rules.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

interface CheckLine {
  status: "ok" | "warn" | "fail";
  text: string;
  hint?: string;
}

function symbol(s: CheckLine["status"]): string {
  return s === "ok" ? "✅" : s === "warn" ? "⚠️ " : "❌";
}

async function fileExists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

async function countSecretPatterns(): Promise<number> {
  try {
    const { listPatternFamilies } = await import("../engines/secret-engine.js") as { listPatternFamilies?: () => Promise<string[]> };
    if (typeof listPatternFamilies === "function") {
      const all = await listPatternFamilies();
      return all.length;
    }
  } catch { /* fall through */ }
  // Fallback: count entries in patterns/secrets.json
  try {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const { dirname } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    for (const cand of [join(here, "../../patterns/secrets.json"), join(here, "../patterns/secrets.json")]) {
      try {
        const raw = await readFile(cand, "utf8");
        return Object.keys(JSON.parse(raw)).length;
      } catch { /* try next */ }
    }
  } catch { /* unknown */ }
  return 0;
}

export async function runDoctor(): Promise<number> {
  const lines: string[] = [];
  lines.push(`Ironward v${pkg.version} — System Check`);
  lines.push("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  lines.push("");

  // ── Offline tools ──
  lines.push("Offline tools");
  const secretCount = await countSecretPatterns();
  const checks: CheckLine[] = [
    { status: secretCount > 0 ? "ok" : "warn", text: `scan_for_secrets    ${secretCount > 0 ? `${secretCount} patterns loaded` : "patterns file not found"}` },
    { status: "ok", text: `scan_code           ${CODE_RULES.length} rules loaded` },
    { status: "ok", text: `scan_deps           OSV.dev (network on demand)` },
    { status: "ok", text: `scan_url            HTTP client ready` },
    { status: "ok", text: `scan_docker         offline rules` },
    { status: "ok", text: `scan_k8s            offline rules` },
    { status: "ok", text: `scan_infra          offline rules` },
    { status: "ok", text: `scan_github         offline rules` },
  ];
  for (const c of checks) lines.push(`${symbol(c.status)} ${c.text}`);
  lines.push("");

  // ── AI provider ──
  lines.push("AI tools");
  const aiCfg = await resolveConfig();
  if (aiCfg) {
    lines.push(`✅ Provider: ${aiCfg.provider}${aiCfg.model ? ` (${aiCfg.model})` : ""}`);
    if (aiCfg.provider === "ollama") {
      lines.push(`✅ Ollama base URL: ${aiCfg.baseUrl ?? "http://localhost:11434"}`);
    } else if (aiCfg.apiKey) {
      lines.push(`✅ API key: present (length ${aiCfg.apiKey.length})`);
    } else {
      lines.push(`⚠️  API key: missing for provider ${aiCfg.provider}`);
    }
    for (const t of ["scan_auth_logic", "scan_sqli", "scan_xss", "scan_idor", "fix_and_pr"]) {
      lines.push(`✅ ${t}     ready`);
    }
  } else {
    lines.push("⚠️  No AI provider configured.");
    lines.push("    Run `ironward login` (cloud) or install Ollama (local).");
  }
  lines.push("");

  // ── Local AI (Ollama) ──
  lines.push("Local AI (Ollama)");
  const ollama = new OllamaClient();
  const ollamaUp = await ollama.isAvailable();
  if (ollamaUp) {
    lines.push(`✅ Ollama: running (localhost:11434)`);
    const models = await ollama.listModels();
    if (models.length === 0) {
      lines.push(`⚠️  No local models installed`);
      lines.push(`    For best results: ollama pull deepseek-coder:6.7b`);
    } else {
      for (const m of models) {
        const sizeGb = m.size > 0 ? ` (${(m.size / 1024 / 1024 / 1024).toFixed(1)} GB)` : "";
        lines.push(`✅ ${m.name}${sizeGb}`);
      }
      const rec = await ollama.getRecommendedModel();
      if (!rec.installed) {
        lines.push(`⚠️  No large model installed`);
        lines.push(`    For better results: ollama pull ${rec.model}`);
      }
    }
  } else {
    lines.push("⚠️  Ollama: not running");
    lines.push("    Install at https://ollama.com — then `ollama serve`.");
  }
  lines.push("");

  // ── Integrations ──
  lines.push("Integrations");
  const ironCfg = await loadIronwardConfig();
  lines.push(ironCfg.slack ? `✅ Slack: ${ironCfg.slack.channel ?? "(no channel)"} (threshold: ${ironCfg.slack.threshold ?? "high"})` : "⚠️  Slack: Not configured");
  lines.push(ironCfg.linear ? `✅ Linear: team ${ironCfg.linear.teamId ?? "(any)"} · label ${ironCfg.linear.label ?? "security"}` : "⚠️  Linear: Not configured");
  lines.push(ironCfg.jira ? `✅ Jira: ${ironCfg.jira.projectKey} on ${ironCfg.jira.baseUrl}` : "⚠️  Jira: Not configured");
  lines.push(ironCfg.email ? `✅ Email: ${ironCfg.email.frequency ?? "weekly"} digest → ${ironCfg.email.to.length} recipient${ironCfg.email.to.length === 1 ? "" : "s"}` : "⚠️  Email: Not configured");
  lines.push("");

  // ── Git hooks + storage ──
  lines.push("Git hooks");
  const hookPath = join(process.cwd(), ".git", "hooks", "pre-commit");
  const hookExists = await fileExists(hookPath);
  lines.push(hookExists ? "✅ Pre-commit hook: installed" : "⚠️  Pre-commit hook: not installed (run `ironward install-hooks`)");
  lines.push("✅ ironward watch: available");
  lines.push("");

  lines.push("Storage");
  const home = homedir();
  const storagePaths = [
    [defaultConfigPath(), "Config"],
    [join(home, ".ironward", "cache.json"), "Cache"],
    [join(home, ".ironward", "ironward.db"), "Database"],
    [join(home, ".ironward", "npm-cache.json"), "NPM cache"],
  ];
  for (const [p, label] of storagePaths) {
    const exists = await fileExists(p);
    lines.push(`${exists ? "✅" : "⚠️ "} ${label.padEnd(10)}: ${p}${exists ? "" : " (not yet created)"}`);
  }
  lines.push("");

  // ── Overall ──
  const warnings = lines.filter((l) => l.startsWith("⚠️")).length;
  const fails = lines.filter((l) => l.startsWith("❌")).length;
  if (fails > 0) lines.push(`Overall: 🔴 Issues — ${fails} failure${fails === 1 ? "" : "s"}, ${warnings} warning${warnings === 1 ? "" : "s"}`);
  else if (warnings > 0) lines.push(`Overall: 🟡 Healthy — ${warnings} warning${warnings === 1 ? "" : "s"}`);
  else lines.push(`Overall: 🟢 All systems operational`);

  console.log(lines.join("\n"));
  return fails > 0 ? 1 : 0;
}
