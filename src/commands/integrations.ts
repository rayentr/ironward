import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  loadConfig,
  saveConfig,
  defaultConfigPath,
  redactConfig,
  updateConfigSection,
  type SlackConfig,
  type LinearConfig,
  type JiraConfig,
  type EmailConfig,
} from "../integrations/config.js";
import { sendSlackAlert, buildSlackMessage } from "../integrations/slack.js";
import { renderBadge, renderBadgeSvg, computeSecurityScore, updateReadmeBadge, colorForScore } from "../integrations/badge.js";
import { startApiServer, InMemoryStore } from "../integrations/api-server.js";

function pickFlag(rest: string[], flag: string): string | undefined {
  const eq = rest.find((a) => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = rest.indexOf(flag);
  if (i >= 0 && i + 1 < rest.length) return rest[i + 1];
  return undefined;
}

function hasFlag(rest: string[], flag: string): boolean {
  return rest.includes(flag);
}

// ───────────────────────────────────────────────
// slack-setup
// ───────────────────────────────────────────────

export async function runSlackSetup(rest: string[]): Promise<number> {
  const webhookUrl = pickFlag(rest, "--webhook");
  const channel = pickFlag(rest, "--channel");
  const threshold = pickFlag(rest, "--threshold") as SlackConfig["threshold"] | undefined;
  const mode = pickFlag(rest, "--mode") as SlackConfig["mode"] | undefined;
  const test = hasFlag(rest, "--test");

  if (!webhookUrl) {
    console.error("ironward slack-setup: --webhook <url> is required.");
    console.error("Usage: ironward slack-setup --webhook <url> [--channel #chan] [--threshold high|critical|all] [--mode realtime|digest|both] [--test]");
    return 2;
  }

  const cfg: Partial<SlackConfig> = {
    webhookUrl,
    ...(channel ? { channel } : {}),
    ...(threshold ? { threshold } : { threshold: "high" }),
    ...(mode ? { mode } : { mode: "realtime" }),
  };
  await updateConfigSection("slack", cfg);
  console.log(`Slack configured. Threshold: ${cfg.threshold}. Mode: ${cfg.mode}.${channel ? ` Channel: ${channel}.` : ""}`);
  console.log(`Saved to ${defaultConfigPath()} (chmod 600).`);

  if (test) {
    const payload = buildSlackMessage(
      {
        repo: "ironward-test",
        scannedBy: "cli",
        scannedAt: new Date(),
        findings: [],
      },
      cfg.threshold,
    );
    const res = await sendSlackAlert(cfg as SlackConfig, {
      repo: "ironward-test",
      scannedBy: "cli",
      scannedAt: new Date(),
      findings: [],
    });
    console.log(`Test message: ${res.ok ? "OK" : `FAILED — ${res.error ?? "unknown"}`}`);
    void payload;
    return res.ok ? 0 : 1;
  }
  return 0;
}

// ───────────────────────────────────────────────
// linear-setup
// ───────────────────────────────────────────────

export async function runLinearSetup(rest: string[]): Promise<number> {
  const apiKey = pickFlag(rest, "--api-key");
  const teamId = pickFlag(rest, "--team-id");
  const projectId = pickFlag(rest, "--project-id");
  const threshold = pickFlag(rest, "--threshold") as LinearConfig["threshold"] | undefined;
  const label = pickFlag(rest, "--label") ?? "security";

  if (!apiKey) {
    console.error("ironward linear-setup: --api-key <key> is required.");
    console.error("Usage: ironward linear-setup --api-key <key> [--team-id <id>] [--project-id <id>] [--threshold critical|high|both] [--label security]");
    return 2;
  }
  await updateConfigSection("linear", {
    apiKey,
    ...(teamId ? { teamId } : {}),
    ...(projectId ? { projectId } : {}),
    threshold: threshold ?? "high",
    label,
  });
  console.log(`Linear configured. Auto-create threshold: ${threshold ?? "high"}. Label: ${label}.`);
  console.log(`Saved to ${defaultConfigPath()} (chmod 600).`);
  return 0;
}

// ───────────────────────────────────────────────
// jira-setup
// ───────────────────────────────────────────────

export async function runJiraSetup(rest: string[]): Promise<number> {
  const baseUrl = pickFlag(rest, "--url");
  const email = pickFlag(rest, "--email");
  const apiToken = pickFlag(rest, "--api-token");
  const projectKey = pickFlag(rest, "--project");
  const issueType = pickFlag(rest, "--issue-type") ?? "Bug";
  const threshold = pickFlag(rest, "--threshold") as JiraConfig["threshold"] | undefined;

  if (!baseUrl || !email || !apiToken || !projectKey) {
    console.error("ironward jira-setup: --url, --email, --api-token, and --project are required.");
    console.error("Usage: ironward jira-setup --url https://co.atlassian.net --email you@co --api-token <t> --project SEC [--issue-type Bug] [--threshold critical|high|both]");
    return 2;
  }
  await updateConfigSection("jira", {
    baseUrl,
    email,
    apiToken,
    projectKey,
    issueType,
    threshold: threshold ?? "high",
  });
  console.log(`Jira configured. Project: ${projectKey}. Issue type: ${issueType}. Threshold: ${threshold ?? "high"}.`);
  console.log(`Saved to ${defaultConfigPath()} (chmod 600).`);
  return 0;
}

// ───────────────────────────────────────────────
// email-setup
// ───────────────────────────────────────────────

export async function runEmailSetup(rest: string[]): Promise<number> {
  const apiKey = pickFlag(rest, "--api-key");
  const from = pickFlag(rest, "--from");
  const toRaw = pickFlag(rest, "--to");
  const frequency = pickFlag(rest, "--frequency") as EmailConfig["frequency"] | undefined;
  const sendTime = pickFlag(rest, "--send-time") ?? "09:00";

  if (!apiKey || !from || !toRaw) {
    console.error("ironward email-setup: --api-key, --from, and --to are required.");  // ironward-ignore
    console.error("Usage: ironward email-setup --api-key <resend-key> --from <addr> --to <addr1,addr2> [--frequency daily|weekly] [--send-time 09:00]");
    return 2;
  }
  const to = toRaw.split(",").map((s) => s.trim()).filter(Boolean);
  await updateConfigSection("email", {
    provider: "resend",
    apiKey,
    from,
    to,
    frequency: frequency ?? "weekly",
    sendTime,
  });
  console.log(`Email digest configured. Frequency: ${frequency ?? "weekly"} at ${sendTime}. Recipients: ${to.length}.`);
  console.log(`Saved to ${defaultConfigPath()} (chmod 600).`);
  return 0;
}

// ───────────────────────────────────────────────
// badge
// ───────────────────────────────────────────────

export async function runBadge(rest: string[]): Promise<number> {
  const formatRaw = pickFlag(rest, "--format") ?? "url";
  const updateReadme = hasFlag(rest, "--update-readme");
  const linkUrl = pickFlag(rest, "--link") ?? "https://github.com/rayentr/ironward";
  const readmePath = pickFlag(rest, "--readme") ?? resolve(process.cwd(), "README.md");
  const scoreFlag = pickFlag(rest, "--score");

  // For now, score is read from --score flag, or from config.badge.lastScore, or computed
  // as 100 (fallback) since we don't yet persist findings. The CLI will pass actual scores
  // in a future release; --score lets users plug in their own.
  let score: number;
  if (scoreFlag) {
    score = Math.max(0, Math.min(100, parseInt(scoreFlag, 10)));
  } else {
    const cfg = await loadConfig();
    score = cfg.badge?.lastScore ?? computeSecurityScore([]);
  }

  if (updateReadme) {
    let content: string;
    try { content = await readFile(readmePath, "utf8"); } catch {
      console.error(`ironward badge: cannot read ${readmePath}`);
      return 2;
    }
    const updated = updateReadmeBadge(content, score, linkUrl);
    await writeFile(readmePath, updated, "utf8");
    console.log(`Updated badge in ${readmePath} (score ${score}/100, color ${colorForScore(score)}).`);
    return 0;
  }

  const out = renderBadge(score, formatRaw as Parameters<typeof renderBadge>[1], linkUrl);
  console.log(out);
  if (formatRaw === "svg") {
    console.log(renderBadgeSvg(score));
  }
  return 0;
}

// ───────────────────────────────────────────────
// api-server
// ───────────────────────────────────────────────

export async function runApiServer(rest: string[]): Promise<number> {
  const port = parseInt(pickFlag(rest, "--port") ?? "7373", 10);
  const host = pickFlag(rest, "--host") ?? "127.0.0.1";
  const store = new InMemoryStore({ findings: [], repos: [] });
  const { server, port: actualPort } = await startApiServer({ port, host, store });
  console.log(`Ironward API server listening on http://${host}:${actualPort}`);
  console.log("Endpoints:");
  console.log("  GET  /api/health");
  console.log("  GET  /api/findings[?severity=critical&repo=X]");
  console.log("  GET  /api/findings/critical");
  console.log("  GET  /api/repos");
  console.log("  GET  /api/score");
  console.log("  POST /api/scan");
  console.log("  GET  /api/config");
  console.log("  GET  /api/badge.svg");
  console.log("Ctrl-C to stop.");
  // Keep process alive until SIGINT
  return new Promise<number>((resolveExit) => {
    process.on("SIGINT", () => {
      server.close(() => resolveExit(0));
    });
    process.on("SIGTERM", () => {
      server.close(() => resolveExit(0));
    });
  });
}

// ───────────────────────────────────────────────
// config (4F — unified)
// ───────────────────────────────────────────────

export async function runConfig(rest: string[]): Promise<number> {
  const reset = hasFlag(rest, "--reset");
  const exportPath = pickFlag(rest, "--export");
  const importPath = pickFlag(rest, "--import");

  if (reset) {
    await saveConfig({});
    console.log(`Configuration cleared at ${defaultConfigPath()}.`);
    return 0;
  }

  if (importPath) {
    let raw: string;
    try { raw = await readFile(resolve(process.cwd(), importPath), "utf8"); } catch {
      console.error(`ironward config: cannot read ${importPath}`);
      return 2;
    }
    let parsed: Awaited<ReturnType<typeof loadConfig>>;
    try { parsed = JSON.parse(raw); } catch {
      console.error(`ironward config: ${importPath} is not valid JSON`);
      return 2;
    }
    await saveConfig(parsed);
    console.log(`Imported configuration from ${importPath}.`);
    return 0;
  }

  const cfg = await loadConfig();
  if (exportPath) {
    await writeFile(resolve(process.cwd(), exportPath), JSON.stringify(cfg, null, 2) + "\n", "utf8");
    console.log(`Exported configuration to ${exportPath} (contains secrets — keep private).`);
    return 0;
  }

  // Default: pretty-print redacted config
  const r = redactConfig(cfg);
  console.log("Ironward Configuration");
  console.log("──────────────────────");
  console.log(`Path:    ${defaultConfigPath()}`);
  console.log(`Slack:   ${r.slack ? `${r.slack.channel ?? "(no channel)"} (threshold: ${r.slack.threshold ?? "high"}, mode: ${r.slack.mode ?? "realtime"})` : "Not configured"}`);
  console.log(`Linear:  ${r.linear ? `team: ${r.linear.teamId ?? "(any)"} · label: ${r.linear.label ?? "security"} · threshold: ${r.linear.threshold ?? "high"}` : "Not configured"}`);
  console.log(`Jira:    ${r.jira ? `${r.jira.projectKey} on ${r.jira.baseUrl} · threshold: ${r.jira.threshold ?? "high"}` : "Not configured"}`);
  console.log(`Email:   ${r.email ? `${r.email.frequency ?? "weekly"} digest → ${r.email.to.join(", ")}` : "Not configured"}`);
  console.log(`Badge:   ${r.badge?.lastScore != null ? `${r.badge.lastScore}/100 (last updated ${r.badge.lastUpdated ?? "—"})` : "No score recorded yet"}`);
  console.log("");
  console.log("  ironward config --reset           clear all settings");
  console.log("  ironward config --export PATH     export to JSON (includes secrets)");  // ironward-ignore
  console.log("  ironward config --import PATH     import from JSON");
  return 0;
}
