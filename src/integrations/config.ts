import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export interface SlackConfig {
  webhookUrl: string;
  channel?: string;
  threshold?: "critical" | "high" | "medium" | "low" | "all";
  mode?: "realtime" | "digest" | "both";
}

export interface LinearConfig {
  apiKey: string;
  teamId?: string;
  projectId?: string;
  threshold?: "critical" | "high" | "both";
  label?: string;
  assigneeId?: string | null;
}

export interface JiraConfig {
  baseUrl: string;       // e.g. "https://company.atlassian.net"
  email: string;
  apiToken: string;
  projectKey: string;    // e.g. "SEC"
  issueType?: string;    // default "Bug"
  threshold?: "critical" | "high" | "both";
}

export interface EmailConfig {
  provider: "resend";
  apiKey: string;
  from: string;
  to: string[];
  frequency?: "daily" | "weekly";
  sendTime?: string;     // "09:00"
}

export interface BadgeConfig {
  lastScore?: number;
  lastUpdated?: string;
}

export interface IronwardConfig {
  slack?: SlackConfig;
  linear?: LinearConfig;
  jira?: JiraConfig;
  email?: EmailConfig;
  badge?: BadgeConfig;
}

export function defaultConfigPath(): string {
  return process.env.IRONWARD_CONFIG_PATH ?? join(homedir(), ".ironward", "config.json");
}

export async function loadConfig(path: string = defaultConfigPath()): Promise<IronwardConfig> {
  try {
    const raw = await readFile(path, "utf8");
    return JSON.parse(raw) as IronwardConfig;
  } catch {
    return {};
  }
}

export async function saveConfig(cfg: IronwardConfig, path: string = defaultConfigPath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  // Best-effort restrict to user-only — file may contain API keys.
  try { await chmod(path, 0o600); } catch { /* not all FS support chmod */ }
}

/** Deep-merge a single section into existing config and persist. */
export async function updateConfigSection<K extends keyof IronwardConfig>(
  section: K,
  patch: Partial<NonNullable<IronwardConfig[K]>>,
  path: string = defaultConfigPath(),
): Promise<IronwardConfig> {
  const cfg = await loadConfig(path);
  cfg[section] = { ...(cfg[section] as object | undefined), ...patch } as IronwardConfig[K];
  await saveConfig(cfg, path);
  return cfg;
}

/** Returns config with all secrets redacted (for display/export). */
export function redactConfig(cfg: IronwardConfig): IronwardConfig {
  const redact = (s: string | undefined): string | undefined => {
    if (!s) return s;
    if (s.length <= 8) return "***";
    return s.slice(0, 4) + "***" + s.slice(-4);
  };
  const out: IronwardConfig = {};
  if (cfg.slack) {
    out.slack = { ...cfg.slack, webhookUrl: redact(cfg.slack.webhookUrl) ?? "***" };
  }
  if (cfg.linear) {
    out.linear = { ...cfg.linear, apiKey: redact(cfg.linear.apiKey) ?? "***" };
  }
  if (cfg.jira) {
    out.jira = { ...cfg.jira, apiToken: redact(cfg.jira.apiToken) ?? "***" };
  }
  if (cfg.email) {
    out.email = { ...cfg.email, apiKey: redact(cfg.email.apiKey) ?? "***" };
  }
  if (cfg.badge) out.badge = { ...cfg.badge };
  return out;
}

/** Stable fingerprint for a finding — used to dedupe Linear/Jira issue creation. */
export function findingFingerprint(repo: string, file: string, line: number, ruleId: string): string {
  // Simple djb2-ish hash, good enough for dedup keys.
  const s = `${repo}\x00${file}\x00${line}\x00${ruleId}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}
