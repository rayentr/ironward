import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type AIProvider = "anthropic" | "openai" | "gemini" | "groq" | "ollama";

export interface AIConfig {
  provider: AIProvider;
  apiKey?: string;
  model: string;
  baseUrl?: string;
}

export interface ProviderMeta {
  id: AIProvider;
  name: string;
  tagline: string;
  keyUrl?: string;
  defaultModel: string;
  envVar?: string;
  requiresKey: boolean;
}

export const PROVIDERS: ProviderMeta[] = [
  {
    id: "anthropic",
    name: "Anthropic",
    tagline: "Claude Opus/Sonnet — best reasoning",
    keyUrl: "https://console.anthropic.com/settings/keys",
    defaultModel: "claude-opus-4-5",
    envVar: "ANTHROPIC_API_KEY",
    requiresKey: true,
  },
  {
    id: "openai",
    name: "OpenAI",
    tagline: "GPT-4o — great alternative",
    keyUrl: "https://platform.openai.com/api-keys",
    defaultModel: "gpt-4o",
    envVar: "OPENAI_API_KEY",
    requiresKey: true,
  },
  {
    id: "gemini",
    name: "Google",
    tagline: "Gemini 1.5 Pro — good for XSS/SQLi",
    keyUrl: "https://aistudio.google.com/app/apikey",
    defaultModel: "gemini-1.5-pro",
    envVar: "GEMINI_API_KEY",
    requiresKey: true,
  },
  {
    id: "groq",
    name: "Groq",
    tagline: "Llama 3 — fastest, cheapest",
    keyUrl: "https://console.groq.com/keys",
    defaultModel: "llama-3.3-70b-versatile",
    envVar: "GROQ_API_KEY",
    requiresKey: true,
  },
  {
    id: "ollama",
    name: "Ollama",
    tagline: "Local — free, private, no cloud",
    defaultModel: "llama3.1",
    requiresKey: false,
  },
];

export function getProvider(id: AIProvider): ProviderMeta {
  const p = PROVIDERS.find((x) => x.id === id);
  if (!p) throw new Error(`Unknown provider: ${id}`);
  return p;
}

export function configPath(): string {
  return join(homedir(), ".ironward", "config.json");
}

export async function readConfig(): Promise<AIConfig | null> {
  try {
    const raw = await readFile(configPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<AIConfig>;
    if (!parsed.provider || !parsed.model) return null;
    if (!PROVIDERS.some((p) => p.id === parsed.provider)) return null;
    return parsed as AIConfig;
  } catch {
    return null;
  }
}

export async function writeConfig(cfg: AIConfig): Promise<void> {
  const p = configPath();
  await mkdir(dirname(p), { recursive: true, mode: 0o700 });
  await writeFile(p, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

export async function deleteConfig(): Promise<boolean> {
  try {
    await rm(configPath(), { force: true });
    return true;
  } catch {
    return false;
  }
}

export function resolveConfigFromEnv(): AIConfig | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return { provider: "anthropic", apiKey: process.env.ANTHROPIC_API_KEY, model: getProvider("anthropic").defaultModel };
  }
  if (process.env.OPENAI_API_KEY) {
    return { provider: "openai", apiKey: process.env.OPENAI_API_KEY, model: getProvider("openai").defaultModel };
  }
  if (process.env.GEMINI_API_KEY) {
    return { provider: "gemini", apiKey: process.env.GEMINI_API_KEY, model: getProvider("gemini").defaultModel };
  }
  if (process.env.GROQ_API_KEY) {
    return { provider: "groq", apiKey: process.env.GROQ_API_KEY, model: getProvider("groq").defaultModel };
  }
  return null;
}
