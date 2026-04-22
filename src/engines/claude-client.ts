import Anthropic from "@anthropic-ai/sdk";
import { type AIConfig, type AIProvider, getProvider, resolveConfigFromEnv } from "./ai-config.js";

export interface ClaudeRequest {
  model: string;
  system: string;
  user: string;
  maxTokens?: number;
  temperature?: number;
}

export interface ClaudeClient {
  analyze(req: ClaudeRequest): Promise<string>;
  provider?: AIProvider;
}

export type AIClient = ClaudeClient;

export class MissingApiKeyError extends Error {
  constructor(msg?: string) {
    super(
      msg ??
        "No AI provider configured. Run `ironward login` to pick one (Anthropic, OpenAI, Gemini, Groq, or Ollama), " +
          "or set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY / GROQ_API_KEY in your environment.",
    );
    this.name = "MissingApiKeyError";
  }
}

class AnthropicSdkClient implements ClaudeClient {
  readonly provider: AIProvider = "anthropic";
  private client: Anthropic;
  constructor(apiKey: string) {
    this.client = new Anthropic({ apiKey });
  }
  async analyze(req: ClaudeRequest): Promise<string> {
    const msg = await this.client.messages.create({
      model: req.model,
      max_tokens: req.maxTokens ?? 2048,
      temperature: req.temperature ?? 0,
      system: req.system,
      messages: [{ role: "user", content: req.user }],
    });
    const parts: string[] = [];
    for (const block of msg.content) {
      if (block.type === "text") parts.push(block.text);
    }
    return parts.join("");
  }
}

class OpenAICompatibleClient implements ClaudeClient {
  readonly provider: AIProvider;
  private url: string;
  private headers: Record<string, string>;
  constructor(provider: AIProvider, baseUrl: string, apiKey: string | undefined) {
    this.provider = provider;
    this.url = `${baseUrl.replace(/\/$/, "")}/chat/completions`;
    this.headers = { "Content-Type": "application/json" };
    if (apiKey) this.headers["Authorization"] = `Bearer ${apiKey}`;
  }
  async analyze(req: ClaudeRequest): Promise<string> {
    const body = {
      model: req.model,
      temperature: req.temperature ?? 0,
      max_tokens: req.maxTokens ?? 2048,
      messages: [
        { role: "system", content: req.system },
        { role: "user", content: req.user },
      ],
    };
    const res = await fetch(this.url, { method: "POST", headers: this.headers, body: JSON.stringify(body) });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${this.provider} API ${res.status}: ${text.slice(0, 300)}`);
    }
    const json = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return json.choices?.[0]?.message?.content ?? "";
  }
}

class GeminiClient implements ClaudeClient {
  readonly provider: AIProvider = "gemini";
  constructor(private apiKey: string) {}
  async analyze(req: ClaudeRequest): Promise<string> {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(req.model)}:generateContent?key=${this.apiKey}`;
    const body = {
      systemInstruction: { parts: [{ text: req.system }] },
      contents: [{ role: "user", parts: [{ text: req.user }] }],
      generationConfig: { temperature: req.temperature ?? 0, maxOutputTokens: req.maxTokens ?? 2048 },
    };
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`gemini API ${res.status}: ${text.slice(0, 300)}`);
    }
    const json = (await res.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    const parts = json.candidates?.[0]?.content?.parts ?? [];
    return parts.map((p) => p.text ?? "").join("");
  }
}

class OllamaClient implements ClaudeClient {
  readonly provider: AIProvider = "ollama";
  private url: string;
  constructor(baseUrl: string) {
    this.url = `${baseUrl.replace(/\/$/, "")}/api/chat`;
  }
  async analyze(req: ClaudeRequest): Promise<string> {
    const body = {
      model: req.model,
      stream: false,
      options: { temperature: req.temperature ?? 0 },
      messages: [
        { role: "system", content: req.system },
        { role: "user", content: req.user },
      ],
    };
    const res = await fetch(this.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`ollama API ${res.status}: ${text.slice(0, 300)}`);
    }
    const json = (await res.json()) as { message?: { content?: string } };
    return json.message?.content ?? "";
  }
}

export function createClient(cfg: AIConfig): ClaudeClient {
  switch (cfg.provider) {
    case "anthropic":
      if (!cfg.apiKey) throw new MissingApiKeyError("Anthropic provider selected but no API key is set.");
      return new AnthropicSdkClient(cfg.apiKey);
    case "openai":
      if (!cfg.apiKey) throw new MissingApiKeyError("OpenAI provider selected but no API key is set.");
      return new OpenAICompatibleClient("openai", cfg.baseUrl ?? "https://api.openai.com/v1", cfg.apiKey);
    case "groq":
      if (!cfg.apiKey) throw new MissingApiKeyError("Groq provider selected but no API key is set.");
      return new OpenAICompatibleClient("groq", cfg.baseUrl ?? "https://api.groq.com/openai/v1", cfg.apiKey);
    case "gemini":
      if (!cfg.apiKey) throw new MissingApiKeyError("Gemini provider selected but no API key is set.");
      return new GeminiClient(cfg.apiKey);
    case "ollama":
      return new OllamaClient(cfg.baseUrl ?? "http://localhost:11434");
  }
}

let override: ClaudeClient | null = null;
let cachedConfig: AIConfig | null | undefined;

export function setClaudeClient(client: ClaudeClient | null): void {
  override = client;
}

export function resetResolvedConfig(): void {
  cachedConfig = undefined;
}

async function loadConfigFile(): Promise<AIConfig | null> {
  const { readConfig } = await import("./ai-config.js");
  return readConfig();
}

function resolveConfigSync(): AIConfig | null {
  if (cachedConfig !== undefined) return cachedConfig;
  const fromEnv = resolveConfigFromEnv();
  if (fromEnv) {
    cachedConfig = fromEnv;
    return fromEnv;
  }
  cachedConfig = null;
  return null;
}

export async function resolveConfig(): Promise<AIConfig | null> {
  const fromEnv = resolveConfigFromEnv();
  if (fromEnv) return fromEnv;
  return loadConfigFile();
}

export function getClaudeClient(): ClaudeClient {
  if (override) return override;
  const fromEnv = resolveConfigSync();
  if (fromEnv) return createClient(fromEnv);
  throw new MissingApiKeyError();
}

export async function getClaudeClientAsync(): Promise<ClaudeClient> {
  if (override) return override;
  const cfg = await resolveConfig();
  if (cfg) return createClient(cfg);
  throw new MissingApiKeyError();
}

const RECOMMENDED_FOR_DEEP_REASONING: AIProvider[] = ["anthropic", "openai"];

export function warnIfWeakProvider(client: ClaudeClient, tool: string): string | null {
  const provider = client.provider;
  if (!provider) return null;
  if (RECOMMENDED_FOR_DEEP_REASONING.includes(provider)) return null;
  const meta = getProvider(provider);
  if (tool === "scan_auth_logic" || tool === "scan_idor") {
    return `Note: ${meta.name} is configured. For best results on ${tool}, use Anthropic Claude or OpenAI GPT-4o.`;
  }
  return null;
}

export function extractJson<T = unknown>(text: string): T {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed) as T;
  } catch {}
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) {
    try {
      return JSON.parse(fenced[1]) as T;
    } catch {}
  }
  const braced = trimmed.match(/\{[\s\S]*\}/);
  if (braced) {
    try {
      return JSON.parse(braced[0]) as T;
    } catch {}
  }
  throw new Error(`AI response was not valid JSON. First 200 chars:\n${trimmed.slice(0, 200)}`);
}
