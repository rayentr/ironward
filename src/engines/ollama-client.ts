import type { ClaudeRequest, ClaudeClient } from "./claude-client.js";
import type { AIProvider } from "./ai-config.js";

export interface OllamaModel {
  name: string;
  size: number;
  modifiedAt?: string;
}

export interface OllamaClientOpts {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const DEFAULT_BASE_URL = "http://localhost:11434";
const DEFAULT_TIMEOUT_MS = 30_000;

const PRIORITY_MODELS: readonly string[] = [
  "deepseek-coder:33b",
  "codellama:34b",
  "llama3.1:70b",
  "mistral:7b-instruct",
  "llama3.2:3b",
];

const RECOMMENDED_DEFAULT = "deepseek-coder:6.7b";

interface OllamaTagsResponse {
  models?: Array<{ name?: string; size?: number; modified_at?: string }>;
}

interface OllamaChatResponse {
  message?: { content?: string };
  error?: string;
}

export class OllamaClient implements ClaudeClient {
  readonly provider: AIProvider = "ollama";
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: OllamaClientOpts = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private async request(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const res = await this.request("/api/tags", { method: "GET" });
      return res.ok;
    } catch {
      return false;
    }
  }

  async listModels(): Promise<OllamaModel[]> {
    try {
      const res = await this.request("/api/tags", { method: "GET" });
      if (!res.ok) return [];
      const json = (await res.json()) as OllamaTagsResponse;
      const models = json.models ?? [];
      return models
        .filter((m) => typeof m.name === "string" && m.name.length > 0)
        .map((m) => ({
          name: m.name as string,
          size: typeof m.size === "number" ? m.size : 0,
          modifiedAt: m.modified_at,
        }));
    } catch {
      return [];
    }
  }

  async pullModel(name: string): Promise<void> {
    const res = await this.request("/api/pull", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`ollama pull ${res.status}: ${text.slice(0, 300)}`);
    }
    const body = await res.text();
    const lines = body.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line) as { error?: string };
        if (obj.error) {
          throw new Error(`ollama pull error: ${obj.error}`);
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith("ollama pull error:")) {
          throw err;
        }
      }
    }
  }

  async getRecommendedModel(): Promise<{ model: string; installed: boolean }> {
    const installed = await this.listModels();
    const installedNames = new Set(installed.map((m) => m.name));
    for (const candidate of PRIORITY_MODELS) {
      if (installedNames.has(candidate)) {
        return { model: candidate, installed: true };
      }
    }
    return { model: RECOMMENDED_DEFAULT, installed: installedNames.has(RECOMMENDED_DEFAULT) };
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
    const res = await this.request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`ollama API ${res.status}: ${text.slice(0, 300)}`);
    }
    const json = (await res.json()) as OllamaChatResponse;
    return json.message?.content ?? "";
  }
}

export function firstRunMessage(toolName: string): string {
  const lines = [
    "  ┌─────────────────────────────────────────┐",
    `  │  ${toolName} needs an AI model           │`,
    "  │                                         │",
    "  │  Option A — Free, instant (cloud):      │",
    "  │  ironward login                         │",
    "  │  → Anthropic, OpenAI, Gemini, or Groq   │",
    "  │                                         │",
    "  │  Option B — Free, private (local):      │",
    "  │  1. Install Ollama: ollama.com          │",
    "  │  2. ollama pull deepseek-coder:6.7b     │",
    `  │  3. ${toolName} (retry)                  │`,
    "  │                                         │",
    "  │  Local models: no API key, no cloud,    │",
    "  │  your code never leaves your machine.   │",
    "  └─────────────────────────────────────────┘",
  ];
  return lines.join("\n");
}
