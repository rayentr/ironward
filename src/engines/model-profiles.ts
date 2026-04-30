import type { AIProvider } from "./ai-config.js";

export type ModelTier = "opus" | "sonnet" | "haiku";
export type PromptStyle = "verbose" | "concise" | "structured";
export type JsonReliability = "high" | "medium" | "low";

export interface ModelProfile {
  id: string;
  provider: AIProvider;
  contextWindow: number;
  tier: ModelTier;
  strengths: string[];
  promptStyle: PromptStyle;
  jsonReliability: JsonReliability;
  maxCodeLength: number;
}

export const MODEL_PROFILES: readonly ModelProfile[] = [
  {
    id: "claude-opus-4-5",
    provider: "anthropic",
    contextWindow: 200_000,
    tier: "opus",
    strengths: ["deep reasoning", "auth logic", "IDOR", "nuanced findings"],
    promptStyle: "verbose",
    jsonReliability: "high",
    maxCodeLength: 50_000,
  },
  {
    id: "claude-sonnet-4-6",
    provider: "anthropic",
    contextWindow: 200_000,
    tier: "sonnet",
    strengths: ["balanced", "fast", "structured output"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  {
    id: "claude-haiku-4-5",
    provider: "anthropic",
    contextWindow: 200_000,
    tier: "haiku",
    strengths: ["fast", "cheap", "simple checks"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 15_000,
  },
  {
    id: "gpt-4o",
    provider: "openai",
    contextWindow: 128_000,
    tier: "opus",
    strengths: ["general reasoning", "function-call JSON"],
    promptStyle: "verbose",
    jsonReliability: "high",
    maxCodeLength: 50_000,
  },
  {
    id: "gpt-4o-mini",
    provider: "openai",
    contextWindow: 128_000,
    tier: "sonnet",
    strengths: ["fast", "cheap"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  {
    id: "gemini-2.5-pro",
    provider: "gemini",
    contextWindow: 1_000_000,
    tier: "opus",
    strengths: ["huge context", "XSS", "SQLi"],
    promptStyle: "verbose",
    jsonReliability: "high",
    maxCodeLength: 50_000,
  },
  {
    id: "gemini-2.5-flash",
    provider: "gemini",
    contextWindow: 1_000_000,
    tier: "sonnet",
    strengths: ["huge context", "fast"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  {
    id: "llama-3.3-70b-versatile",
    provider: "groq",
    contextWindow: 128_000,
    tier: "sonnet",
    strengths: ["fast inference", "cheap"],
    promptStyle: "structured",
    jsonReliability: "medium",
    maxCodeLength: 30_000,
  },
  {
    id: "deepseek-coder:33b",
    provider: "ollama",
    contextWindow: 16_000,
    tier: "sonnet",
    strengths: ["code understanding", "local"],
    promptStyle: "concise",
    jsonReliability: "medium",
    maxCodeLength: 8_000,
  },
  {
    id: "deepseek-coder:6.7b",
    provider: "ollama",
    contextWindow: 16_000,
    tier: "haiku",
    strengths: ["lightweight code", "local"],
    promptStyle: "structured",
    jsonReliability: "medium",
    maxCodeLength: 6_000,
  },
  {
    id: "codellama:34b",
    provider: "ollama",
    contextWindow: 16_000,
    tier: "sonnet",
    strengths: ["code", "local"],
    promptStyle: "concise",
    jsonReliability: "medium",
    maxCodeLength: 8_000,
  },
  {
    id: "llama3.1:70b",
    provider: "ollama",
    contextWindow: 8_000,
    tier: "sonnet",
    strengths: ["general", "local"],
    promptStyle: "concise",
    jsonReliability: "medium",
    maxCodeLength: 6_000,
  },
  {
    id: "mistral:7b-instruct",
    provider: "ollama",
    contextWindow: 8_000,
    tier: "haiku",
    strengths: ["small", "local"],
    promptStyle: "structured",
    jsonReliability: "low",
    maxCodeLength: 4_000,
  },
  {
    id: "llama3.2:3b",
    provider: "ollama",
    contextWindow: 4_000,
    tier: "haiku",
    strengths: ["tiny", "local"],
    promptStyle: "structured",
    jsonReliability: "low",
    maxCodeLength: 2_000,
  },
];

const FALLBACKS: Record<AIProvider, ModelProfile> = {
  anthropic: {
    id: "anthropic-default",
    provider: "anthropic",
    contextWindow: 200_000,
    tier: "sonnet",
    strengths: ["balanced"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  openai: {
    id: "openai-default",
    provider: "openai",
    contextWindow: 128_000,
    tier: "sonnet",
    strengths: ["balanced"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  gemini: {
    id: "gemini-default",
    provider: "gemini",
    contextWindow: 1_000_000,
    tier: "sonnet",
    strengths: ["huge context"],
    promptStyle: "concise",
    jsonReliability: "high",
    maxCodeLength: 30_000,
  },
  groq: {
    id: "groq-default",
    provider: "groq",
    contextWindow: 128_000,
    tier: "sonnet",
    strengths: ["fast"],
    promptStyle: "structured",
    jsonReliability: "medium",
    maxCodeLength: 30_000,
  },
  ollama: {
    id: "ollama-default",
    provider: "ollama",
    contextWindow: 8_000,
    tier: "haiku",
    strengths: ["local"],
    promptStyle: "structured",
    jsonReliability: "low",
    maxCodeLength: 4_000,
  },
};

export function getModelProfile(provider: AIProvider, modelId: string): ModelProfile {
  const exact = MODEL_PROFILES.find((p) => p.provider === provider && p.id === modelId);
  if (exact) return exact;
  const fallback = FALLBACKS[provider];
  return { ...fallback, id: modelId || fallback.id };
}

export function truncateCodeForModel(code: string, profile: ModelProfile): string {
  if (code.length <= profile.maxCodeLength) return code;
  const head = code.slice(0, profile.maxCodeLength);
  return `// [truncated by ironward — model ${profile.id} max ${profile.maxCodeLength} chars]\n${head}\n// [end truncation]`;
}
