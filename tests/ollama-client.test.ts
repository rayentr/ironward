import { test } from "node:test";
import assert from "node:assert/strict";
import { OllamaClient, firstRunMessage } from "../src/engines/ollama-client.ts";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function makeFetch(handler: (url: string, init?: RequestInit) => Promise<Response>): typeof fetch {
  return ((input: Request | string | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    return handler(url, init);
  }) as unknown as typeof fetch;
}

test("isAvailable returns true on 200", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () => jsonResponse({ models: [] })),
  });
  assert.equal(await client.isAvailable(), true);
});

test("isAvailable returns false on connection refused", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () => {
      throw new Error("ECONNREFUSED");
    }),
  });
  assert.equal(await client.isAvailable(), false);
});

test("isAvailable returns false on timeout", async () => {
  const client = new OllamaClient({
    timeoutMs: 30,
    fetchImpl: makeFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal as AbortSignal | undefined;
          if (signal) {
            signal.addEventListener("abort", () => reject(new Error("aborted")));
          }
        }),
    ),
  });
  assert.equal(await client.isAvailable(), false);
});

test("listModels returns [] on connection refused", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () => {
      throw new Error("ECONNREFUSED");
    }),
  });
  const models = await client.listModels();
  assert.deepEqual(models, []);
});

test("listModels parses model names from API response", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () =>
      jsonResponse({
        models: [
          { name: "deepseek-coder:6.7b", size: 4_000_000_000, modified_at: "2024-01-01T00:00:00Z" },
          { name: "llama3.2:3b", size: 2_000_000_000 },
        ],
      }),
    ),
  });
  const models = await client.listModels();
  assert.equal(models.length, 2);
  assert.equal(models[0].name, "deepseek-coder:6.7b");
  assert.equal(models[0].size, 4_000_000_000);
  assert.equal(models[0].modifiedAt, "2024-01-01T00:00:00Z");
  assert.equal(models[1].name, "llama3.2:3b");
});

test("getRecommendedModel returns deepseek-coder:33b when only that's installed", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () =>
      jsonResponse({ models: [{ name: "deepseek-coder:33b", size: 1 }] }),
    ),
  });
  const rec = await client.getRecommendedModel();
  assert.equal(rec.model, "deepseek-coder:33b");
  assert.equal(rec.installed, true);
});

test("getRecommendedModel returns deepseek-coder:6.7b default when nothing installed", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () => jsonResponse({ models: [] })),
  });
  const rec = await client.getRecommendedModel();
  assert.equal(rec.model, "deepseek-coder:6.7b");
  assert.equal(rec.installed, false);
});

test("getRecommendedModel follows priority order with multiple installed", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () =>
      jsonResponse({
        models: [
          { name: "mistral:7b-instruct", size: 1 },
          { name: "codellama:34b", size: 1 },
          { name: "llama3.2:3b", size: 1 },
        ],
      }),
    ),
  });
  // deepseek-coder:33b not present, codellama:34b is highest available in priority order
  const rec = await client.getRecommendedModel();
  assert.equal(rec.model, "codellama:34b");
  assert.equal(rec.installed, true);
});

test("analyze POSTs the right body shape", async () => {
  let capturedUrl = "";
  let capturedBody: unknown = null;
  const client = new OllamaClient({
    fetchImpl: makeFetch(async (url, init) => {
      capturedUrl = url;
      capturedBody = JSON.parse((init?.body as string) ?? "{}");
      return jsonResponse({ message: { content: "ok" } });
    }),
  });
  await client.analyze({
    model: "deepseek-coder:6.7b",
    system: "sys",
    user: "usr",
    temperature: 0.2,
  });
  assert.ok(capturedUrl.endsWith("/api/chat"));
  const body = capturedBody as {
    model: string;
    stream: boolean;
    options: { temperature: number };
    messages: Array<{ role: string; content: string }>;
  };
  assert.equal(body.model, "deepseek-coder:6.7b");
  assert.equal(body.stream, false);
  assert.equal(body.options.temperature, 0.2);
  assert.equal(body.messages[0].role, "system");
  assert.equal(body.messages[0].content, "sys");
  assert.equal(body.messages[1].role, "user");
  assert.equal(body.messages[1].content, "usr");
});

test("analyze parses message.content from response", async () => {
  const client = new OllamaClient({
    fetchImpl: makeFetch(async () => jsonResponse({ message: { content: "hello world" } })),
  });
  const out = await client.analyze({ model: "x", system: "s", user: "u" });
  assert.equal(out, "hello world");
});

test("firstRunMessage includes the toolName in the box", () => {
  const msg = firstRunMessage("scan_auth_logic");
  assert.ok(msg.includes("scan_auth_logic"));
  assert.ok(msg.includes("┌─"));
  assert.ok(msg.includes("└─"));
  assert.ok(msg.includes("│"));
});
