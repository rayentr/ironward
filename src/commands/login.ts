import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import {
  type AIConfig,
  type AIProvider,
  PROVIDERS,
  getProvider,
  readConfig,
  writeConfig,
  deleteConfig,
  configPath,
} from "../engines/ai-config.js";
import { createClient } from "../engines/claude-client.js";

const execAsync = promisify(exec);

async function openUrl(url: string): Promise<void> {
  const platform = process.platform;
  const cmd = platform === "darwin" ? `open "${url}"` : platform === "win32" ? `start "" "${url}"` : `xdg-open "${url}"`;
  try {
    await execAsync(cmd);
  } catch {
    // can't open browser — just print the URL
  }
}

async function testAnthropic(apiKey: string, model: string): Promise<void> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 8,
      messages: [{ role: "user", content: "hi" }],
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Anthropic API ${res.status}: ${text.slice(0, 200)}`);
  }
}

async function testOpenAICompat(provider: AIProvider, apiKey: string, model: string, baseUrl: string): Promise<void> {
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      max_tokens: 8,
      messages: [{ role: "user", content: "hi" }],
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${provider} API ${res.status}: ${text.slice(0, 200)}`);
  }
}

async function testGemini(apiKey: string, model: string): Promise<void> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: "hi" }] }],
      generationConfig: { maxOutputTokens: 8 },
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Gemini API ${res.status}: ${text.slice(0, 200)}`);
  }
}

async function testOllama(baseUrl: string, model: string): Promise<void> {
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      stream: false,
      messages: [{ role: "user", content: "hi" }],
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Ollama API ${res.status}: ${text.slice(0, 200)}`);
  }
}

export async function testConnection(cfg: AIConfig): Promise<void> {
  switch (cfg.provider) {
    case "anthropic":
      return testAnthropic(cfg.apiKey!, cfg.model);
    case "openai":
      return testOpenAICompat("openai", cfg.apiKey!, cfg.model, cfg.baseUrl ?? "https://api.openai.com/v1");
    case "groq":
      return testOpenAICompat("groq", cfg.apiKey!, cfg.model, cfg.baseUrl ?? "https://api.groq.com/openai/v1");
    case "gemini":
      return testGemini(cfg.apiKey!, cfg.model);
    case "ollama":
      return testOllama(cfg.baseUrl ?? "http://localhost:11434", cfg.model);
  }
}

async function listOllamaModels(baseUrl: string): Promise<string[]> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/api/tags`);
    if (!res.ok) return [];
    const json = (await res.json()) as { models?: Array<{ name?: string }> };
    return (json.models ?? []).map((m) => m.name ?? "").filter(Boolean);
  } catch {
    return [];
  }
}

export async function runLogin(): Promise<number> {
  const rl = createInterface({ input, output });
  try {
    console.log("\nIronward — pick an AI provider for auth/SQLi/XSS/IDOR scans and auto-fix PRs.\n");
    PROVIDERS.forEach((p, i) => {
      console.log(`  ${i + 1}. ${p.name.padEnd(10)} — ${p.tagline}`);
    });
    console.log(`  ${PROVIDERS.length + 1}. Skip         — use offline tools only (secrets, code, deps, URL)\n`); // ironward-ignore

    const pick = (await rl.question(`Choose a provider [1-${PROVIDERS.length + 1}]: `)).trim();
    const idx = parseInt(pick, 10);
    if (!Number.isFinite(idx) || idx < 1 || idx > PROVIDERS.length + 1) {
      console.log("Invalid choice.");
      return 2;
    }
    if (idx === PROVIDERS.length + 1) {
      console.log("\nNo AI provider configured. Offline tools (scan-secrets, scan-code, scan-deps, scan-url) still work."); // ironward-ignore
      return 0;
    }
    const provider = PROVIDERS[idx - 1];
    let cfg: AIConfig;

    if (provider.id === "ollama") {
      const rawBase = (await rl.question("Ollama base URL [http://localhost:11434]: ")).trim();
      const baseUrl = rawBase || "http://localhost:11434";
      const models = await listOllamaModels(baseUrl);
      if (models.length === 0) {
        console.log(`\nCould not reach Ollama at ${baseUrl}. Is the server running?`);
        console.log("Start it with:  ollama serve");
        return 2;
      }
      console.log("\nAvailable models:");
      models.forEach((m, i) => console.log(`  ${i + 1}. ${m}`));
      const mpick = (await rl.question(`Pick a model [1-${models.length}]: `)).trim();
      const mi = parseInt(mpick, 10);
      if (!Number.isFinite(mi) || mi < 1 || mi > models.length) {
        console.log("Invalid choice.");
        return 2;
      }
      cfg = { provider: "ollama", model: models[mi - 1], baseUrl };
    } else {
      console.log(`\nOpening ${provider.keyUrl} in your browser…`);
      if (provider.keyUrl) await openUrl(provider.keyUrl);
      const apiKey = (await rl.question("Paste your API key: ")).trim();
      if (!apiKey) {
        console.log("No key entered — aborting.");
        return 2;
      }
      const modelAnswer = (await rl.question(`Model [${provider.defaultModel}]: `)).trim();
      cfg = { provider: provider.id, apiKey, model: modelAnswer || provider.defaultModel };
    }

    process.stdout.write("Testing connection... ");
    try {
      await testConnection(cfg);
      console.log("ok.");
    } catch (err) {
      console.log("failed.");
      console.error(`  ${(err as Error).message}`);
      console.error("\nNot saved. Run `ironward login` again to retry.");
      return 2;
    }

    await writeConfig(cfg);
    console.log(`\nSaved to ${configPath()} (chmod 600).`);
    console.log(`Provider: ${provider.name}`);
    console.log(`Model:    ${cfg.model}`);
    console.log("\nAll 13 tools are now available. Run `ironward whoami` to confirm.");
    return 0;
  } finally {
    rl.close();
  }
}

export async function runLogout(): Promise<number> {
  const existed = (await readConfig()) !== null;
  await deleteConfig();
  console.log(existed ? `Removed ${configPath()}.` : "Nothing to remove — no config was saved.");
  return 0;
}

export async function runWhoami(): Promise<number> {
  const cfg = await readConfig();
  if (!cfg) {
    const envProvider = process.env.ANTHROPIC_API_KEY
      ? "anthropic (from ANTHROPIC_API_KEY)"
      : process.env.OPENAI_API_KEY
        ? "openai (from OPENAI_API_KEY)"
        : process.env.GEMINI_API_KEY
          ? "gemini (from GEMINI_API_KEY)"
          : process.env.GROQ_API_KEY
            ? "groq (from GROQ_API_KEY)"
            : null;
    if (envProvider) {
      console.log(`Provider: ${envProvider}`);
      console.log("No saved config at ~/.ironward/config.json — using environment variable.");
      return 0;
    }
    console.log("No AI provider configured.");
    console.log("Run `ironward login` to pick one, or `ironward free` to see what works offline.");
    return 1;
  }
  const meta = getProvider(cfg.provider);
  console.log(`Provider: ${meta.name}`);
  console.log(`Model:    ${cfg.model}`);
  if (cfg.baseUrl) console.log(`Base URL: ${cfg.baseUrl}`);
  console.log(`Config:   ${configPath()}`);
  // Intentionally don't print the API key
  return 0;
}

export async function runFree(): Promise<number> {
  console.log(`
Tools that work WITHOUT any API key (pure offline):

  scan_for_secrets   665 pattern families + Shannon entropy
  scan_code          27 static rules (eval, SSRF, weak crypto, …)
  scan_deps          OSV.dev CVE lookup + typosquat/abandoned/malware checks
  scan_url           security headers, CORS, cookies, exposed paths, TLS

Meta-command:

  ironward scan <dir>     runs secrets + code + deps in one go

Tools that need an AI provider (ironward login):

  scan_auth_logic    reasoning model catches logic bugs patterns can't
  scan_sqli          confirms cross-language SQL injection candidates
  scan_xss           confirms DOM + server-side XSS candidates
  scan_idor          confirms missing ownership checks on routes
  fix_and_pr         generates surgical fix PRs with validation
`);
  return 0;
}
