import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export type Severity = "critical" | "high" | "medium" | "low";

export interface PatternDef {
  pattern: string;
  severity: Severity;
  description: string;
  category?: string;
  minEntropy?: number;
  allowlist?: string;
}

export interface Finding {
  type: string;
  category?: string;
  severity: Severity;
  description: string;
  line: number;
  column: number;
  match: string;
  redacted: string;
  source: "pattern" | "entropy";
  fix: string;
}

type CompiledPattern = {
  name: string;
  regex: RegExp;
  allowlist?: RegExp;
  def: PatternDef;
};

let compiled: CompiledPattern[] | null = null;

function compilePattern(source: string): { regex: RegExp; flags: string } {
  let flags = "g";
  const inline = source.match(/^\(\?([imsux]+)\)/);
  if (inline) {
    for (const f of inline[1]) if ("ims".includes(f) && !flags.includes(f)) flags += f;
    source = source.slice(inline[0].length);
  }
  return { regex: new RegExp(source, flags), flags };
}

async function loadPatterns(): Promise<CompiledPattern[]> {
  if (compiled) return compiled;
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "../../patterns/secrets.json"),
    join(here, "../patterns/secrets.json"),
  ];
  let raw: string | null = null;
  for (const p of candidates) {
    try {
      raw = await readFile(p, "utf8");
      break;
    } catch {}
  }
  if (!raw) throw new Error("secrets.json pattern file not found");
  const parsed = JSON.parse(raw) as Record<string, PatternDef>;
  compiled = Object.entries(parsed).map(([name, def]) => {
    const { regex } = compilePattern(def.pattern);
    const allowlist = def.allowlist ? compilePattern(def.allowlist).regex : undefined;
    return { name, regex, allowlist, def };
  });
  return compiled;
}

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const len = s.length;
  let h = 0;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

function redact(s: string): string {
  if (s.length <= 8) return "***";
  return s.slice(0, 4) + "***" + s.slice(-2);
}

function lineColFromIndex(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

const PLACEHOLDER_TOKENS = [
  "EXAMPLE",
  "EXAMPLEKEY",
  "PLACEHOLDER",
  "YOUR_",
  "YOURKEY",
  "YOURTOKEN",
  "YOURSECRET",
  "REPLACE_ME",
  "REPLACEME",
  "CHANGEME",
  "INSERT_",
  "XXXXXXXX",
  "FAKEKEY",
  "DUMMYKEY",
  "NOTREAL",
  "SAMPLEKEY",
];

function isPlaceholder(s: string): boolean {
  const upper = s.toUpperCase();
  for (const t of PLACEHOLDER_TOKENS) if (upper.includes(t)) return true;
  // Runs of 6+ identical chars strongly suggest a placeholder.
  if (/(.)\1{5,}/.test(s)) return true;
  return false;
}

function isCommonNonSecret(s: string): boolean {
  // UUID v1-v5
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return true;
  // Git short / full SHA-1 / SHA-256 hex
  if (/^[0-9a-f]{40}$/i.test(s)) return true;
  if (/^[0-9a-f]{64}$/i.test(s)) return true;
  // Locale / path / dotted identifier
  if (/^[a-z]+([/._-][a-z0-9]+)+$/i.test(s) && !/[A-Z]/.test(s)) return true;
  // Pure hex CSS color or short hex number
  if (/^#?[0-9a-f]{3,8}$/i.test(s)) return true;
  return false;
}

function fixSuggestion(type: string, category?: string): string {
  const key = (category ?? "") + ":" + type;
  if (/aws/.test(key)) return "Move to AWS Secrets Manager or an env var (e.g. process.env.AWS_ACCESS_KEY_ID).";
  if (/gcp|google/.test(key)) return "Load from Google Secret Manager or GOOGLE_APPLICATION_CREDENTIALS env var.";
  if (/azure/.test(key)) return "Load from Azure Key Vault or an env var; rotate this credential now.";
  if (/stripe|square|paypal|braintree|shopify|plaid|coinbase|binance/.test(key))
    return "Load payment credentials from the server env only — never ship to client or repo.";
  if (/github|gitlab|bitbucket|azure_devops|gitea/.test(key))
    return "Use a CI secret or env var; rotate this token immediately.";
  if (/openai|anthropic|cohere|huggingface|replicate|perplexity|mistral|ai21|groq/.test(key))
    return "Load from env and rotate the key in the provider dashboard.";
  if (/slack|discord|teams|twilio|vonage|sendgrid|mailgun|mailchimp|postmark|sparkpost/.test(key))
    return "Load from env; rotate any exposed webhook or API credential.";
  if (/datadog|newrelic|pagerduty|sentry|rollbar|logdna|loggly|honeycomb/.test(key))
    return "Rotate the observability token and load it from env in production.";
  if (/private_key|ssh|pgp|ppk/.test(key))
    return "Store keys outside the repo (KMS, Vault, or a secrets manager); rotate now.";
  if (/postgres|mysql|mariadb|mongodb|redis|memcached|elasticsearch|rabbitmq|clickhouse|neon|supabase|planetscale|cockroach|turso|firebase|firestore/.test(key))
    return "Move the connection string to an env var; never commit credentials.";
  if (/jwt/.test(key)) return "JWTs should never be hardcoded; issue them at runtime and store signing keys in env.";
  if (/npm|pypi|rubygems|dockerhub|cargo/.test(key)) return "Use CI publish tokens with minimal scope; rotate this token now.";
  if (/generic_password|generic_secret/.test(key))
    return "Move the secret to an env var (e.g. process.env.SECRET) and rotate the existing value.";
  return "Move the secret to an environment variable and rotate the existing value.";
}

const ENTROPY_THRESHOLD = 4.7;
const ENTROPY_MIN_LEN = 24;
const STRING_LITERAL = /(['"`])([^'"`\\\n]{20,})\1/g;
const ENTROPY_ALLOWLIST = /^(https?:\/\/|[a-z]+[/._-][a-z0-9]+|[0-9a-f-]{36}$|[0-9a-f]{40}$|[0-9a-f]{64}$)/i;
// Real secrets are continuous tokens. Prose is not. This filter alone eliminates
// virtually all entropy false positives on descriptions, prompts, and docstrings.
const TOKEN_SHAPED = /^[A-Za-z0-9_+/=.\-]+$/;

const IGNORE_DIRECTIVES = [
  /ironward[-_:]ignore/i,
  /ironward[-_:]disable[-_:]line/i,
  /aegis[-_:]?mcp[-_:]ignore/i,
  /aegis[-_:]ignore/i,
  /securemcp[-_:]ignore/i,
  /nosecrets/i,
  /secret-scan[-_:]ignore/i,
];

function lineHasIgnoreDirective(content: string, line: number): boolean {
  const lines = content.split("\n");
  const l = lines[line - 1] ?? "";
  const prev = lines[line - 2] ?? "";
  for (const d of IGNORE_DIRECTIVES) if (d.test(l) || d.test(prev)) return true;
  return false;
}

export async function scanText(content: string, _filename = "<input>"): Promise<Finding[]> {
  const patterns = await loadPatterns();
  const findings: Finding[] = [];
  const seenAt = new Map<number, Set<string>>();

  const markSeen = (line: number, type: string) => {
    let s = seenAt.get(line);
    if (!s) {
      s = new Set();
      seenAt.set(line, s);
    }
    s.add(type);
  };

  for (const { name, regex, allowlist, def } of patterns) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(content)) !== null) {
      const match = m[0];
      if (isPlaceholder(match)) continue;
      if (allowlist && allowlist.test(match)) continue;
      if (def.minEntropy !== undefined && shannonEntropy(match) < def.minEntropy) continue;
      const { line, column } = lineColFromIndex(content, m.index);
      if (lineHasIgnoreDirective(content, line)) continue;
      findings.push({
        type: name,
        category: def.category,
        severity: def.severity,
        description: def.description,
        line,
        column,
        match,
        redacted: redact(match),
        source: "pattern",
        fix: fixSuggestion(name, def.category),
      });
      markSeen(line, name);
    }
  }

  STRING_LITERAL.lastIndex = 0;
  let sm: RegExpExecArray | null;
  while ((sm = STRING_LITERAL.exec(content)) !== null) {
    const literal = sm[2];
    if (literal.length < ENTROPY_MIN_LEN) continue;
    if (!TOKEN_SHAPED.test(literal)) continue;
    if (ENTROPY_ALLOWLIST.test(literal)) continue;
    if (isPlaceholder(literal)) continue;
    if (isCommonNonSecret(literal)) continue;
    const hasVariety = /[a-z]/.test(literal) && /[A-Z0-9]/.test(literal);
    if (!hasVariety) continue;
    const h = shannonEntropy(literal);
    if (h < ENTROPY_THRESHOLD) continue;

    const start = sm.index + 1;
    const { line, column } = lineColFromIndex(content, start);
    if (seenAt.has(line) && seenAt.get(line)!.size > 0) continue;
    if (lineHasIgnoreDirective(content, line)) continue;

    findings.push({
      type: "high_entropy_string",
      category: "heuristic",
      severity: "medium",
      description: `High-entropy string literal (H=${h.toFixed(2)}); likely a secret or token`,
      line,
      column,
      match: literal,
      redacted: redact(literal),
      source: "entropy",
      fix: "If this is a secret, move it to an environment variable. If it is not, add `// ironward-ignore` to suppress.",
    });
    markSeen(line, "high_entropy_string");
  }

  findings.sort((a, b) => a.line - b.line || a.column - b.column);
  return findings;
}

export function severityRank(s: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[s];
}
