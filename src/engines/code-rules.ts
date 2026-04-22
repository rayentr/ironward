export type CodeSeverity = "critical" | "high" | "medium" | "low";

export interface CodeRule {
  id: string;
  severity: CodeSeverity;
  category:
    | "dangerous-function"
    | "weak-crypto"
    | "unsafe-io"
    | "insecure-protocol"
    | "debug-leak"
    | "logging"
    | "prototype-pollution"
    | "open-redirect"
    | "ssrf"
    | "cors"
    | "jwt"
    | "rate-limit"
    | "framework";
  title: string;
  re: RegExp;
  rationale: string;
  fix: string;
}

const REQ = "(?:req|request|ctx|event|_req|args)\\.(?:body|params|query|headers)";

export const CODE_RULES: CodeRule[] = [
  {
    id: "eval-call",
    severity: "critical",
    category: "dangerous-function",
    title: "eval() call", // ironward-ignore
    re: /(?<![A-Za-z0-9_$])eval\s*\(/g, // ironward-ignore
    rationale: "eval executes arbitrary code. If any argument flows from user input, this is RCE.",
    fix: "Remove eval. Parse data explicitly (JSON.parse on a validated string) or use a safe sandbox.",
  },
  {
    id: "new-function-constructor",
    severity: "critical",
    category: "dangerous-function",
    title: "new Function() constructor", // ironward-ignore
    re: /\bnew\s+Function\s*\(/g, // ironward-ignore
    rationale: "new Function(...) is eval in disguise — it compiles its arguments as code.",
    fix: "Replace with a lookup table, predicate, or template engine that doesn't compile strings.",
  },
  {
    id: "child-process-user-input",
    severity: "critical",
    category: "dangerous-function",
    title: "child_process exec/spawn with request input",
    re: new RegExp(
      `\\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\\s*\\((?=[\\s\\S]{0,200}?${REQ})`,
      "g",
    ),
    rationale: "User input flowing into exec/spawn is command injection unless shell: false and args are an array of safe values.",
    fix: "Use execFile with an array of args, validate inputs against an allowlist, or avoid shelling out entirely.",
  },
  {
    id: "path-join-user-input",
    severity: "high",
    category: "unsafe-io",
    title: "path.join / path.resolve with request input (path traversal risk)",
    re: new RegExp(
      `\\bpath\\s*\\.\\s*(?:join|resolve)\\s*\\((?=[\\s\\S]{0,200}?${REQ})`,
      "g",
    ),
    rationale: "Concatenating user input into file paths enables directory traversal (../../etc/passwd).",
    fix: "Normalize the path and assert it starts with an allowed base directory before reading.",
  },
  {
    id: "fs-read-user-input",
    severity: "high",
    category: "unsafe-io",
    title: "fs.read* called with request input",
    re: new RegExp(
      `\\bfs\\s*\\.\\s*(?:readFile|readFileSync|createReadStream|open)\\s*\\((?=[\\s\\S]{0,200}?${REQ})`,
      "g",
    ),
    rationale: "Reading files from user-controlled paths leaks arbitrary file contents.",
    fix: "Resolve the path to a safe base dir and ensure the resolved path stays within it (path.resolve + startsWith check).",
  },
  {
    id: "math-random-secret",
    severity: "high",
    category: "weak-crypto",
    title: "Math.random() used where a secret / token / id is expected",
    re: /\b(?:token|id|secret|key|salt|nonce|uuid|otp|password|sessionId|resetCode|verificationCode)\b[^;\n]{0,120}Math\.random\s*\(\s*\)/gi,
    rationale: "Math.random is not a CSPRNG. Tokens, session IDs, password reset codes etc. must be unguessable.",
    fix: "Use crypto.randomBytes / crypto.randomUUID / crypto.getRandomValues.",
  },
  {
    id: "md5-hash",
    severity: "medium",
    category: "weak-crypto",
    title: "MD5 hash usage",
    re: /createHash\s*\(\s*['"]md5['"]\s*\)|(?<![A-Za-z0-9_$])md5\s*\(/gi,
    rationale: "MD5 is cryptographically broken (collisions, preimage weakness). Not safe for signatures or integrity.",
    fix: "Use SHA-256 or better. For passwords, use bcrypt/argon2 (not plain SHA).",
  },
  {
    id: "sha1-hash",
    severity: "medium",
    category: "weak-crypto",
    title: "SHA-1 hash usage",
    re: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    rationale: "SHA-1 is deprecated; practical collisions exist. Not safe for new applications.",
    fix: "Use SHA-256 or SHA-3.",
  },
  {
    id: "des-cipher",
    severity: "high",
    category: "weak-crypto",
    title: "DES / 3DES cipher usage",
    re: /createCipher(?:iv)?\s*\(\s*['"](?:des|3des|des-ede|desx)[^'"]*['"]/gi,
    rationale: "DES has a 56-bit effective key, 3DES is deprecated. Not acceptable for new encryption.",
    fix: "Use aes-256-gcm with a unique IV per message and authenticated encryption.",
  },
  {
    id: "rc4-cipher",
    severity: "high",
    category: "weak-crypto",
    title: "RC4 cipher usage",
    re: /createCipher(?:iv)?\s*\(\s*['"]rc4[^'"]*['"]/gi,
    rationale: "RC4 has known biases and is considered broken.",
    fix: "Use aes-256-gcm.",
  },
  {
    id: "insecure-http-fetch",
    severity: "medium",
    category: "insecure-protocol",
    title: "HTTP URL in fetch/axios (use HTTPS)",
    re: /\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)|got|request)\s*\(\s*['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^'"`\s]+/g,
    rationale: "Plain HTTP leaks request contents to any on-path observer and allows MITM.",
    fix: "Use https://. If an endpoint forces HTTP, talk to the provider before shipping.",
  },
  {
    id: "console-log-secret",
    severity: "medium",
    category: "logging",
    title: "Secret-named variable in console.log / console.info / console.debug",
    // Only match when the sensitive term is used as an identifier — `obj.password`,
    // shorthand `{ password }`, or passed as an arg `foo,`/`foo)` — NOT when it
    // appears inside a prose string like "no secrets provided".
    re: /\bconsole\s*\.\s*(?:log|info|debug|warn|error)\s*\([^)]*(?:\.(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|credential)\b|[{,]\s*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|credential)\w*\s*[,)}]|\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|credential)\w*\s*[,)])/gi,
    rationale: "Logging secrets persists them to server logs, log aggregators, and often cloud monitoring — a common breach vector.",
    fix: "Redact the value or remove the log. Log only an identifier or a short prefix.",
  },
  {
    id: "commented-secret",
    severity: "high",
    category: "logging",
    title: "Commented-out assignment that looks like a secret",
    re: /(?:\/\/|#)\s*(?:[A-Z][A-Z0-9_]{2,}|[a-z_]+_key|[a-z_]+_secret|[a-z_]+_token)\s*=\s*['"]?[A-Za-z0-9_+/=\-]{16,}/g,
    rationale: "Secrets live in git history forever — even if commented out at the time of commit.",
    fix: "Rotate the value and delete the comment. git filter-repo the history if the commit is still local.",
  },
  {
    id: "debugger-statement", // ironward-ignore
    severity: "medium",
    category: "debug-leak",
    title: "Stray `debugger;` statement", // ironward-ignore
    re: /(?<![A-Za-z0-9_$])debugger\s*;?/g, // ironward-ignore
    rationale: "`debugger` halts execution when devtools are open, can leak timing info, and has no place in production builds.", // ironward-ignore
    fix: "Remove. If you need conditional breakpoints in dev, gate behind process.env.NODE_ENV !== 'production'.", // ironward-ignore
  },
  {
    id: "todo-security",
    severity: "low",
    category: "debug-leak",
    title: "TODO/FIXME mentioning an unfinished security control", // ironward-ignore
    re: /(?:TODO|FIXME|XXX|HACK)\b[^\n]*?\b(?:auth|secur|validat|sanitiz|escap|permission|admin|rate[- ]?limit|csrf)\b/gi,
    rationale: "Unfinished security work shipped to production is the single most common regression.",
    fix: "Resolve before merging, or move to an issue with a due date and remove the TODO.",
  },
  {
    id: "prototype-pollution-merge",
    severity: "high",
    category: "prototype-pollution",
    title: "Deep-merge of request body into an object (prototype pollution)",
    re: new RegExp(
      `\\b(?:merge|deepMerge|_\\.merge|lodash\\.merge|\\$\\.extend|Object\\.assign|defaultsDeep)\\s*\\((?=[\\s\\S]{0,150}?${REQ})`,
      "g",
    ),
    rationale: "Attacker posts {\"__proto__\": {\"isAdmin\": true}} — deep-merge walks into Object.prototype and every object in the process inherits the flag.",
    fix: "Validate the body against a schema (Zod/Joi) BEFORE merging; or use a merge function that blocks __proto__/constructor keys.",
  },
  {
    id: "open-redirect",
    severity: "high",
    category: "open-redirect",
    title: "Open redirect: res.redirect(req.body/query/params.x)",
    re: new RegExp(
      `\\b(?:res|reply|ctx)\\s*\\.\\s*redirect\\s*\\(\\s*${REQ}\\.[A-Za-z_$][\\w]*`,
      "g",
    ),
    rationale: "Attackers craft links that look like your domain but bounce to a phishing page.",
    fix: "Validate the target against an allowlist of internal paths (startsWith('/') and not '//').",
  },
  {
    id: "ssrf-fetch",
    severity: "critical",
    category: "ssrf",
    title: "Server-Side Request Forgery: fetch/axios with request input",
    re: new RegExp(
      `\\b(?:fetch|axios\\.(?:get|post|put|patch|delete|request)|got|http\\.get|https\\.get|request)\\s*\\(\\s*${REQ}\\.[A-Za-z_$][\\w]*\\s*[,)]`,
      "g",
    ),
    rationale: "The attacker controls where your server makes outgoing requests — they can hit internal services (169.254.169.254 AWS metadata, localhost:6379 Redis) and exfiltrate creds.",
    fix: "Resolve the URL, validate host against an allowlist, block private CIDR ranges, disable redirects or validate each hop.",
  },
  {
    id: "cors-wildcard-literal",
    severity: "medium",
    category: "cors",
    title: "CORS origin: '*' in code",
    re: /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*['"]\*['"]/g,
    rationale: "Wildcard CORS on an authenticated API lets any site issue requests with the user's session.",
    fix: "Set origin to an explicit allowlist. If you need permissive CORS, remove credentials.",
  },
  {
    id: "cors-reflect-origin",
    severity: "high",
    category: "cors",
    title: "CORS echoes request Origin back without validation",
    re: /res\s*\.\s*(?:set|header)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*req\.headers\.origin/g,
    rationale: "Reflecting any origin defeats CORS entirely — combined with credentials it becomes a single-request account takeover.",
    fix: "Check req.headers.origin against an allowlist and only echo it back if it's in the list.",
  },
  {
    id: "jwt-hardcoded-weak-secret",
    severity: "critical",
    category: "jwt",
    title: "jwt.sign/verify with a weak hardcoded secret",
    re: /\bjwt\s*\.\s*(?:sign|verify)\s*\([^,)]+,\s*['"](?:secret|password|test|changeme|admin|123456|supersecret|jwt-secret|my-secret|ironward)['"]/gi,
    rationale: "A guessable JWT signing secret lets any attacker forge tokens for any user.",
    fix: "Read from process.env.JWT_SECRET; require it to be 32+ bytes of entropy at boot.",
  },
  {
    id: "jwt-alg-none",
    severity: "critical",
    category: "jwt",
    title: "JWT `alg: 'none'` accepted", // ironward-ignore
    re: /\balg\s*:\s*['"]none['"]/gi, // ironward-ignore
    rationale: "'none' means no signature. Any attacker can forge tokens.",
    fix: "Never allow alg=none. Pin an explicit algorithm (e.g. RS256) in the verify options.",
  },
  {
    id: "sql-string-concat",
    severity: "critical",
    category: "framework",
    title: "SQL built with string concatenation and request input",
    re: new RegExp(
      `["'\`][^"'\`\\n]*\\b(?:SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\b[^"'\`\\n]*["'\`]\\s*\\+\\s*${REQ}`,
      "gi",
    ),
    rationale: "Concatenating request values into SQL is classic injection. Parameters are bound, not strings.",
    fix: "Use parameterized queries: db.query('SELECT * FROM t WHERE id = $1', [id]).",
  },
  {
    id: "express-disable-helmet-pattern",
    severity: "medium",
    category: "framework",
    title: "Express app without helmet() security middleware",
    re: /\b(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)\s*;?(?![\s\S]{0,1500}?\bhelmet\s*\()/g,
    rationale: "Helmet sets a dozen security headers (CSP, HSTS, X-Frame-Options, …). Without it, defaults are unsafe.",
    fix: "import helmet from 'helmet'; app.use(helmet());",
  },
  {
    id: "no-rate-limit-on-auth",
    severity: "high",
    category: "rate-limit",
    title: "Auth route without rate-limiting middleware",
    re: /\b(?:app|router)\s*\.\s*(?:post|put)\s*\(\s*['"`]\/(?:login|signin|signup|register|forgot(?:[-_]?password)?|reset(?:[-_]?password)?|auth(?:\/[a-z]+)?)['"`]\s*,\s*(?![\s\S]{0,120}?(?:rateLimit|limiter|rate[-_]?limit|throttle|slowDown))/gi,
    rationale: "Login/register/reset endpoints without throttling are the #1 target for credential stuffing.",
    fix: "Add an express-rate-limit (or similar) middleware keyed by IP and/or email.",
  },
  {
    id: "setuid-setgid-call",
    severity: "medium",
    category: "dangerous-function",
    title: "process.setuid / setgid",
    re: /\bprocess\s*\.\s*set(?:uid|gid|groups)\s*\(/g,
    rationale: "Dropping privileges is fine; raising them is dangerous. Either way, non-obvious and should be reviewed.",
    fix: "Audit the call site. Prefer running the process as the right user from the start (systemd User=, Docker USER).",
  },
  {
    id: "insecure-random-jwt-secret",
    severity: "high",
    category: "weak-crypto",
    title: "JWT signing secret derived from Math.random or Date.now",
    re: /(?:JWT|jwt)[_-]?(?:secret|key)\s*=\s*(?:Math\.random|Date\.now)\s*\(/g,
    rationale: "Predictable signing secrets defeat JWT entirely.",
    fix: "Generate the secret once with openssl rand -base64 64 and read it from env.",
  },
];

export interface CodeFinding {
  ruleId: string;
  severity: CodeSeverity;
  category: CodeRule["category"];
  title: string;
  line: number;
  column: number;
  snippet: string;
  rationale: string;
  fix: string;
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

function truncate(s: string, n = 160): string {
  const oneline = s.replace(/\s+/g, " ").trim();
  return oneline.length <= n ? oneline : oneline.slice(0, n - 1) + "…";
}

const IGNORE_DIRECTIVE = /(?:ironward|securemcp|aegis)[-_:]?ignore/i;

export function scanCodeRules(content: string): CodeFinding[] {
  const findings: CodeFinding[] = [];
  const seen = new Set<string>();
  const lines = content.split("\n");

  const hasIgnoreOn = (line: number): boolean => {
    const l = lines[line - 1] ?? "";
    const prev = lines[line - 2] ?? "";
    return IGNORE_DIRECTIVE.test(l) || IGNORE_DIRECTIVE.test(prev);
  };

  for (const rule of CODE_RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(content)) !== null) {
      const { line, column } = lineColFromIndex(content, m.index);
      const key = `${rule.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (hasIgnoreOn(line)) continue;
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        category: rule.category,
        title: rule.title,
        line,
        column,
        snippet: truncate(m[0]),
        rationale: rule.rationale,
        fix: rule.fix,
      });
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
  }
  findings.sort(
    (a, b) => a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId),
  );
  return findings;
}

export function severityRank(s: CodeSeverity): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[s];
}
