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
    | "framework"
    | "nosql"
    | "xxe"
    | "template-injection"
    | "header-injection"
    | "timing-attack"
    | "python"
    | "path-traversal";
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

  // --- Injection: NoSQL ---
  {
    id: "nosql-mongo-where",
    severity: "high",
    category: "nosql",
    title: "MongoDB $where operator fed with request input",
    re: new RegExp(
      `\\$where\\s*:\\s*(?=[\\s\\S]{0,100}?${REQ})`,
      "g",
    ),
    rationale: "Mongo's $where runs arbitrary JavaScript on the server. User input here is code injection.",
    fix: "Replace $where with field operators ($eq, $in, $regex with anchors). Validate inputs with a schema.",
  },
  {
    id: "nosql-mongo-mapreduce",
    severity: "medium",
    category: "nosql",
    title: "MongoDB mapReduce with request input",
    re: new RegExp(
      `\\.\\s*mapReduce\\s*\\((?=[\\s\\S]{0,150}?${REQ})`,
      "g",
    ),
    rationale: "mapReduce runs JS on the server. Attacker-controlled map/reduce functions can exfiltrate data or escape sandboxes.",
    fix: "Use aggregation pipelines ($group, $project) with typed operators instead of mapReduce over user strings.",
  },

  // --- Injection: LDAP ---
  {
    id: "ldap-filter-user-input",
    severity: "high",
    category: "framework",
    title: "LDAP search filter built from request input",
    re: new RegExp(
      "\\b(?:ldapsearch|ldap\\s*\\.\\s*search|LdapClient\\s*\\.\\s*search|ldapClient\\s*\\.\\s*search)\\s*\\(" +
        `(?=[\\s\\S]{0,200}?\`[^\`]*\\$\\{[^}]*${REQ})`,
      "g",
    ),
    rationale: "Interpolating user input into an LDAP filter lets attackers change the filter semantics (e.g. (uid=*)(|(password=*))).",
    fix: "Escape each value with an LDAP-safe escaper (ldapEscape) and assemble the filter from static parts.",
  },

  // --- Injection: XXE ---
  {
    id: "xxe-xml-parser",
    severity: "medium",
    category: "xxe",
    title: "XML parser instantiated without explicit DTD/entity disable",
    re: /\bnew\s+DOMParser\s*\(\s*\)|\blibxmljs\s*\.\s*parseXml(?:String)?\s*\(|\bxml2js\s*(?:\.\s*\w+)?\s*\.\s*parseString\s*\(/g,
    rationale: "Default XML parsers resolve external entities and DTDs — classic XXE lets attackers read local files or SSRF internal hosts.",
    fix: "Pass options that disable DTD/entity expansion (libxmljs: noent:false, noblanks:true, nonet:true; xml2js: explicitDtd:false; or use a DOM parser safer-by-default like fast-xml-parser).",
  },

  // --- Injection: Template ---
  {
    id: "template-jinja-render-string",
    severity: "high",
    category: "template-injection",
    title: "Flask render_template_string with request input",
    re: /\brender_template_string\s*\([^)]*(?:flask\.request|request)\s*\.\s*(?:args|form|values|json|data)/g,
    rationale: "render_template_string compiles the string as a Jinja template — user input becomes SSTI and leads to RCE on Flask.",
    fix: "Use render_template() with a file-backed template, or pass user values as template variables (not the template body).",
  },
  {
    id: "template-handlebars-compile-user",
    severity: "high",
    category: "template-injection",
    title: "Handlebars.compile() with request input",
    re: /\bHandlebars\s*\.\s*compile\s*\([^)]*\breq(?:uest)?\s*\.\s*(?:body|params|query|headers)/g,
    rationale: "Handlebars.compile on a user-controlled template is SSTI. Even without helpers, attackers can leak context variables.",
    fix: "Precompile templates at build time. Treat user input as data passed INTO a compiled template, never as the template source.",
  },
  {
    id: "template-pug-user-input",
    severity: "high",
    category: "template-injection",
    title: "pug.compile / pug.render with request input",
    re: /\bpug\s*\.\s*(?:compile|render)\s*\([^)]*\breq(?:uest)?\s*\.\s*(?:body|params|query|headers)/g,
    rationale: "Pug template source from user input allows arbitrary JS execution on the server via template features.",
    fix: "Load template source from disk only; pass user data via the locals object on render.",
  },

  // --- Injection: Header / Log ---
  {
    id: "header-injection-crlf",
    severity: "medium",
    category: "header-injection",
    title: "res.setHeader / writeHead value from unsanitized request input",
    re: /\bres\s*\.\s*(?:setHeader|writeHead)\s*\([^,)]+,\s*(?:req|request|ctx)\s*\.\s*(?:body|params|query|headers)\s*\.[A-Za-z_$][\w]*/g,
    rationale: "Unescaped CR/LF in a header value splits the response — attacker injects cookies, cache-poisoning hints, or a fake second response.",
    fix: "Validate the value (/^[\\w .,/:=+-]+$/ or allowlist) and reject newlines/carriage returns before calling setHeader.",
  },
  {
    id: "log-injection-user-input",
    severity: "medium",
    category: "logging",
    title: "User input concatenated into log message (log injection)",
    re: /\b(?:console\s*\.\s*(?:log|info|error|warn|debug)|logger\s*\.\s*(?:log|info|error|warn|debug))\s*\([^)]*\+\s*(?:req|request)\s*\.\s*(?:body|params|query|headers)/g,
    rationale: "Unescaped newlines from user input forge fake log entries — attackers plant misleading records or break log parsers.",
    fix: "Pass user fields as structured fields (logger.info({userId}, 'msg')) or sanitize \\r\\n before concatenating.",
  },

  // --- Cryptography ---
  {
    id: "crypto-hardcoded-iv",
    severity: "critical",
    category: "weak-crypto",
    title: "createCipheriv called with a hardcoded IV literal",
    re: /\bcreateCipheriv\s*\(\s*[^,]+,\s*[^,]+,\s*(?:Buffer\s*\.\s*from\s*\(\s*['"][0-9a-fA-F]{16,}['"]|['"][A-Za-z0-9+/=]{16,}['"])/g,
    rationale: "A static IV destroys the semantic security of CBC/CTR/GCM — identical plaintexts encrypt to identical ciphertexts, and for GCM it enables key recovery.",
    fix: "Generate a fresh IV per message with crypto.randomBytes(12) for GCM or 16 for CBC, and prepend it to the ciphertext.",
  },
  {
    id: "crypto-ecb-mode",
    severity: "critical",
    category: "weak-crypto",
    title: "ECB cipher mode in use",
    re: /\bcreateCipher(?:iv)?\s*\(\s*['"](?:aes-(?:128|192|256)-ecb|des-ecb|des-ede-ecb|des-ede3-ecb|bf-ecb|rc2-ecb)['"]/gi,
    rationale: "ECB encrypts identical blocks to identical ciphertexts — the classic ECB penguin. Reveals patterns in plaintext and leaks structure.",
    fix: "Use aes-256-gcm with a unique IV per message. Never ECB for anything but a single block of random data.",
  },
  {
    id: "crypto-rsa-without-oaep",
    severity: "medium",
    category: "weak-crypto",
    title: "RSA encryption using PKCS#1 v1.5 padding",
    re: /\bcrypto\s*\.\s*publicEncrypt\s*\(\s*\{[^}]*padding\s*:\s*crypto\s*\.\s*constants\s*\.\s*RSA_PKCS1_PADDING/g,
    rationale: "PKCS#1 v1.5 is vulnerable to Bleichenbacher-style padding-oracle attacks when the decryption side leaks error modes.",
    fix: "Use RSA_PKCS1_OAEP_PADDING with SHA-256. Better yet, use hybrid encryption (RSA-KEM or ECIES) for real-world payloads.",
  },
  {
    id: "crypto-short-rsa-key",
    severity: "critical",
    category: "weak-crypto",
    title: "RSA key generated with < 2048-bit modulus",
    re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"]rsa['"]\s*,\s*\{[^}]*modulusLength\s*:\s*(?:512|1024)\b/g,
    rationale: "512- and 1024-bit RSA is factorable today (1024 is borderline; 512 is trivially broken).",
    fix: "Use modulusLength: 2048 minimum; 3072+ for anything long-lived. Or switch to Ed25519 with generateKeyPair('ed25519').",
  },
  {
    id: "crypto-short-aes-key",
    severity: "critical",
    category: "weak-crypto",
    title: "AES cipher with undersized key (aes-40 / aes-64)",
    re: /\bcreateCipher(?:iv)?\s*\(\s*['"]aes-(?:40|64)-/gi,
    rationale: "AES is defined for 128/192/256-bit keys. Non-standard short variants are either export-grade crippled or nonexistent in the spec.",
    fix: "Use aes-256-gcm with a 32-byte key from crypto.randomBytes(32).",
  },
  {
    id: "bcrypt-short-salt-rounds",
    severity: "medium",
    category: "weak-crypto",
    title: "bcrypt hash with < 7 salt rounds",
    re: /\bbcrypt\s*\.\s*(?:hash|hashSync)\s*\([^,]+,\s*[1-6]\s*[),]/g,
    rationale: "Low bcrypt work factors (<=6) are trivially brute-forced on modern GPUs.",
    fix: "Use 10-12 rounds minimum in 2026 (bcrypt.hash(pw, 12)). Revisit when hardware changes.",
  },
  {
    id: "scrypt-low-n",
    severity: "medium",
    category: "weak-crypto",
    title: "scrypt N parameter below recommended 2^14",
    re: /\bscrypt(?:Sync)?\s*\([^)]*\{[^}]*\bN\s*:\s*(?:\d{1,4})\b[^}]*\}/g,
    rationale: "N < 16384 is below OWASP's minimum and cheap to brute-force.",
    fix: "Use N: 2**15 (32768) or 2**17 for interactive logins; r: 8, p: 1 as starting points.",
  },

  // --- Authentication ---
  {
    id: "jwt-decode-not-verify",
    severity: "high",
    category: "jwt",
    title: "jwt.decode() used instead of jwt.verify()", // ironward-ignore
    re: /\bjwt\s*\.\s*decode\s*\(/g, // ironward-ignore
    rationale: "jwt.decode does NOT check the signature — any attacker can forge a token and decode returns the forged payload.",
    fix: "Use jwt.verify(token, secret, { algorithms: ['HS256'] }). Only use decode for inspecting unverified metadata (e.g. 'kid' lookup) and then verify.",
  },
  {
    id: "cookie-no-samesite",
    severity: "medium",
    category: "framework",
    title: "res.cookie called with options object missing sameSite",
    re: /\bres\s*\.\s*cookie\s*\(\s*['"][^'"]+['"]\s*,\s*[^,]+\s*,\s*\{(?![^}]*sameSite)[^}]+\}/g,
    rationale: "Without SameSite, the cookie is sent on cross-site requests — CSRF and top-level navigation attacks become trivial.",
    fix: "Add sameSite: 'lax' for login sessions, 'strict' for sensitive flows. Also set httpOnly: true and secure: true.",
  },
  {
    id: "password-in-url-query",
    severity: "medium",
    category: "insecure-protocol",
    title: "Password / secret passed as a URL query parameter",
    re: /[?&](?:password|pwd|secret|api[_-]?key|token)=[^&\s"'`)]+/gi,
    rationale: "URL query parameters are logged by proxies, browsers, and server access logs — long-lived leak.",
    fix: "Send credentials in the Authorization header or a POST body. Never on the query string.",
  },
  {
    id: "basic-auth-over-http",
    severity: "high",
    category: "insecure-protocol",
    title: "HTTP Basic auth over plain http://",
    re: /http:\/\/[^\s"'`]*[?&]auth(?:orization)?=|Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]+/g,
    rationale: "Basic auth is base64, not encryption. Over http:// the credentials are plaintext on the wire.",
    fix: "Switch the endpoint to https://. For public APIs, use bearer tokens with short lifetimes instead of Basic.",
  },
  {
    id: "timing-unsafe-comparison",
    severity: "high",
    category: "timing-attack",
    title: "Secret compared with == / === against request input",
    re: /\b(?:password|token|secret|apiKey|api_key|hmac|signature)\s*(?:===?|!==?)\s*(?:req|request|ctx)\s*\.\s*(?:body|params|query|headers)/gi,
    rationale: "String equality short-circuits on first mismatch — the attacker can measure request time to learn the secret byte-by-byte.",
    fix: "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) after ensuring equal lengths.",
  },
  {
    id: "hmac-no-timing-safe",
    severity: "medium",
    category: "timing-attack",
    title: "HMAC digest compared with == / === (timing attack)",
    re: /\.\s*digest\s*\(\s*['"](?:hex|base64|base64url)?['"]?\s*\)\s*===?\s*/g,
    rationale: "Comparing an HMAC via string equality leaks the digest byte-by-byte via timing.",
    fix: "Compute both digests as Buffers and compare with crypto.timingSafeEqual.",
  },

  // --- Node.js specific ---
  {
    id: "child-process-exec-template",
    severity: "high",
    category: "dangerous-function",
    title: "child_process.exec with a template literal (string interpolation)",
    re: /\bchild_process\s*\.\s*exec\s*\(\s*`[^`]*\$\{/g,
    rationale: "Template-literal interpolation into exec is shell concatenation — command injection if any value is user-controlled.",
    fix: "Use execFile(cmd, [arg1, arg2], cb) with arguments as an array. Never interpolate into a shell string.",
  },
  {
    id: "require-user-input",
    severity: "critical",
    category: "dangerous-function",
    title: "require() called with request input (arbitrary module load)",
    re: /\brequire\s*\(\s*(?:req|request|ctx)\s*\.\s*(?:body|params|query|headers)/g,
    rationale: "Loading a module chosen by the attacker can execute arbitrary code from node_modules or via path traversal.",
    fix: "Map user input to a fixed allowlist of module names and require() the mapped value, not the input.",
  },
  {
    id: "fs-write-user-path",
    severity: "high",
    category: "unsafe-io",
    title: "fs.writeFile / appendFile called with request input as the path",
    re: /\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*(?:req|request|ctx)\s*\.\s*(?:body|params|query|headers)/g,
    rationale: "Writing to a user-controlled path lets attackers overwrite arbitrary files (configs, deploy hooks, .ssh/authorized_keys).",
    fix: "Resolve the path against a safe base dir and assert path.resolve(base, input).startsWith(base + sep).",
  },

  // --- Python-specific ---
  {
    id: "py-pickle-loads-untrusted",
    severity: "critical",
    category: "python",
    title: "pickle.load/loads on untrusted input",
    re: /\bpickle\s*\.\s*loads?\s*\(\s*(?:request\s*\.|flask\s*\.\s*request\s*\.|bytes\s*\()/g,
    rationale: "pickle deserialization of attacker-controlled bytes is direct RCE — __reduce__ runs arbitrary code on load.",
    fix: "Use JSON (json.loads) or a schema validator (pydantic). Never pickle anything that crosses a trust boundary.",
  },
  {
    id: "py-yaml-load-unsafe",
    severity: "critical",
    category: "python",
    title: "yaml.load without SafeLoader",
    re: /\byaml\s*\.\s*load\s*\((?![^)]*Loader\s*=\s*(?:yaml\s*\.\s*)?(?:Safe|CSafe)Loader)/g,
    rationale: "yaml.load with the default FullLoader/UnsafeLoader deserializes Python objects — !!python/object tags are RCE.",
    fix: "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
  },
  {
    id: "py-subprocess-shell-true",
    severity: "high",
    category: "python",
    title: "subprocess call with shell=True",
    re: /\bsubprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
    rationale: "shell=True spawns /bin/sh -c — any concatenated user input becomes command injection.",
    fix: "Pass args as a list and omit shell=True: subprocess.run(['git', 'log', '--', user_path]).",
  },
  {
    id: "py-assert-security-check",
    severity: "medium",
    category: "python",
    title: "assert used for an authorization or security check",
    re: /\bassert\s+(?:request\s*\.|flask\s*\.\s*request\s*\.|self\s*\.\s*is_authenticated|is_admin\b|has_permission\s*\(|current_user\s*\.\s*is_admin)/g,
    rationale: "Python's assert is stripped when code runs with -O (optimize). The security check silently disappears in production.",
    fix: "Replace with an explicit if not ...: raise HTTPException(403) (or framework equivalent).",
  },
  {
    id: "py-django-debug-true",
    severity: "medium",
    category: "python",
    title: "Django DEBUG = True in settings",
    re: /^\s*DEBUG\s*=\s*True\b/gm,
    rationale: "DEBUG=True in Django exposes full stack traces, settings, and the debug error page with source snippets to any visitor.",
    fix: "Set DEBUG = os.environ.get('DJANGO_DEBUG') == '1' and leave it unset in production.",
  },
  {
    id: "py-flask-debug-true",
    severity: "medium",
    category: "python",
    title: "Flask app.run() with debug=True",
    re: /\bapp\s*\.\s*run\s*\([^)]*\bdebug\s*=\s*True/g,
    rationale: "Flask's debug mode exposes the Werkzeug interactive debug UI — attackers can execute Python in the server process.",
    fix: "Never set debug=True in production. Gate on an env var and default to False.",
  },
  {
    id: "py-exec-call",
    severity: "high",
    category: "dangerous-function",
    title: "Python exec() call",
    // Match only Python-style usages: f"..."-strings, request.*, compile(), or
    // the statement-in-a-function pattern typical of Python (`    exec(` on a
    // line of its own). Avoid matching JS's child_process.exec("cmd", ...).
    re: /(?<![A-Za-z0-9_$.])exec\s*\(\s*(?:f['"]|request\s*\.|flask\s*\.\s*request\s*\.|compile\s*\()/g,
    rationale: "Python's exec() compiles and runs a string as code. Anything user-controlled reaching it is RCE.",
    fix: "Remove exec(). Use a dispatch dict mapping names to functions, or ast.literal_eval for data.",
  },

  // --- Info leaks ---
  {
    id: "source-map-reference-in-prod",
    severity: "low",
    category: "debug-leak",
    title: "Source map reference in a minified bundle",
    re: /\/\/#\s*sourceMappingURL\s*=\s*[^\s]+\.map/g,
    rationale: "Shipping sourceMappingURL in production exposes original source, comments, and module structure to anyone with devtools.",
    fix: "Strip the comment for production builds (terser: sourceMap: { url: 'inline' } is also wrong). Host maps only for your error tracker behind auth.",
  },
  {
    id: "stack-trace-in-response",
    severity: "medium",
    category: "debug-leak",
    title: "Stack trace sent to client in HTTP response",
    re: /\bres\s*\.\s*(?:send|json)\s*\([^)]*\berr(?:or)?\s*\.\s*stack\b|\bres\s*\.\s*status\s*\(\s*\d+\s*\)\s*\.\s*(?:send|json)\s*\([^)]*\berr(?:or)?\s*\.\s*stack\b/g,
    rationale: "Stack traces leak file paths, dependency versions, and occasionally secrets pulled into error messages.",
    fix: "Log err.stack server-side. Send the client a generic 500 with a correlation id; no stack.",
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
