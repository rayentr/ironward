import type { CodeRule } from "../engines/code-rules.js";

export const NODEJS_EXTENDED_RULES: CodeRule[] = [
  {
    id: "node-http-no-timeout",
    severity: "medium",
    category: "nodejs" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "http.createServer / app.listen called without setTimeout",
    re: /(?:http|https)\s*\.\s*createServer\s*\(/g,
    negativePattern: /setTimeout|timeout\s*:/,
    rationale:
      "Node servers default to no socket timeout (or very long ones). Slowloris-style clients can hold connections open forever and exhaust the connection pool.",
    fix: "Call server.setTimeout(30_000) (or similar) on the returned server, and set keepAliveTimeout/headersTimeout explicitly.",
  },
  {
    id: "node-process-exit-in-handler",
    severity: "high",
    category: "nodejs" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "process.exit() inside an Express/Fastify route handler",
    re: /(?:app|router)\s*\.\s*(?:get|post|put|delete)[\s\S]{0,300}?process\s*\.\s*exit\s*\(/g,
    rationale:
      "A handler that can call process.exit() turns any matching request into a single-packet DoS — the worker dies and all in-flight requests fail.",
    fix: "Remove process.exit from request paths. Throw or return an error response and let your error middleware handle it.",
  },
  {
    id: "node-event-emitter-leak",
    severity: "medium",
    category: "nodejs" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "EventEmitter .on() registered inside a loop (listener leak)",
    re: /for\s*\([^)]*\)\s*\{[\s\S]{0,200}?\.\s*on\s*\(/g,
    rationale:
      "Registering listeners in a loop without removeListener leaks memory and trips MaxListenersExceededWarning, eventually crashing the process.",
    fix: "Register the listener once outside the loop, or call .once() / .removeListener() to keep the count bounded.",
  },
  {
    id: "node-stream-no-error-handler",
    severity: "medium",
    category: "nodejs" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "fs.createReadStream without an 'error' handler",
    re: /\bfs\s*\.\s*createReadStream\s*\([^)]*\)/g,
    negativePattern: /\.on\s*\(\s*['"]error['"]/,
    rationale:
      "Unhandled stream errors are emitted as 'uncaughtException' and crash the Node process — a single bad path becomes a DoS.",
    fix: "Chain .on('error', err => ...) on the stream, or use stream.pipeline() which propagates errors safely.",
  },
  {
    id: "node-tar-slip",
    severity: "high",
    category: "nodejs" as any,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "tar/zip extract without path validation (zip-slip)",
    re: /\b(?:tar|adm-zip|extract-zip)\s*\.\s*(?:extract|x)\s*\(/g,
    rationale:
      "Archive entries with names like ../../etc/passwd are written outside the destination directory unless every entry's resolved path is checked.",
    fix: "Validate each entry's resolved path stays under the destination dir (path.resolve + startsWith), or use tar with the strict and onwarn options.",
  },
  {
    id: "node-zip-bomb-no-limit",
    severity: "medium",
    category: "nodejs" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "Archive extract without a maxSize / sizeLimit guard (zip bomb)",
    re: /\b(?:tar|adm-zip|extract-zip)\s*\.\s*(?:extract|x)\s*\(/g,
    negativePattern: /maxSize|sizeLimit/,
    rationale:
      "A 42 KB zip can expand to several GB. Without a size cap, a single upload can fill the disk or exhaust memory.",
    fix: "Stream-extract with a cumulative byte counter and abort once a configured maxSize is exceeded.",
  },
  {
    id: "node-json-pollution-merge",
    severity: "high",
    category: "nodejs" as any,
    owasp: "A08:2021 Software and Data Integrity Failures",
    languages: ["javascript", "typescript"],
    title: "Object.assign({}, JSON.parse(req.body)) — prototype pollution path",  // ironward-ignore
    re: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*JSON\.parse\s*\(\s*req\s*\.\s*body/g,
    rationale:
      "Object.assign copies own enumerable __proto__ keys when the source comes from JSON.parse — combined with later merges this becomes prototype pollution.",
    fix: "Validate the parsed body against a schema (Zod) before any merge. Use Object.create(null) bases, or strip __proto__ / constructor keys.",
  },
  {
    id: "node-buffer-from-unsafe",
    severity: "high",
    category: "nodejs" as any,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "Deprecated new Buffer(string) constructor",  // ironward-ignore
    re: /\bnew\s+Buffer\s*\(\s*[^)]+\)/g,
    rationale:
      "new Buffer(arg) is overloaded: a number allocates uninitialized memory (info leak), a string parses with implicit utf-8. Both behaviors were deprecated in Node 4+.",  // ironward-ignore
    fix: "Use Buffer.from(string [, encoding]) for data and Buffer.alloc(size) for fresh, zero-filled buffers.",
  },
  {
    id: "node-http-response-splitting",
    severity: "high",
    category: "nodejs" as any,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "res.setHeader for Set-Cookie/Location/Refresh fed with request input",
    re: /\bres\s*\.\s*setHeader\s*\(\s*['"](?:Set-Cookie|Location|Refresh)['"]\s*,\s*(?:req|request)\s*\./g,
    rationale:
      "Unsanitized CR/LF in a header value lets an attacker inject extra headers or split the response — cache poisoning, fake redirects, session fixation.",
    fix: "Validate against /^[\\w .,/:=+\\-]+$/ or strip \\r\\n before setHeader. For cookies, use the cookie library which handles encoding.",
  },
  {
    id: "node-meta-refresh-redirect",
    severity: "medium",
    category: "nodejs" as any,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "res.send with <meta http-equiv=\"refresh\"> built from user input",
    re: /\bres\s*\.\s*send\s*\(\s*[`'"][\s\S]{0,200}?<meta\s+http-equiv\s*=\s*\\?["']refresh\\?["'][\s\S]{0,200}?\$\{?\s*(?:req|request)\s*\./gi,
    rationale:
      "Meta-refresh URLs derived from user input are an open-redirect vector that bypasses the same response-header allowlist that res.redirect would hit.",
    fix: "Validate the target against an allowlist (startsWith('/') and not '//'); render a static refresh URL or use res.redirect with a vetted destination.",
  },
];
