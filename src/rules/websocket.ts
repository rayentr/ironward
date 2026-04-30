import type { CodeRule } from "../engines/code-rules.js";

export const WEBSOCKET_RULES: CodeRule[] = [
  {
    id: "ws-no-origin-check",
    severity: "high",
    category: "framework" as any,
    confidence: 70,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "WebSocketServer / wss connection handler with no Origin validation",
    // Match `new WebSocketServer(...)` or `wss.on('connection', ...)` followed by a body  // ironward-ignore
    // that never references `origin`. Bounded window keeps regex linear.
    re: /(?:new\s+WebSocketServer\s*\([\s\S]{0,400}?\)|\bwss\s*\.\s*on\s*\(\s*['"`]connection['"`][\s\S]{0,400}?\})/g,
    rationale: "WebSocket upgrades are not bound by the browser same-origin policy. Without an Origin header check on the upgrade request, any cross-origin page can connect and act as the user.",
    fix: "Validate `req.headers.origin` against an allowlist in the `verifyClient` callback (ws) or the upgrade handler before accepting the socket.",
    negativePattern: /\borigin\b/i,
  },
  {
    id: "ws-no-auth-on-connect",
    severity: "high",
    category: "framework" as any,
    confidence: 65,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "wss connection handler attaches message listener with no auth check",
    // `wss.on('connection', (ws, req) => { ws.on('message', ...) })` with no auth-shaped  // ironward-ignore
    // identifier between the connection arrow and the message subscription.
    re: /\bwss\s*\.\s*on\s*\(\s*['"`]connection['"`]\s*,\s*(?:\([^)]*\)|\w+)\s*=>\s*\{[\s\S]{0,300}?\bws\s*\.\s*on\s*\(\s*['"`]message['"`]/g,
    rationale: "Accepting a WebSocket connection and subscribing to messages without verifying the caller means anyone who can reach the server can read/write the channel as an authenticated user.",
    fix: "Authenticate inside the connection handler (cookie session, JWT in upgrade query, or a signed ticket) before binding `message`/`close` listeners. Close the socket on auth failure.",
    negativePattern: /\b(?:auth|token|jwt|verify(?:Token|Jwt|Auth)?|session\.user|requireAuth)\b/i,
  },
  {
    id: "ws-broadcast-includes-user-data",
    severity: "high",
    category: "framework" as any,
    confidence: 70,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "wss.clients.forEach broadcast that embeds user.* fields",
    // `wss.clients.forEach(...)` whose body references `user.` or `req.user`.  // ironward-ignore
    re: /\bwss\s*\.\s*clients\s*\.\s*forEach\s*\([\s\S]{0,300}?(?:\breq\.user\b|\buser\s*\.\s*\w+)/g,
    rationale: "Broadcasting payloads that include another user's fields leaks PII / state to every connected client. Per-recipient filtering is needed.",
    fix: "Iterate `wss.clients` with a per-client authorization check, or maintain rooms/channels keyed by ownership and only `send` to authorized members.",
  },
  {
    id: "ws-message-no-validation",
    severity: "medium",
    category: "framework" as any,
    confidence: 65,
    owasp: "A04:2021 Insecure Design",
    languages: ["javascript", "typescript"],
    title: "ws.on('message') handler calls JSON.parse with no try/catch",
    // `ws.on('message', (data) => { ... JSON.parse(data) ... })` body without `try`.  // ironward-ignore
    re: /\bws\s*\.\s*on\s*\(\s*['"`]message['"`]\s*,\s*(?:\([^)]*\)|\w+)\s*=>\s*\{[\s\S]{0,400}?\bJSON\s*\.\s*parse\s*\([^)]*\)/g,
    rationale: "Untrusted WebSocket payloads frequently arrive malformed. An uncaught JSON.parse throw kills the socket process or skips intended validation, and a missing schema check lets attackers send arbitrary fields downstream.",
    fix: "Wrap JSON.parse in try/catch and validate the parsed object against a schema (Zod / yup) before acting on it.",
    negativePattern: /\btry\s*\{/,
  },
  {
    id: "ws-eval-in-handler",
    severity: "critical",
    category: "framework" as any,
    confidence: 95,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "eval() or new Function() inside a ws.on('message') handler", // ironward-ignore
    // `ws.on('message', ...)` body containing `eval(` or `new Function(`. // ironward-ignore
    re: /\bws\s*\.\s*on\s*\(\s*['"`]message['"`]\s*,[\s\S]{0,400}?(?:\beval\s*\(|\bnew\s+Function\s*\()/g, // ironward-ignore
    rationale: "Passing WebSocket frame contents to eval / new Function is direct remote code execution — the channel is user-controlled by definition.",
    fix: "Remove eval / new Function entirely. Dispatch on a typed message-name field with a static handler map.",
  },
];
