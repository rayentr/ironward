import type { CodeRule } from "../engines/code-rules.js";

export const REACT_RULES: CodeRule[] = [
  {
    id: "react-usestate-password",
    severity: "medium",
    category: "react",
    confidence: 65,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "useState holds a password value", // ironward-ignore
    re: /useState\s*[<(][^)>]*\)\s*;?\s*\/\/[^\n]*\b(?:password|secret|jwt|apiKey|token)\b/gi, // ironward-ignore
    rationale: "Sensitive values held in component state can be exposed via React DevTools, error boundaries, or accidentally serialized into props.",
    fix: "Hold sensitive values only as long as needed and clear them on unmount. Avoid storing them in component state if possible.",
  },
  {
    id: "react-usestate-named-secret",
    severity: "medium",
    category: "react",
    confidence: 70,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "useState variable named password / token / secret / apiKey / jwt", // ironward-ignore
    re: /const\s+\[\s*(?:password|token|secret|apiKey|jwt)\s*,/gi, // ironward-ignore
    rationale: "Storing credentials in client-side state risks exposure via DevTools, source maps, or component serialization.",
    fix: "Submit credentials directly via fetch and discard. Never persist them in long-lived component state.",
  },
  {
    id: "react-localstorage-token",
    severity: "high",
    category: "react",
    confidence: 85,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "localStorage.setItem with token / jwt / session / auth / refresh key",
    re: /localStorage\.setItem\s*\(\s*['"`](?:token|jwt|session|auth|refresh)\w*['"`]/gi, // ironward-ignore
    rationale: "Tokens in localStorage are accessible to any XSS payload on the page. Use httpOnly cookies instead.",
    fix: "Set the token via a Set-Cookie header with httpOnly, secure, and SameSite=strict.",
  },
  {
    id: "react-sessionstorage-token",
    severity: "high",
    category: "react",
    confidence: 80,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "sessionStorage.setItem with token / jwt / session / auth / refresh key",
    re: /sessionStorage\.setItem\s*\(\s*['"`](?:token|jwt|session|auth|refresh)\w*['"`]/gi, // ironward-ignore
    rationale: "sessionStorage is also reachable by any script in the page, including XSS payloads.",
    fix: "Use httpOnly cookies for credentials.",
  },
  {
    id: "react-dangerously-set-no-dompurify",
    severity: "critical",
    category: "react",
    confidence: 75,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "dangerouslySetInnerHTML without DOMPurify sanitization",
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!\s*DOMPurify\.sanitize|sanitize)[^}]+\}\s*\}/g,
    rationale: "Injecting unsanitized HTML enables XSS via stored or reflected payloads.",
    fix: "Wrap the value in DOMPurify.sanitize() — or render as text via React's normal JSX.",
  },
  {
    id: "react-link-href-user-url",
    severity: "high",
    category: "react",
    confidence: 65,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "<a href={user.url}> / href from request data — open redirect risk",  // ironward-ignore
    re: /href\s*=\s*\{\s*(?:user\.url|user\.website|(?:req|request|params|searchParams)\.[\w.]+)\s*\}/g,
    rationale: "User-controlled URLs in href can be javascript: URIs (XSS) or external phishing destinations (open redirect).",
    fix: "Validate the URL against http(s) and an allowlist of hosts before rendering.",
  },
  {
    id: "react-useeffect-fetch-user-input",
    severity: "high",
    category: "react",
    confidence: 60,
    owasp: "A10:2021 Server-Side Request Forgery (SSRF)",
    languages: ["javascript", "typescript"],
    title: "useEffect fetch(userInput) without sanitization",
    re: /useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[\s\S]{0,400}fetch\s*\(\s*(?:user\.url|input|search|query|searchParams)/g,
    rationale: "Calling fetch with a raw user-supplied URL can leak credentials (cookies, Authorization) to attacker-controlled hosts and enable client-side SSRF-like behavior.",
    fix: "Validate the URL is on an expected host before fetching, and avoid sending credentials cross-origin.",
  },
  {
    id: "react-eval-in-component",
    severity: "info",
    category: "react",
    confidence: 90,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "eval() inside a React component", // ironward-ignore
    re: /export\s+(?:default\s+)?function\s+[A-Z]\w*\s*\([\s\S]{0,800}\beval\s*\(/g, // ironward-ignore
    rationale: "Calling eval inside a component allows arbitrary code execution if any input is attacker-controlled, and inflates the bundle's CSP attack surface.",
    fix: "Replace eval with a parser or a structured switch over expected values.", // ironward-ignore
  },
  {
    id: "react-console-log-state-secret",
    severity: "medium",
    category: "react",
    confidence: 60,
    owasp: "A09:2021 Security Logging and Monitoring Failures",
    languages: ["javascript", "typescript"],
    title: "console.log of state containing password / token / secret", // ironward-ignore
    re: /(?<!redact[\s\S]{0,80})(?<!sanitize[\s\S]{0,80})console\.log\s*\([^)]*\b(?:password|token|secret|jwt|apiKey)\b/gi, // ironward-ignore
    rationale: "Logging credentials puts them in browser devtools and any log shipping pipeline (Sentry, LogRocket).",
    fix: "Remove the log, or redact the value before logging.",
  },
  {
    id: "react-nextlink-href-user",
    severity: "high",
    category: "react",
    confidence: 65,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "<Link href={user.X}> with user-controlled destination",  // ironward-ignore
    re: /<Link\s+[^>]*href\s*=\s*\{\s*(?:user\.|(?:req|request|params|searchParams)\.)/g,
    rationale: "Next.js Link rendering a user-supplied URL becomes an open-redirect or javascript: URI vector.",
    fix: "Validate the URL host and protocol before passing to Link.",
  },
  {
    id: "react-window-location-user",
    severity: "high",
    category: "react",
    confidence: 70,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "window.location assigned from user input",
    re: /window\.location(?:\.href)?\s*=\s*(?:user\.|(?:req|request|params|searchParams)\.|input\b)/g,
    rationale: "Assigning user-controlled values to window.location is an open redirect and can execute javascript: URIs.",
    fix: "Validate destination URLs against an allowlist before navigating.",
  },
  {
    id: "react-iframe-src-user",
    severity: "high",
    category: "react",
    confidence: 75,
    owasp: "A03:2021 Injection",
    languages: ["javascript", "typescript"],
    title: "<iframe src={...} /> with user-controlled URL",
    re: /<iframe\s+[^>]*src\s*=\s*\{\s*(?:user\.|(?:req|request|params|searchParams)\.)/g,
    rationale: "Loading user-supplied content in an iframe enables phishing and clickjacking.",
    fix: "Validate the iframe src against an allowlist of trusted origins.",
  },
];
