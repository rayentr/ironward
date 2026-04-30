import type { CodeRule } from "../engines/code-rules.js";

export const AUTHENTICATION_RULES: CodeRule[] = [
  // --- jwt.sign without expiresIn ---
  {
    id: "jwt-sign-no-expires-in",
    severity: "high",
    category: "jwt",
    confidence: 75,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "jwt.sign called without an expiresIn option",
    re: /\bjwt\s*\.\s*sign\s*\(\s*\{[\s\S]{0,200}?\}\s*,\s*[^,)]+\s*(?:,\s*\{(?![^}]*expiresIn)[^}]*\})?\s*\)/g,
    rationale: "A JWT without an expiry lives forever. If a token is leaked or a session needs to be revoked, there's no time-based safety net.",
    fix: "Pass { expiresIn: '15m' } (or '1h' for refresh-token-backed sessions) and rotate refresh tokens server-side.",
  },

  // --- express-session: short literal secret ---
  {
    id: "express-session-short-secret",
    severity: "critical",
    category: "authentication",
    confidence: 90,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "express-session configured with a literal secret under 32 chars", // ironward-ignore
    re: /\bsession\s*\(\s*\{[^}]*\bsecret\s*:\s*['"][^'"]{1,31}['"]/g,
    rationale: "A short, hardcoded session signing key is brute-forceable offline once any signed cookie is captured. Anyone with repo access can also forge sessions directly.", // ironward-ignore
    fix: "Read the secret from process.env, assert length >= 32 bytes at startup, and rotate periodically.",
  },

  // --- express-session missing core options ---
  {
    id: "express-session-missing-cookie-secure",
    severity: "high",
    category: "authentication",
    confidence: 75,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "express-session config object missing cookie.secure / saveUninitialized / resave settings",
    re: /\bsession\s*\(\s*\{(?![^}]*cookie\s*:)[^}]*\bsecret\s*:/g,
    rationale: "Without cookie.secure session cookies travel over HTTP; without resave / saveUninitialized defaults the store can blow up or leak anonymous sessions.",
    fix: "Set cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: ... }, resave: false, saveUninitialized: false explicitly.",
  },

  // --- res.cookie without httpOnly on session-named cookies ---
  {
    id: "cookie-session-name-no-httponly",
    severity: "high",
    category: "authentication",
    confidence: 80,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "res.cookie with a session-like name set without httpOnly",
    re: /\bres\s*\.\s*cookie\s*\(\s*['"](?:session|sid|sess|auth|jwt|tkn|connect\.sid)['"][\s\S]{0,200}?\{(?![^}]*httpOnly\s*:\s*true)[^}]+\}/g,
    rationale: "Without httpOnly the cookie is readable from JavaScript — any XSS becomes session theft.",
    fix: "Set httpOnly: true on every cookie that carries auth state. Only opt out for cookies that JS legitimately needs to read.",
  },
  {
    id: "cookie-session-name-no-secure",
    severity: "high",
    category: "authentication",
    confidence: 75,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "res.cookie with a session-like name set without secure flag",
    re: /\bres\s*\.\s*cookie\s*\(\s*['"](?:session|sid|sess|auth|jwt|tkn|connect\.sid)['"][\s\S]{0,200}?\{(?![^}]*\bsecure\s*:\s*true)[^}]+\}/g,
    rationale: "Without secure: true the cookie is sent over plaintext HTTP and any on-path observer can copy it.",
    fix: "Set secure: true unconditionally in production. For local dev, gate on process.env.NODE_ENV !== 'production'.",
  },

  // --- Plaintext password compare ---
  {
    id: "auth-plaintext-password-compare",
    severity: "critical",
    category: "authentication",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Stored user password compared in plaintext to request value", // ironward-ignore
    re: /\b(?:user|account|row)\s*\.\s*pass(?:word|wd)?\s*===?\s*(?:req|request|ctx)\s*\.\s*body\s*\.\s*pass(?:word|wd)?/g,
    rationale: "A direct equality compare implies passwords are stored in plaintext (or reversibly encrypted), which is a breach-in-waiting.", // ironward-ignore
    fix: "Store passwords as bcrypt / argon2id hashes and use bcrypt.compare(input, hash) — never == or ===.", // ironward-ignore
  },

  // --- Storing password without hashing ---
  {
    id: "auth-store-password-no-hash",
    severity: "high",
    category: "authentication",
    confidence: 65,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "User-supplied password assigned to a record field without bcrypt/argon2 nearby", // ironward-ignore
    re: /\b(?:user|account|row|data)\s*\.\s*pass(?:word|wd)?\s*=\s*(?:req|request|ctx)\s*\.\s*body\s*\.\s*pass(?:word|wd)?(?![\s\S]{0,200}?(?:bcrypt|argon2|scrypt|pbkdf2))/g,
    rationale: "Assigning the raw request password into a record means it will be persisted without hashing — a single DB dump exposes every credential.", // ironward-ignore
    fix: "Hash with bcrypt.hash(req.body.password, 12) (or argon2.hash) and store the digest only.", // ironward-ignore
  },

  // --- OAuth state ---
  {
    id: "oauth-passport-no-state-option",
    severity: "high",
    category: "authentication",
    confidence: 80,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "passport.authenticate strategy invoked without state: true",
    re: /\bpassport\s*\.\s*authenticate\s*\(\s*['"](?:google|github|facebook|twitter|oauth2|oidc)['"]\s*,\s*\{(?![^}]*\bstate\s*:\s*true)[^}]+\}/g,
    rationale: "Without an OAuth state parameter the callback cannot prove the request originated from this client — opens the door to login CSRF / account takeover.",
    fix: "Pass { state: true } to passport.authenticate (or generate and verify a per-session nonce manually) and assert it on callback.",
  },
  {
    id: "oauth-callback-no-state-validation",
    severity: "high",
    category: "authentication",
    confidence: 70,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "OAuth callback handler reads req.query.code but never compares req.query.state to session",  // ironward-ignore
    re: /\breq\s*\.\s*query\s*\.\s*code\b(?![\s\S]{0,400}?req\s*\.\s*session\s*\.\s*(?:state|oauthState))/g,
    rationale: "An OAuth callback that ignores the state parameter accepts any code — attackers can paste their own authorisation code into a victim session.",
    fix: "Generate a random state at the /authorize step, store it on req.session, and reject the callback if req.query.state does not match.",
  },

  // --- jwt.verify without algorithms allowlist ---
  {
    id: "jwt-verify-no-algorithms-option",
    severity: "high",
    category: "jwt",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "jwt.verify called without an algorithms: [...] option",
    // Match the entire jwt.verify(...) invocation (including its options object). The // ironward-ignore
    // negativePattern then checks the full call for an algorithms: option. Previously the
    // negative lookahead was placed AFTER the closing `)` so it couldn't see the option.
    re: /\bjwt\s*\.\s*verify\s*\([\s\S]*?\)/g,
    negativePattern: /algorithms\s*:/,
    rationale: "jsonwebtoken accepts whatever algorithm the token's header advertises. Without an algorithms allowlist, an attacker can swap RS256 to HS256 (algorithm confusion) and sign with the public key.",
    fix: "Always pass { algorithms: ['RS256'] } (or your specific algorithm) so jsonwebtoken refuses unexpected algs.",
  },

  // --- Reset token equality compare ---
  {
    id: "reset-token-equality-compare",
    severity: "high",
    category: "timing-attack",
    confidence: 85,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Password reset token compared with === / == (timing attack)", // ironward-ignore
    re: /\b(?:resetT(?:ok|kn)|passwordResetT(?:ok|kn)|forgotT(?:ok|kn))\w*\s*===?\s*(?:req|request|ctx)\s*\.\s*(?:body|params|query)/g,
    rationale: "Equality compare of a reset token leaks the token byte-by-byte over many timed requests — attacker reconstructs a victim's reset link.",
    fix: "Use crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(provided)) after asserting equal lengths.",
  },

  // --- Magic link token short / weak ---
  {
    id: "magic-link-token-short-weak",
    severity: "high",
    category: "authentication",
    confidence: 80,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Magic-link token generated with Math .random or short slice",
    re: /\b(?:magicLink|loginLink|signInLink)\w*\s*=\s*(?:Math\s*\.\s*random\s*\(\s*\)\s*\.\s*toString|['"][\s\S]{0,40}?['"]\s*\.\s*slice\s*\(\s*0\s*,\s*(?:[1-9]|1[0-5])\s*\))/g,
    rationale: "Magic-link tokens shorter than 16 random characters or generated from Math .random are guessable within reasonable attacker effort.",
    fix: "Use crypto.randomBytes(32).toString('base64url') and require >= 22 chars of base64 entropy.",
  },

  // --- Email verification token guessable ---
  {
    id: "email-verify-token-guessable",
    severity: "high",
    category: "authentication",
    confidence: 80,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Email-verification token derived from Date.now or sequential counter",
    re: /\b(?:verify|verification|emailConfirm)T(?:ok|kn)\w*\s*=\s*(?:Date\s*\.\s*now\s*\(\s*\)\s*\.\s*toString|String\s*\(\s*Date\s*\.\s*now|\+\+\s*counter|counter\s*\+\+)/g,
    rationale: "Time- or counter-based verification values can be enumerated — attacker activates a victim's account or pre-confirms an email they don't own.",
    fix: "Use crypto.randomBytes(32).toString('hex') for verification tokens; expire them after a short TTL and single-use them.",
  },

  // --- Session id placed in URL fragment / query ---
  {
    id: "session-id-in-url-query",
    severity: "high",
    category: "authentication",
    confidence: 80,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Session id appended to a URL as a query string or fragment",
    // Match standard ?key= / &key= / #key= forms PLUS the Java/Tomcat ;jsessionid= path-param form.
    re: /(?:[?&#](?:sessionid|sessionId|session_id|sid|jsessionid)=|;jsessionid=)[^&\s'"`)]+/gi,
    rationale: "Session ids in URLs leak via Referer headers, browser history, web server logs, and bookmarks — long-lived hijack risk.", // ironward-ignore
    fix: "Carry session ids in cookies (HttpOnly + Secure + SameSite=Lax). Never embed them in URLs or links.",
  },

  // --- Refresh token without rotation ---
  {
    id: "refresh-token-no-rotation",
    severity: "medium",
    category: "authentication",
    confidence: 60,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Refresh-token issued but no rotation / revocation logic in proximity",
    re: /\brefreshT(?:ok|kn)\w*\s*=\s*(?:crypto\s*\.\s*randomBytes|jwt\s*\.\s*sign)\b(?![\s\S]{0,300}?(?:revoke|rotate|invalidate|delete\s*\(\s*refresh))/g,
    rationale: "A refresh token without rotation or server-side revocation is essentially a long-lived password — leak once, the attacker keeps a session forever.",
    fix: "Persist refresh tokens server-side, rotate on every use, and revoke the old one. Detect reuse and force full re-auth.",
  },

  // --- Login response leaks whether user exists ---
  {
    id: "login-user-not-found-distinct-error",
    severity: "medium",
    category: "authentication",
    confidence: 70,
    owasp: "A07:2021 Identification and Authentication Failures",
    languages: ["javascript", "typescript"],
    title: "Login error response distinguishes 'user not found' from 'wrong password'", // ironward-ignore
    re: /\bres\s*\.\s*(?:status\s*\(\s*\d+\s*\)\s*\.\s*)?(?:json|send)\s*\(\s*\{[^}]*\b(?:error|message)\s*:\s*['"][^'"]*(?:user\s+not\s+found|no\s+such\s+user|unknown\s+user|email\s+not\s+registered)/gi,
    rationale: "Differentiating the two errors enables account enumeration — attackers learn which emails are registered.",
    fix: "Return a single generic error ('Invalid email or password') for both branches and log the specific cause server-side only.",
  },
];
