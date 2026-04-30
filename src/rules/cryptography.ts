import type { CodeRule } from "../engines/code-rules.js";

export const CRYPTOGRAPHY_RULES: CodeRule[] = [
  // --- Hardcoded all-zero IV ---
  {
    id: "crypto-iv-all-zero-buffer",
    severity: "critical",
    category: "cryptography",
    confidence: 95,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Hardcoded all-zero IV used with createCipheriv",
    re: /\bBuffer\s*\.\s*(?:from|alloc)\s*\(\s*['"](?:00){8,}['"]\s*,\s*['"]hex['"]/g,
    rationale: "An all-zero IV is the worst possible static IV. For GCM it enables key recovery; for CBC/CTR it makes identical plaintexts encrypt to identical ciphertexts.",
    fix: "Generate a fresh IV per message with crypto.randomBytes(12) for GCM or 16 for CBC and prepend it to the ciphertext.",
  },

  // --- Date.now-derived secrets ---
  {
    id: "crypto-date-now-as-token-source",
    severity: "high",
    category: "cryptography",
    confidence: 80,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Date.now() / new Date().getTime() used as the source for a token, key, secret, or nonce", // ironward-ignore
    re: /\b(?:tokn?|tok|sessionToken|resetToken|verifyToken|magicLink|nonce|csrf|apiKey|signKey)\b[^;\n]{0,120}(?:Date\s*\.\s*now\s*\(\s*\)|new\s+Date\s*\(\s*\)\s*\.\s*getTime\s*\(\s*\))/g,
    rationale: "Time-based values are predictable to within a few seconds and trivially brute-forceable. Anything an attacker shouldn't guess must come from a CSPRNG.",
    fix: "Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID() instead of millisecond timestamps.",
  },

  // --- Deprecated pseudoRandomBytes ---
  {
    id: "crypto-pseudo-random-bytes",
    severity: "high",
    category: "cryptography",
    confidence: 95,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "crypto.pseudoRandomBytes used (deprecated, non-cryptographic)",
    re: /\bcrypto\s*\.\s*pseudoRandomBytes\s*\(/g,
    rationale: "pseudoRandomBytes was deprecated in Node 4 because it does not provide cryptographic strength — output is predictable to a determined attacker.",
    fix: "Use crypto.randomBytes(n). It throws on entropy starvation and is suitable for keys, IVs, and tokens.",
  },

  // --- bcrypt rounds 7-9 ---
  {
    id: "bcrypt-mid-salt-rounds-2026",
    severity: "medium",
    category: "cryptography",
    confidence: 80,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "bcrypt hash with 7-9 salt rounds (too low for 2026 hardware)",
    re: /\bbcrypt\s*\.\s*(?:hash|hashSync)\s*\([^,]+,\s*[789]\s*[),]/g,
    rationale: "Rounds 7-9 were tolerable a decade ago but modern GPUs and ASICs can grind these in offline attacks. OWASP guidance is 10+ for 2024+ deployments.",
    fix: "Move to 12 rounds for new hashes (bcrypt.hash(pw, 12)) and rehash on the next successful login.",
  },

  // --- argon2 timeCost too low ---
  {
    id: "argon2-time-cost-too-low",
    severity: "medium",
    category: "cryptography",
    confidence: 85,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "argon2 hash with timeCost (t) below 2",
    re: /\bargon2\s*\.\s*hash\s*\([^)]*\btimeCost\s*:\s*[01]\b/g,
    rationale: "A timeCost of 0 or 1 reduces argon2 to almost free per guess, defeating the memory-hard design when an attacker can parallelise guesses.",
    fix: "Use timeCost: 3 minimum, memoryCost: 65536 (64 MiB) or higher, parallelism: 1-4. Tune to ~250 ms per hash on production hardware.",
  },

  // --- Hardcoded bcrypt salt literal ---
  {
    id: "bcrypt-hardcoded-salt-literal",
    severity: "high",
    category: "cryptography",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "bcrypt hash called with a hardcoded salt string literal",
    re: /\bbcrypt\s*\.\s*(?:hash|hashSync)\s*\([^,]+,\s*['"]\$2[abxy]?\$\d{1,2}\$[./A-Za-z0-9]{20,}['"]/g,
    rationale: "Reusing the same salt across users defeats bcrypt's protection against precomputation — every user with the same password has the same hash.",
    fix: "Pass an integer cost factor (bcrypt.hash(pw, 12)) so bcrypt generates a per-call random salt.",
  },

  // --- PBKDF2: key derived from non-secret material ---
  {
    id: "kdf-derived-from-username-or-email",
    severity: "high",
    category: "cryptography",
    confidence: 75,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "PBKDF2 / scrypt key derivation seeded from username or email instead of a secret",
    re: /\b(?:pbkdf2|pbkdf2Sync|scrypt|scryptSync)\s*\(\s*(?:user(?:name)?|email|login|userId)\b/g,
    rationale: "KDFs need a high-entropy secret as the password input. Deriving keys from a public identifier means anyone who knows the username can derive the key.",
    fix: "Pass the user's actual passphrase (or a server-side master key) as the first argument and the public identifier as a salt component only.",
  },

  // --- PBKDF2 iterations too low ---
  {
    id: "pbkdf2-iterations-too-low",
    severity: "high",
    category: "cryptography",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "PBKDF2 with iteration count below 100,000",
    re: /\bpbkdf2(?:Sync)?\s*\([^,)]+,[^,)]+,\s*(?:\d{1,4}|[1-9]\d{4})\s*,/g,
    rationale: "OWASP 2023 recommends 600,000 PBKDF2-SHA256 iterations for password storage. Anything under 100,000 is brute-forceable.",
    fix: "Use 600000 iterations with SHA-256 (or migrate to argon2id / scrypt entirely).",
  },

  // --- AES key length mismatch ---
  {
    id: "crypto-aes-256-with-16-byte-key",
    severity: "high",
    category: "cryptography",
    confidence: 80,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "createCipheriv('aes-256-gcm', ...) called with a 16-byte key",
    re: /\bcreateCipheriv\s*\(\s*['"]aes-256-(?:gcm|cbc|ctr)['"]\s*,\s*Buffer\s*\.\s*alloc\s*\(\s*16\s*\)/g,
    rationale: "aes-256 requires a 32-byte key. Passing 16 bytes leads to an exception at best and silently degraded security at worst depending on the runtime.",
    fix: "Use crypto.randomBytes(32) for aes-256-* or switch the cipher name to aes-128-gcm if a 16-byte key is intentional.",
  },

  // --- HMAC-SHA1 in new code ---
  {
    id: "hmac-sha1-new-code",
    severity: "medium",
    category: "cryptography",
    confidence: 85,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "createHmac('sha1', ...) in application code",  // ironward-ignore
    re: /\bcreateHmac\s*\(\s*['"]sha1['"]/gi,
    rationale: "HMAC-SHA1 is not yet broken but SHA-1 is deprecated industry-wide. New code should not adopt it.",
    fix: "Use createHmac('sha256', key) (or sha512 for higher-margin use cases).",
  },

  // --- rand()/random() in non-crypto contexts producing tokens ---
  {
    id: "non-crypto-random-token",
    severity: "high",
    category: "cryptography",
    confidence: 75,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript", "python"],
    title: "rand() / random() output assigned to a token-shaped variable", // ironward-ignore
    re: /\b(?:tokn|tok|sessionTok|resetTok|verifyTok|magicLink|csrf|apiKey)\w*\s*=\s*(?:rand|random)\s*\(/g,
    rationale: "Plain rand()/random() in C, Python, PHP, etc. is not cryptographically secure — outputs are predictable from a few samples.",
    fix: "Use a CSPRNG: secrets.token_hex(32) in Python, crypto.randomBytes(32) in Node, /dev/urandom in C, random_bytes() in PHP.",
  },

  // --- Hardcoded encryption key literal padded to length ---
  {
    id: "crypto-hardcoded-key-padend",
    severity: "critical",
    category: "cryptography",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Hardcoded string literal padded with padEnd / padStart used as an encryption key",
    re: /\b(?:enc(?:ryption)?Key|cipherKey|aesKey|symmetricKey)\s*=\s*['"][^'"]+['"]\s*\.\s*pad(?:End|Start)\s*\(\s*(?:16|24|32)/g,
    rationale: "A literal padded out to 16/24/32 bytes is still a fixed value committed to the repository — anyone who reads the source can decrypt every ciphertext.",
    fix: "Read the key from a secret manager / env var at runtime and require it to be exactly 32 bytes of base64-decoded random data.",
  },

  // --- ECB padding oracle: cipher mode in transformation string ---
  {
    id: "crypto-cipher-no-mode-suffix",
    severity: "medium",
    category: "cryptography",
    confidence: 70,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "createCipheriv called with bare 'aes' name (defaults to ECB on some runtimes)",
    re: /\bcreateCipher(?:iv)?\s*\(\s*['"]aes['"]/g,
    rationale: "Passing only 'aes' relies on undocumented runtime defaults. Different OpenSSL builds pick different modes; some default to ECB.",
    fix: "Always specify the full cipher string: createCipheriv('aes-256-gcm', key, iv).",
  },

  // --- JWT signed with HS256 + short hardcoded secret ---
  {
    id: "jwt-sign-short-literal-secret",
    severity: "critical",
    category: "cryptography",
    confidence: 85,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "jwt.sign with a string literal under 16 bytes as the signing key",
    re: /\bjwt\s*\.\s*sign\s*\([^,]+,\s*['"][^'"]{1,15}['"]/g,
    rationale: "Short signing strings are brute-forceable offline once the attacker has any signed token. Minimum recommended HS256 secret is 256 bits (32 bytes).",
    fix: "Read the signing key from process.env and assert key.length >= 32 at startup.",
  },

  // --- Crypto random with Math.random fallback ---
  {
    id: "crypto-math-random-fallback",
    severity: "high",
    category: "cryptography",
    confidence: 85,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Math .random used as a fallback for crypto.getRandomValues / randomBytes", // ironward-ignore
    re: /\?\s*crypto\s*\.\s*(?:randomBytes|getRandomValues)[^:]*:\s*Math\s*\.\s*random/g,
    rationale: "If crypto isn't available, the code silently weakens to a non-CSPRNG. Better to fail loudly than to ship insecure tokens in older browsers.",
    fix: "Throw if window.crypto is missing and require callers to handle the absence explicitly. Never silently fall back to a non-CSPRNG.",
  },

  // --- Insecure cipher: blowfish ---
  {
    id: "crypto-blowfish-cipher",
    severity: "medium",
    category: "cryptography",
    confidence: 90,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["javascript", "typescript"],
    title: "Blowfish cipher used (small 64-bit block size — Sweet32 attack)",
    re: /\bcreateCipher(?:iv)?\s*\(\s*['"](?:bf|blowfish)[^'"]*['"]/gi,
    rationale: "Blowfish has a 64-bit block — vulnerable to the Sweet32 birthday attack on long sessions.",
    fix: "Use aes-256-gcm with a unique IV per message.",
  },
];
