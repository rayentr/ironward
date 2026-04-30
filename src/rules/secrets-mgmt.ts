import type { CodeRule } from "../engines/code-rules.js";

export const SECRETS_MGMT_RULES: CodeRule[] = [
  {
    id: "secret-mgmt-hardcoded-prod-url",
    severity: "high",
    category: "insecure-protocol" as any,
    confidence: 70,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "Hardcoded production URL paired with an Authorization header",
    // A production-shaped URL string within ~200 chars of an Authorization / Bearer header.
    re: /['"`]https:\/\/[\w.-]*(?:api\.production\.|prod\.|api\.prod\.|production\.)[\w.-]+[^'"`]*['"`][\s\S]{0,200}?(?:Authorization|Bearer\s+[A-Za-z0-9._-]+)/g,
    rationale: "Embedding production hostnames next to credential headers creates a single point of leakage — both pieces required to attack are committed to source.",
    fix: "Source the base URL from env (`process.env.API_URL`) and the bearer token from a secret manager / env. Keep them out of git.",
  },
  {
    id: "secret-mgmt-hardcoded-ip",
    severity: "medium",
    category: "insecure-protocol" as any,
    confidence: 75,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript", "json", "yaml"],
    title: "Hardcoded public IP address in config",
    // Match a quoted IPv4 that is NOT in 10/8, 172.16/12, 192.168/16, 127/8, or 0.0.0.0.
    re: /['"`](?!10\.|127\.|0\.0\.0\.0|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}['"`]/g,
    rationale: "Hardcoded public IPs lock infra to one cloud region/provider, leak topology, and survive in git history forever.",
    fix: "Move to DNS hostnames behind env vars. Use service discovery (Consul, k8s Service) so IPs can rotate without code changes.",
  },
  {
    id: "secret-mgmt-secret-in-test-file",
    severity: "high",
    category: "insecure-protocol" as any,
    confidence: 70,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "Real-looking secret literal (sk_live_ / AKIA / ghp_ / xoxb_) in source",
    // Quoted literal matching common high-entropy real-secret prefixes.
    re: /['"`](?:sk_live_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{30,})['"`]/g,
    rationale: "These prefixes are issued by Stripe/AWS/GitHub/Slack/Google. A literal in any source file (including tests) means the secret is in git history forever and must be rotated.",
    fix: "Replace with a fake placeholder (`'sk_test_FAKE_...'`) or a fixture loaded at runtime. Rotate the real secret if it was ever committed.",
  },
  {
    id: "secret-mgmt-multiple-env-files-prod",
    severity: "high",
    category: "insecure-protocol" as any,
    confidence: 85,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript", "shell", "yaml"],
    title: ".env.production literal referenced alongside concrete secret values",
    // Match a `.env.production` reference within ~200 chars of a key=secret-shape pair.
    re: /\.env\.production\b[\s\S]{0,200}?\b\w+_?(?:KEY|SECRET|TOKEN|PASSWORD)\s*=\s*['"`]?[A-Za-z0-9_\-]{16,}['"`]?/g,
    rationale: ".env.production should never be committed. Co-located references plus real-looking values is a strong indicator the file is already in the repo.",
    fix: "Add `.env.production` to `.gitignore`, run `git rm --cached .env.production`, rotate every value, and load production secrets from your secret manager.",
  },
  {
    id: "secret-mgmt-config-with-creds",
    severity: "high",
    category: "insecure-protocol" as any,
    confidence: 75,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["json"],
    title: "config.json-style object containing both username and a non-template password",
    // `"username": "..."` followed within ~200 chars by `"password": "<non-placeholder>"`.
    re: /"username"\s*:\s*"[^"$<{][^"]{1,80}"[\s\S]{0,200}?"password"\s*:\s*"(?!\$\{|<|TODO|CHANGEME|PLACEHOLDER)[^"]{6,}"/gi,
    rationale: "Hardcoded credential pairs in config files are committed to git and shipped to every developer machine — equivalent to publishing the password.",
    fix: "Replace the literal value with `${ENV_VAR}` or a templated placeholder; load real credentials from env / a secret manager at runtime.",
  },
];
