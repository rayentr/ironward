import type { CodeRule } from "../engines/code-rules.js";

export const DEP_SECURITY_RULES: CodeRule[] = [
  {
    id: "dep-wildcard-version",
    severity: "high",
    category: "framework" as any,
    confidence: 90,
    owasp: "A06:2021 Vulnerable and Outdated Components",
    languages: ["json"],
    title: "package.json dependency pinned to \"*\" or \"latest\"",
    // Match a JSON key + value where the version is `*` or `latest`.
    re: /"[\w@\/-]+"\s*:\s*"(?:\*|latest)"/g,
    rationale: "Floating `*`/`latest` versions mean every install can pull a different tree, including a freshly published malicious version (supply-chain attack).",
    fix: "Pin to an exact version or a tight range (`^1.2.3`). Re-generate lockfile and commit it.",
  },
  {
    id: "dep-postinstall-script",
    severity: "medium",
    category: "framework" as any,
    confidence: 70,
    owasp: "A08:2021 Software and Data Integrity Failures",
    languages: ["json"],
    title: "package.json declares a postinstall script (verify intent)",
    re: /"postinstall"\s*:\s*"[^"]+"/g,
    rationale: "postinstall scripts run arbitrary code on every `npm install` for every consumer of your package. Frequently abused for supply-chain attacks.",
    fix: "Remove the postinstall if not strictly required. If kept, document why and ensure it cannot be triggered when the package is installed as a dependency (use `prepare` for git-only flows).",
  },
  {
    id: "dep-npm-install-in-ci",
    severity: "medium",
    category: "framework" as any,
    confidence: 80,
    owasp: "A08:2021 Software and Data Integrity Failures",
    languages: ["yaml"],
    title: "CI workflow uses `npm install` instead of `npm ci`",
    // Match a YAML run-line that calls `npm install` (not `npm ci`, not `npm install -g <tool>`).
    re: /(?:^|\n)\s*(?:-\s*run\s*:\s*|run\s*:\s*\|?\s*\n?\s*-?\s*)?npm\s+install\b(?!\s*-g)/g,
    rationale: "`npm install` mutates the lockfile and may resolve to versions the developer never tested. `npm ci` installs exactly what the lockfile pins, deterministically.",
    fix: "Replace `npm install` with `npm ci` in CI. Same for pnpm (`pnpm install --frozen-lockfile`) and yarn (`yarn install --frozen-lockfile`).",
  },
  {
    id: "dep-old-jquery",
    severity: "high",
    category: "framework" as any,
    confidence: 95,
    owasp: "A06:2021 Vulnerable and Outdated Components",
    languages: ["json", "javascript", "typescript", "html"],
    title: "Reference to jquery@1.x or jquery@2.x (known XSS CVEs)",
    re: /\bjquery[@\/-]\s*(?:\")?[12]\.\d+(?:\.\d+)?\b|"jquery"\s*:\s*"\^?[12]\.\d+(?:\.\d+)?"/g,
    rationale: "jQuery 1.x and 2.x have known XSS sinks (CVE-2015-9251, CVE-2019-11358 affect <3.4). Modern apps should be on 3.7+ or off jQuery entirely.",
    fix: "Upgrade to jquery@^3.7.1 (or remove jQuery) and re-test selectors / `.html()` callsites for XSS.",
  },
];
