<h1 align="center">Ironward</h1>

<p align="center"><em>Security scanning for the vibe coding era.</em></p>

<p align="center">
  <a href="https://www.npmjs.com/package/ironward"><img alt="npm" src="https://img.shields.io/npm/v/ironward?color=9af99a&label=npm"></a>
  <a href="https://github.com/rayentr/ironward/actions"><img alt="tests" src="https://img.shields.io/badge/tests-286%2F286-9af99a"></a>
  <a href="./vscode-extension"><img alt="vscode" src="https://img.shields.io/badge/VS%20Code-extension-9af99a"></a>
  <a href="./LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-9af99a"></a>
  <a href="https://www.npmjs.com/package/ironward"><img alt="downloads" src="https://img.shields.io/npm/dm/ironward?color=9af99a"></a>
</p>

<p align="center">
  An open-source <strong>MCP server</strong>, <strong>CLI</strong>, and <strong>GitHub Action</strong> that finds
  hardcoded secrets, auth bugs, SQL injection, XSS, IDOR, and vulnerable dependencies in your code —
  and opens a fix PR. Four of its tools work fully offline, no API key required.
</p>

---

## Install

```bash
# Scan the current project — no install, no API key.
npx ironward scan .
```

That's it. Runs offline, streams findings, exits non-zero on criticals so CI fails.

Or install globally:

```bash
npm install -g ironward
ironward scan ./src
```

---

## The 13 tools

| Tool | Runtime | What it finds |
|------|---------|---------------|
| `scan_for_secrets` | **Offline** | 665 pattern families — AWS, GCP, Azure, Stripe, PayPal, GitHub, OpenAI, Anthropic, Supabase, PlanetScale, Ethereum/Solana wallets, Firebase, + Shannon entropy |
| `scan_code` | **Offline** | 61 static rules — `eval`, command injection, path traversal, weak crypto, SSRF, XXE, NoSQL/LDAP injection, template injection, timing-unsafe comparisons, Python-specific (pickle, yaml.load, subprocess shell=True) |
| `scan_deps` | **Offline** | OSV.dev CVE lookup + typosquat detection + known-malware list + abandoned packages + license compliance |
| `scan_url` | **Offline** | Letter-graded web scan — headers, CORS, cookies, exposed `.env` / `.git`, source maps, admin panels, API docs, Supabase/Firebase keys, TLS expiry |
| `scan_docker` | **Offline** | Dockerfile + docker-compose — root user, `privileged:true`, sensitive host mounts, secrets in ENV/ARG, `:latest` tags, `curl \| sh`, exposed SSH/DB ports |
| `scan_k8s` | **Offline** | Kubernetes manifests — privileged containers, `hostNetwork`, dangerous capabilities (SYS_ADMIN, ALL), missing resource limits, secrets in env literals, default service accounts |
| `scan_infra` | **Offline** | Terraform + CloudFormation — public S3, 0.0.0.0/0 security groups, publicly-accessible RDS, IAM `*` policies, unencrypted EBS, GCP allUsers ACLs, Azure open NSGs |
| `scan_github` | **Offline** | GitHub Actions — `pull_request_target` + checkout (PR arbitrary-code-execution), expression injection via `${{ github.event.* }}` in `run:`, unpinned action versions, write-all permissions, artifact leaks |
| `scan_auth_logic` | AI | Backwards auth checks, missing ownership, privilege escalation, bypassable middleware, JWT `alg:none` acceptance, session fixation |
| `scan_sqli` | AI | SQL injection across JS/TS, Python, Go, Ruby, PHP, Java — string concat, template literals, ORM `raw` / `$queryRawUnsafe` |
| `scan_xss` | AI | DOM + server-side XSS — `innerHTML`, `dangerouslySetInnerHTML`, Vue `v-html`, Svelte `{@html}`, EJS unescaped, reflected Express/Koa responses |
| `scan_idor` | AI | Routes reading an ID from params without an owner check. Prisma/Mongoose mass-assignment via `data: req.body` |
| `fix_and_pr` | AI | Generates surgical multi-file patches with validation loop — re-scans the fix before opening the PR |

**Bring your own model.** AI tools work with Anthropic, OpenAI, Gemini, Groq, or a fully-local Ollama install.

---

## Demo

```
$ npx ironward scan ./src
Ironward — offline scan of ./src

── scan-secrets ──
src/config.js
  [CRITICAL] L14:1  AWS access key ID  (aws_access_key)
      AKIA***REDACTED***

── scan-code ──
src/api/upload.js
  [HIGH] L42:5  eval() call  (eval-call)
      why: eval executes arbitrary code — a direct RCE sink when fed user input.
      fix: Remove eval. Parse data explicitly (JSON.parse, Function constructors).

── scan-deps ──
2 vulnerabilities across 14 dependencies — 1 critical, 1 high, 0 medium.

[CRITICAL] lodash@4.17.15  GHSA-p6mc-m468-83gw  — fixed in 4.17.19
  Prototype pollution in lodash

Done in 412ms.  Exit 2.
```

Exit codes: `0` clean · `1` low/medium findings · `2` critical or high findings (fails CI).

---

## `ironward login` — use AI-powered scanners

Offline tools are always on. To enable `scan_auth_logic`, `scan_sqli`, `scan_xss`, `scan_idor`, and `fix_and_pr`, pick a provider:

```bash
ironward login
```

Interactive picker:

```
Ironward — pick an AI provider.

  1. Anthropic   — Claude Opus/Sonnet — best reasoning
  2. OpenAI      — GPT-4o — great alternative
  3. Google      — Gemini 1.5 Pro — good for XSS/SQLi
  4. Groq        — Llama 3 — fastest, cheapest
  5. Ollama      — Local — free, private, no cloud
  6. Skip        — offline tools only

Choose a provider [1-6]:
```

Key is stored in `~/.ironward/config.json` (chmod 600) and never leaves your machine.

```bash
ironward whoami     # show current provider + model
ironward logout     # remove saved config
ironward free       # list tools that work without any API key
```

---

## Use in Cursor / Claude Code / VS Code

<details>
<summary><strong>Cursor</strong></summary>

```json
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "ironward": {
      "command": "npx",
      "args": ["-y", "ironward@latest"],
      "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
    }
  }
}
```
</details>

<details>
<summary><strong>Claude Code</strong></summary>

```bash
claude mcp add ironward -- npx -y ironward@latest
```
</details>

<details>
<summary><strong>VS Code</strong></summary>

```json
// .vscode/mcp.json
{
  "servers": {
    "ironward": {
      "command": "npx",
      "args": ["-y", "ironward@latest"]
    }
  }
}
```
</details>

`ANTHROPIC_API_KEY` (or any other provider key) is only required for the AI tools. Offline tools work without it.

---

## GitHub Action

Scan on every push and pull request. Inline PR annotations, job summary with full findings table, zero config.

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rayentr/ironward/github-action@v1
        with:
          fail-on: critical
```

Full configuration and outputs in [github-action/README.md](./github-action/README.md).

---

## CLI reference

```
Scanning
  ironward scan <path>              run every offline scanner (auto-detects IaC files)
  ironward scan-secrets <path>...   665 pattern families
  ironward scan-code <path>...      61 static analysis rules
  ironward scan-deps <path>...      OSV CVE + typosquat / malware / license
  ironward scan-url <https-url>     security headers, TLS, exposed files
  ironward scan-docker <path>...    Dockerfile + docker-compose
  ironward scan-k8s <path>...       Kubernetes manifests
  ironward scan-infra <path>...     Terraform + CloudFormation
  ironward scan-github <path>...    GitHub Actions workflows

Provider
  ironward login                    pick AI provider (interactive)
  ironward logout / whoami / free

Misc
  ironward --version
  ironward --help

Output format
  --format json                     machine-readable output for CI
  --format text                     (default)
```

---

## VS Code extension

Ironward ships a native VS Code extension — inline squiggles, scan on save, status bar count, and a one-click "suppress this finding" quick-fix. Bundled standalone — no CLI install needed.

```bash
# Marketplace
code --install-extension rayentr.ironward

# Or from a local .vsix build
cd vscode-extension && npm install && npm run package
code --install-extension ironward-vscode.vsix
```

Settings: `ironward.scanOnSave`, `ironward.minConfidence`, `ironward.enabledScanners`. See the [extension README](./vscode-extension/README.md) for details.

---

## SARIF + JUnit + webhooks

Ironward fits into the tools your team already uses.

```bash
# GitHub Security tab
ironward scan-secrets --format sarif . > results.sarif
# Then in GitHub Actions:
#   - uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: results.sarif }

# Jenkins / CircleCI / GitLab / Azure DevOps test panels
ironward scan-code --format junit . > results.xml

# Slack (or any POST endpoint)
ironward scan-secrets . --webhook "$SLACK_WEBHOOK_URL"
```

The webhook payload auto-detects Slack (`hooks.slack.com`) and emits Block Kit with rich formatting; any other URL receives raw JSON.

---

## Watch mode + git pre-commit hook

**`ironward watch`** — file watcher that re-scans on every save. Ctrl-C to stop.

```bash
ironward watch ./src
# 🛡  Ironward watching src — Ctrl-C to stop
# 14:32:07  src/api/auth.ts
#   [CRITICAL] L42  jwt-alg-none  conf=95
```

**`ironward install-hooks`** — installs a git pre-commit hook that blocks commits with critical/high findings. Respects `core.hooksPath` (husky, lefthook, …) and preserves existing hook content.

```bash
cd myproject
ironward install-hooks
# git commit now blocks on findings
# bypass once: git commit --no-verify
# remove entirely: ironward uninstall-hooks
```

---

## Incremental scanning + `.ironwardignore`

Ironward caches per-file scan results at `~/.ironward/cache.json` keyed by content hash. On re-scan, unchanged files are served from cache — typically **5–10×** faster on warm runs.

Pre-commit hooks become instant:

```bash
# Only scan files about to be committed.
ironward scan-secrets --staged

# Or files changed relative to a branch.
ironward scan-secrets --since=main

# Bust the cache if you need a fresh run.
ironward scan-secrets --no-cache .
```

Exclude files via `.ironwardignore` (gitignore syntax):

```
# .ironwardignore
fixtures/synthetic-secrets/
generated/
*.test.ts
```

Ironward also honors your existing `.gitignore`.

---

## What makes it different

- **Offline-first.** Four of nine tools run with zero network (except OSV.dev for CVE lookups). Bring an API key only when you want AI reasoning for auth/SQLi/XSS/IDOR.
- **It fixes the bug, not just finds it.** `fix_and_pr` generates multi-file patches and re-scans the fix before opening a PR.
- **Bring your own model.** Anthropic, OpenAI, Gemini, Groq, Ollama. Your key stays local. No Ironward cloud.
- **Three-line install.** No signup, no SSO handshake, no per-seat pricing.
- **Self-scanned.** Ironward scans its own source on every commit — **zero findings**.

---

## Contributing

PRs welcome. The codebase is small and well-tested:

```bash
git clone https://github.com/rayentr/ironward
cd ironward
npm install
npm test          # 166 tests, all offline, no API calls
npm run build
node dist/bin.js scan ./src
```

Good first issues:

- Add a new secret-pattern family — edit [`patterns/secrets.json`](./patterns/secrets.json) and add a fixture to [`tests/fixtures/categories/`](./tests/fixtures/categories).
- Add a static-analysis rule — edit [`src/engines/code-rules.ts`](./src/engines/code-rules.ts).
- Teach `scan_url` a new probe — [`src/engines/url-scanner.ts`](./src/engines/url-scanner.ts).

Every new pattern/rule must ship with a test. The scanner must stay self-clean (`node dist/bin.js scan ./src` returns 0 findings).

---

## License

[MIT](./LICENSE) — free to use, fork, ship.

---

<p align="center">
  <sub>Built by <a href="https://github.com/rayentr">@rayentr</a>.
  <br>Star the repo if Ironward saved you from shipping a secret. ⭐</sub>
</p>
