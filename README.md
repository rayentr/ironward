# Ironward

AI-powered security scanner delivered as an MCP server and CLI. Scans your code for leaked secrets, vulnerable auth logic, injection flaws, and CVE-affected dependencies — and opens fix PRs — directly inside Cursor, Claude Code, and VS Code.

[![npm](https://img.shields.io/npm/v/ironward.svg)](https://www.npmjs.com/package/ironward)
[![license](https://img.shields.io/npm/l/ironward.svg)](./LICENSE)

> **v0.10.0** — **9 tools**. New `scan_code` (27 offline static-analysis rules, no API key needed). 270 secret patterns (+web3, +more AI/ML, +Supabase/Xata/Fauna). `scan_url` now grades sites A+ through F. New `ironward scan <path>` meta-command runs every offline scanner in one pass.

## Tools

### `scan_for_secrets` — offline, instant

- **212 pattern families** — AWS, GCP, Azure, DigitalOcean, Alibaba, Stripe, GitHub (classic/oauth/fine-grained), GitLab, OpenAI, Anthropic, HuggingFace, Slack, Discord, SendGrid, Postgres/Mongo/Redis URLs, PEM / OpenSSH / PGP private keys, npm, DockerHub, Notion, Linear, Figma, Tailscale, and many more.
- **Shannon-entropy fallback** for unknown secrets, with a placeholder + UUID/SHA allowlist to keep false positives near zero.
- **Three input modes** — inline `files`, on-disk `paths`, or a raw `content` snippet.
- **Context-aware gating** — `context: "pre-commit"` returns `isError: true` on critical/high findings so MCP clients can block commits.
- **Redaction by default** — only truncated fingerprints are returned.
- **Line-level suppression** — `// ironward-ignore` on the same or prior line.

### `scan_auth_logic` — Claude Opus

Deep analysis of authentication/authorization defects — the class of bugs pattern scanners cannot catch:

- Backwards auth checks (`if (user)` when the intent is `if (!user)`)
- Missing ownership / tenancy checks (resource fetched by ID with no check that the caller owns it)
- Privilege-escalation paths and role comparison bugs
- Auth middleware that runs too late or is skipped on error paths
- JWT validation gaps — `alg: none`, unchecked `exp`/`aud`/`iss`, skipped signature verification
- Session fixation, unsafe session handling, plaintext password storage in reset flows

A cheap keyword pre-filter skips the model entirely when the file has no auth surface, so unrelated code is free. Requires `ANTHROPIC_API_KEY`.

### `scan_sqli` — Claude Sonnet + pre-filter

Targets query-construction defects a pattern scanner alone cannot judge:

- String concatenation / template literals / f-strings / `%`-format / `str.format` building SQL
- ORM `raw` / `$queryRawUnsafe` / `knex.raw` / `sequelize.query` with interpolated arguments
- Second-order injection (untrusted data stored, then concatenated later)
- Dynamic identifiers (table/column names coming from user input)

A 24-rule cross-language regex pre-filter (JS/TS, Python, Go, Java, Ruby, PHP) surfaces suspect lines; Sonnet confirms or dismisses. Files with no query-construction patterns skip the model entirely.

### `scan_xss` — Claude Sonnet + framework-aware pre-filter

Catches XSS across four flavors:

- **Reflected** — request input flows into the response body without encoding
- **Stored** — persisted input later rendered without escaping
- **DOM** — user-controlled data reaches dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `new Function`, string-`setTimeout`)
- **Framework-specific bypasses** — React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` / `bypassSecurityTrust*`, Svelte `{@html}`, SolidJS `innerHTML={}`
- **Template injection** — EJS `<%- %>`, Handlebars/Mustache `{{{ }}}`, Jinja `|safe` / `autoescape=False`, Flask `Markup()`, Django `|safe`
- **Unsafe PHP** — `echo $_GET/$_POST/$_REQUEST`

A 25-rule pre-filter with sanitizer allowlist (DOMPurify, `textContent`, `he.encode`, etc.) keeps false positives near zero. Sonnet confirms real defects.

### `scan_idor` — Claude Opus, broken-access-control focus

The #1 OWASP category. Catches:

- **Missing ownership checks** — a handler fetches a resource by ID with no verification that the requester owns it
- **Horizontal privilege escalation** — user A modifying user B's data by changing an ID
- **Mass assignment / overposting** — `req.body` spread into updates, letting attackers set `role`, `tenantId`, `credits`, `isAdmin`
- **Predictable sequential IDs** — `parseInt(req.params.id)` patterns enabling enumeration
- **Unprotected admin routes** — endpoints with `authRequired` but no role check
- **Role-from-input** — authorization decisions based on client-controlled flags

A 12-rule pre-filter surfaces data-access and admin sites; Opus reasons over the full request flow. Reports ownership-hint density to weight confidence.

### `scan_url` — live URL audit (no model call)

Point it at a deployed URL and get a misconfiguration report. Network-only, rule-based, no API key needed.

- **Security headers** — missing or weak CSP (incl. `'unsafe-inline'` / `'unsafe-eval'`), HSTS, X-Frame-Options / `frame-ancestors`, X-Content-Type-Options, Referrer-Policy
- **Cookie flags** — missing `Secure`, `HttpOnly` on session-like cookies, `SameSite` absent
- **CORS** — wildcard + credentials (critical), `null` origin acceptance
- **TLS enforcement** — plaintext HTTP responses
- **Exposed dev/build files** — `/.env`, `/.git/config`, `/.DS_Store`, `firebase.json`, `.vscode/settings.json`, `.npmrc`
- **Error leakage** — one 404 probe to detect stack traces / absolute filesystem paths in responses
- **Version disclosure** — `Server`, `X-Powered-By` headers exposing versions

> **Only scan sites you own or are authorized to test.**

### `scan_deps` — offline parsing + OSV.dev

Parses `package.json`, `requirements.txt`, and `Pipfile.lock`. Queries OSV.dev for each unique `(ecosystem, package, version)` tuple and returns findings with CVE aliases, affected ranges, fixed versions, and reference URLs — sorted by CVSS severity.

### `scan_code` — 27 offline static rules, no API key

Pure pattern-matching static analysis. Zero network, zero Claude, instant. Catches:

- **Dangerous functions** — `eval`, `new Function`, `child_process.exec/spawn` with request input, `setuid`
- **Weak crypto** — MD5, SHA-1, DES/3DES, RC4, `Math.random` in token/id/secret context, predictable JWT signing secrets
- **Unsafe I/O** — `path.join`/`path.resolve`/`fs.readFile` with request input (path traversal), plaintext HTTP in fetch/axios
- **Web flaws** — SSRF (`fetch(req.body.url)`), open redirects, prototype pollution via `merge(obj, req.body)`, SQL string concat
- **Framework** — CORS origin wildcard in code, Express app without helmet, auth routes without rate limiting
- **JWT** — `alg: "none"`, hardcoded weak signing secrets (`"secret"`, `"changeme"`, …)
- **Debug / logging** — `debugger;` statements, `console.log(password)`, commented-out secrets, TODOs flagging unfinished auth

Every finding carries a rationale and a concrete fix. `// ironward-ignore` on the same or prior line suppresses.

### `fix_and_pr` — Opus + GitHub (multi-file + self-validation)

Given any finding from any scanner, Opus produces a minimal, surgical fix — **across one or more files** — then Ironward re-runs the relevant scanner on the fixed output. If residual issues remain, it retries (max 2 attempts) with the residual passed back as context. Only when validation passes does it create a branch, commit every changed file, and open a single PR.

The PR body carries the OWASP reference, exploit scenario, severity, and validation status. Set `dryRun: true` to preview, `skipValidation: true` to bypass the loop. Requires `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` with `repo` scope.

## Install

### Cursor (`~/.cursor/mcp.json`)

```json
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

`ANTHROPIC_API_KEY` is only required for Claude-backed tools (`scan_auth_logic`, `scan_sqli`, `fix_and_pr`). `scan_for_secrets` and `scan_deps` work without it.

### Claude Code

```bash
claude mcp add ironward -- npx -y ironward@latest
```

### VS Code (`.vscode/mcp.json`)

```json
{
  "servers": {
    "ironward": {
      "command": "npx",
      "args": ["-y", "ironward@latest"]
    }
  }
}
```

### CLI (no MCP client required)

```bash
npx ironward scan .                                # run EVERY offline scanner in one pass
npx ironward scan-secrets src/                     # 270 secret patterns + entropy
npx ironward scan-code src/                        # 27 static analysis rules
npx ironward scan-deps package.json                # CVE lookup via OSV.dev
npx ironward scan-url https://your-deployed-app.com
npx ironward --help
```

**Zero API key required** for the entire CLI. Just `npx` and go.

Exit codes: `0` clean · `1` findings (no critical/high) · `2` critical or high findings present.

## Dashboard

A local Next.js dashboard lives in [dashboard/](dashboard/). Run it to see scan history, severity distribution, and per-repo security scores — all stored locally in `~/.ironward/ironward.db`.

```bash
cd dashboard && npm install && npm run dev   # http://localhost:3737
```

Record scans from the CLI by setting `IRONWARD_RECORD=1`:

```bash
IRONWARD_RECORD=1 IRONWARD_REPO=you/myapp npx ironward scan-secrets src/
IRONWARD_RECORD=1 IRONWARD_REPO=you/myapp npx ironward scan-url https://myapp.com
```

## Local development

```bash
npm install
npm run build
npm test
```

Or point your IDE config at the local checkout:

```json
{
  "mcpServers": {
    "ironward-dev": {
      "command": "node",
      "args": ["/absolute/path/to/ironward/dist/bin.js"]
    }
  }
}
```

## Tool reference

### `scan_for_secrets`

| Field | Type | Description |
|---|---|---|
| `files` | `{ path, content }[]` | Inline files — preferred when the client already has the text. |
| `paths` | `string[]` | Absolute filesystem paths to read and scan. |
| `content` | `string` | A raw snippet with no file context. |
| `context` | `"pre-commit" \| "on-save" \| "on-demand"` | Gates blocking behavior. |

### `scan_auth_logic` · `scan_sqli`

| Field | Type | Description |
|---|---|---|
| `code` | `string` | Source code to analyze. |
| `language` | `string` | Language hint (e.g. `typescript`, `python`). |
| `path` | `string` | Optional file path for context. |
| `model` | `string` | Anthropic model ID; overridable via `SECUREMCP_AUTH_MODEL` / `SECUREMCP_SQL_MODEL` env. |

### `scan_deps`

| Field | Type | Description |
|---|---|---|
| `paths` | `string[]` | Paths to `package.json`, `requirements.txt`, `Pipfile.lock`. |
| `manifests` | `{ path, content }[]` | Inline manifests. |

### `fix_and_pr`

| Field | Type | Description |
|---|---|---|
| `repo` | `string` | `owner/repo`. |
| `filePath` | `string` | File to fix, relative to repo root. |
| `finding` | `object` | A finding from any scanner. |
| `fileContent` | `string` | Optional inline contents; otherwise fetched from GitHub. |
| `dryRun` | `boolean` | Propose the fix without creating a branch/PR. |

## Architecture

```
IDE (Cursor / Claude Code / VS Code)
        │  JSON-RPC 2.0 over stdio
        ▼
Ironward server  (Node 20+, TypeScript)
        │
        ├─ scan_for_secrets   ← 270 patterns + entropy (offline, zero keys)
        ├─ scan_code          ← 27 static-analysis rules (offline, zero keys)
        ├─ scan_deps          ← manifest parsers + OSV.dev (offline, zero keys)
        ├─ scan_url           ← HTTP audit + letter grade (offline, zero keys)
        ├─ scan_auth_logic    ← Claude Opus + keyword pre-filter
        ├─ scan_sqli          ← Claude Sonnet + 24-rule pre-filter
        ├─ scan_xss           ← Claude Sonnet + 25-rule pre-filter
        ├─ scan_idor          ← Claude Opus + 12-rule access-control pre-filter
        └─ fix_and_pr         ← Opus + GitHub REST (branch + commit + PR)
```

## License

MIT
