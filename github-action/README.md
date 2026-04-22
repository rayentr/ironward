# Ironward GitHub Action

[![Ironward](https://img.shields.io/badge/security-ironward-red)](https://github.com/rayentr/ironward)

Drop-in GitHub Action that scans your code for secrets, static security issues, and vulnerable dependencies on every push and pull request. Zero API key needed for core scanning.

- **665+ secret pattern families** — AWS, GCP, Azure, Stripe, GitHub, OpenAI, web3 wallets, Supabase, PlanetScale, …
- **27 static rules** — eval, command injection, path traversal, weak crypto, SSRF, prototype pollution, JWT `alg:none`, …
- **OSV.dev CVE lookup** plus typosquat / abandoned / malware / license checks
- **Optional URL scan** — security headers, CORS, cookies, exposed `.env`, TLS expiry, embedded Supabase/Firebase keys
- **Inline PR annotations** on every finding — right on the vulnerable line
- **Job summary** with score, counts, and full findings table
- **Fails the build** on critical/high (configurable)

## Quick start

```yaml
name: Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rayentr/ironward-action@v1
```

That's it. The action runs offline scanners against the repo root and fails if any critical or high findings turn up.

## Full config

```yaml
- name: Ironward Security Scan
  uses: rayentr/ironward-action@v1
  with:
    path: ./src
    fail-on: critical
    scan-url: https://myapp.vercel.app
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, or `never`. |
| `scan-secrets` | `true` | Run the 665-pattern secret scanner. |
| `scan-code` | `true` | Run the 27-rule static analyzer. |
| `scan-deps` | `true` | Run OSV + supply-chain intel. |
| `scan-url` | `""` | Optional. Live URL to scan. |
| `anthropic-api-key` | `""` | Optional. Written to `~/.ironward/config.json`. |
| `openai-api-key` | `""` | Optional. Written to `~/.ironward/config.json`. |
| `fail-on-new-only` | `false` | (Reserved for future use.) |
| `report-path` | `ironward-report.json` | Where to write the merged JSON report. |

### Outputs

| Output | Description |
|---|---|
| `findings-count` | Total findings across all scanners. |
| `critical-count` | Number of critical findings. |
| `high-count` | Number of high findings. |
| `medium-count` | Number of medium findings. |
| `low-count` | Number of low findings. |
| `score` | Overall security score (0-100). |
| `report-path` | Path to the JSON report. |

## Using outputs

```yaml
- name: Ironward scan
  id: ironward
  uses: rayentr/ironward-action@v1
  with:
    fail-on: never  # don't fail the job — just report

- name: Comment on PR if criticals exist
  if: steps.ironward.outputs.critical-count != '0' && github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: '⚠️ Ironward found ${{ steps.ironward.outputs.critical-count }} critical security issues. See the job summary.'
      })

- name: Upload full JSON report
  uses: actions/upload-artifact@v4
  with:
    name: ironward-report
    path: ${{ steps.ironward.outputs.report-path }}
```

## Gradual adoption

If you're adding Ironward to a large repo with existing findings you can't fix all at once, start permissive and tighten over time:

```yaml
- uses: rayentr/ironward-action@v1
  with:
    fail-on: critical   # only fail on the worst stuff initially
```

Then ratchet down to `high`, then `medium` as you clean up.

## What runs without an API key

The action's default mode uses **only offline tools** — no network calls except OSV.dev for CVE lookups:

- `scan_for_secrets` — 665 pattern families + Shannon entropy
- `scan_code` — 27 static analysis rules
- `scan_deps` — OSV.dev CVE + typosquat / abandoned / malware / license
- `scan_url` — HTTP header and TLS probes (if you pass a URL)

## What needs an API key

The AI-powered scanners (`scan_auth_logic`, `scan_sqli`, `scan_xss`, `scan_idor`, `fix_and_pr`) are **not currently invoked by this action**. If you supply `anthropic-api-key` or `openai-api-key`, the action writes a config file so future versions — and any manual `ironward` call inside the job — pick it up.

## Badge

Add this to your README:

```md
[![Ironward](https://img.shields.io/badge/security-ironward-red)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/security.yml)
```

## Publishing to the Marketplace

To host this action yourself:

1. Create a new public repo, e.g. `github.com/YOUR_ORG/ironward-action`.
2. Copy the contents of this `github-action/` directory to the repo root (`action.yml`, `Dockerfile`, `entrypoint.sh`, `README.md`).
3. Tag a release `v1.0.0`. GitHub auto-detects `action.yml` and offers to publish to the Marketplace.
4. Users reference it with `uses: YOUR_ORG/ironward-action@v1`.

## Under the hood

- Pulls the `ironward` npm package (published from [rayentr/ironward](https://github.com/rayentr/ironward)).
- Runs each scanner with `--format json`, merges results with `jq`, and emits a single `ironward-report.json`.
- Writes a Markdown summary to `$GITHUB_STEP_SUMMARY`.
- Emits `::error`, `::warning`, and `::notice` annotations (level depends on severity) so GitHub can pin findings to the right file/line in the PR.

## License

MIT.
