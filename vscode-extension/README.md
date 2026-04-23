# Ironward — VS Code extension

[![npm](https://img.shields.io/npm/v/ironward?color=9af99a&label=ironward%20core)](https://www.npmjs.com/package/ironward)
[![license](https://img.shields.io/badge/license-MIT-9af99a)](../LICENSE)

Security scanning for the vibe coding era, right inside your editor.

- **665 secret pattern families** — AWS, GCP, Azure, Stripe, PayPal, GitHub, OpenAI, Anthropic, Supabase, PlanetScale, Ethereum/Solana wallets, Firebase, and entropy heuristic for the rest
- **61 static rules** — `eval`, command injection, weak crypto, SSRF, NoSQL/LDAP/XXE/template injection, JWT `alg:none`, timing-unsafe comparisons, Python-specific (pickle, yaml.load, `subprocess shell=True`), and more
- **Inline squiggles** on the exact line, severity-coloured
- **Scan on save** + scan on open (both configurable)
- **Quick-fix** to suppress a finding with `// ironward-ignore`
- **Status bar** count — click it for the Output panel
- **Confidence filter** — hide findings below your threshold (default 60)
- **Zero API key** — everything in the extension runs offline

The AI-powered scanners (`scan_auth_logic`, `scan_sqli`, `scan_xss`, `scan_idor`, `fix_and_pr`) live in the [Ironward MCP server](https://github.com/rayentr/ironward) — use them from Cursor / Claude Code / VS Code chat with your own Anthropic or OpenAI key.

## Commands

Open the command palette (`⌘⇧P` / `Ctrl+Shift+P`):

| Command | What it does |
|---|---|
| `Ironward: Scan workspace` | Walk every source file and populate the Problems panel |
| `Ironward: Scan current file` | Scan only the active editor |
| `Ironward: Clear findings` | Drop all diagnostics the extension has set |
| `Ironward: Show output` | Open the Output panel with Ironward logs |

## Settings

| Setting | Default | Description |
|---|---|---|
| `ironward.scanOnSave` | `true` | Re-scan a file every time it is saved |
| `ironward.scanOnOpen` | `true` | Scan files as they are opened |
| `ironward.minConfidence` | `60` | Hide secret findings below this score |
| `ironward.enabledScanners` | `["secrets", "code"]` | Which scanners run inline |
| `ironward.statusBar` | `true` | Show the Ironward count in the status bar |

## Quick-fix

Hover any Ironward squiggle → `⌘.` / `Ctrl+.` → **Ironward: suppress this finding**. This appends `// ironward-ignore` (or the correct comment syntax for the current language) to the end of the line. The scanner will skip this line on the next scan.

For rule documentation, the same menu offers **Open docs for `<rule-id>`**.

## How it works

The extension bundles the Ironward scanning engine directly — no CLI installation required, no subprocess per file. Every scan runs in-process, in milliseconds, with the same logic as `ironward scan` on the command line.

## Install

From the Marketplace:

```
code --install-extension rayentr.ironward
```

Or search for **Ironward** in the Extensions panel.

## License

MIT — same as the core scanner. See the [main repo](https://github.com/rayentr/ironward).
