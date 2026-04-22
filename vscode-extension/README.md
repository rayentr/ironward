# Aegis MCP for VS Code

AI-powered security scanner. Finds secrets, auth bugs, SQL injection, and vulnerable dependencies — and can open fix PRs for any finding.

## What you get

- **Commands** (press `⌘⇧P`):
  - **Aegis MCP: Scan Workspace for Secrets** — offline scan across every source file, results in the Output panel.
  - **Aegis MCP: Scan Current File for Secrets** — same, scoped to the active editor.
  - **Aegis MCP: Show MCP Configuration** — opens a ready-to-paste snippet for VS Code's native MCP config or any other MCP client.
- **Auto-scan on save** (opt-in via `aegis-mcp.autoScanOnSave`): every saved file is scanned for secrets in the background.
- **Full Aegis MCP toolset** — register the bundled server as an MCP server (see below) to unlock `scan_auth_logic`, `scan_sqli`, `scan_deps`, and `fix_and_pr` inside Chat / Copilot.

## MCP registration

Run `Aegis MCP: Show MCP Configuration` and paste the generated snippet into `.vscode/mcp.json` or your client's equivalent. `ANTHROPIC_API_KEY` is only required for Claude-backed tools.

## Settings

| Setting | Default | Description |
|---|---|---|
| `aegis-mcp.autoScanOnSave` | `false` | Scan each file for secrets on save. |
| `aegis-mcp.serverCommand` | `npx` | Command used when emitting the MCP config snippet. |
| `aegis-mcp.serverArgs` | `["-y", "aegis-mcp@latest"]` | Arguments for the server command. |
