import * as vscode from "vscode";
import { readFile } from "node:fs/promises";
import { runScanSecrets, formatReport } from "aegis-mcp/dist/tools/scan-secrets.js";

let channel: vscode.OutputChannel | undefined;

function getChannel(): vscode.OutputChannel {
  if (!channel) channel = vscode.window.createOutputChannel("Aegis MCP");
  return channel;
}

async function collectFilesInWorkspace(): Promise<vscode.Uri[]> {
  const includes = "**/*.{js,jsx,ts,tsx,mjs,cjs,py,rb,php,go,java,kt,rs,sh,yml,yaml,toml,env,conf,ini,json}";
  const excludes = "**/{node_modules,.git,dist,build,.next,.turbo,.venv,venv,__pycache__,target,vendor}/**";
  return vscode.workspace.findFiles(includes, excludes, 2000);
}

async function scanUris(uris: vscode.Uri[]): Promise<void> {
  const out = getChannel();
  out.show(true);
  out.appendLine(`Aegis MCP — scanning ${uris.length} file${uris.length === 1 ? "" : "s"}…`);

  const files: Array<{ path: string; content: string }> = [];
  for (const uri of uris) {
    try {
      const content = await readFile(uri.fsPath, "utf8");
      const rel = vscode.workspace.asRelativePath(uri);
      files.push({ path: rel, content });
    } catch {
      /* unreadable — skip */
    }
  }

  const result = await runScanSecrets({ files, context: "on-demand" });
  out.appendLine("");
  out.appendLine(formatReport(result));
  out.appendLine("");
  out.appendLine(`Done. Scanned ${files.length} file${files.length === 1 ? "" : "s"}.`);
}

function mcpConfigSnippet(cmd: string, args: string[]): string {
  const env = "{\n      \"ANTHROPIC_API_KEY\": \"sk-ant-...\"\n    }";
  return JSON.stringify(
    {
      mcpServers: {
        aegis-mcp: {
          command: cmd,
          args,
          env: "<see comment>" as unknown,
        },
      },
    },
    null,
    2,
  ).replace('"<see comment>"', env);
}

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("aegis-mcp");

  context.subscriptions.push(
    vscode.commands.registerCommand("aegis-mcp.scanWorkspace", async () => {
      const uris = await collectFilesInWorkspace();
      await scanUris(uris);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aegis-mcp.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("Aegis MCP: no active editor.");
        return;
      }
      await scanUris([editor.document.uri]);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aegis-mcp.configureMcp", async () => {
      const cmd = config.get<string>("serverCommand", "npx");
      const args = config.get<string[]>("serverArgs", ["-y", "aegis-mcp@latest"]);
      const doc = await vscode.workspace.openTextDocument({
        language: "jsonc",
        content:
          "// Add this to .vscode/mcp.json (VS Code native MCP) or your client's MCP config.\n" +
          "// ANTHROPIC_API_KEY is required only for scan_auth_logic / scan_sqli / fix_and_pr.\n\n" +
          mcpConfigSnippet(cmd, args),
      });
      await vscode.window.showTextDocument(doc);
    }),
  );

  if (config.get<boolean>("autoScanOnSave", false)) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        if (doc.uri.scheme !== "file") return;
        scanUris([doc.uri]).catch((err) => getChannel().appendLine(`scan error: ${String(err)}`));
      }),
    );
  }
}

export function deactivate(): void {
  channel?.dispose();
}
