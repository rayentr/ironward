import * as vscode from "vscode";
import { scanText, setPatterns } from "ironward/engines/secret-engine";
import { scanCodeRules } from "ironward/engines/code-rules";
// Bake the patterns JSON into the bundle so the extension ships self-contained.
import secretsPatterns from "../node_modules/ironward/patterns/secrets.json";

setPatterns(secretsPatterns as Parameters<typeof setPatterns>[0]);

const DIAG_COLL_NAME = "ironward";
let diagnostics: vscode.DiagnosticCollection | undefined;
let statusBar: vscode.StatusBarItem | undefined;
let output: vscode.OutputChannel | undefined;

interface Settings {
  scanOnSave: boolean;
  scanOnOpen: boolean;
  minConfidence: number;
  enabledScanners: Set<string>;
  statusBar: boolean;
}

function readSettings(): Settings {
  const c = vscode.workspace.getConfiguration("ironward");
  return {
    scanOnSave: c.get<boolean>("scanOnSave", true),
    scanOnOpen: c.get<boolean>("scanOnOpen", true),
    minConfidence: c.get<number>("minConfidence", 60),
    enabledScanners: new Set(c.get<string[]>("enabledScanners", ["secrets", "code"])),
    statusBar: c.get<boolean>("statusBar", true),
  };
}

function log(): vscode.OutputChannel {
  if (!output) output = vscode.window.createOutputChannel("Ironward");
  return output;
}

function severityToDiagnosticSeverity(sev: string): vscode.DiagnosticSeverity {
  switch (sev) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ──────────────────────────────────────────────────────────────
// Filter: which URIs do we actually want to scan?
// ──────────────────────────────────────────────────────────────
const TEXT_SCHEMES = new Set(["file"]);
const SKIP_PATTERNS = [
  /\/node_modules\//,
  /\/\.git\//,
  /\/dist\//,
  /\/build\//,
  /\/\.next\//,
  /\/\.turbo\//,
  /\/\.venv\//,
  /\/__pycache__\//,
  /\/target\//,
  /\/coverage\//,
  /\.min\.js$/,
  /\.map$/,
];

function shouldScan(uri: vscode.Uri): boolean {
  if (!TEXT_SCHEMES.has(uri.scheme)) return false;
  const p = uri.fsPath;
  for (const re of SKIP_PATTERNS) if (re.test(p)) return false;
  return true;
}

// ──────────────────────────────────────────────────────────────
// Per-document scan → diagnostics
// ──────────────────────────────────────────────────────────────
async function scanDocument(doc: vscode.TextDocument, settings: Settings): Promise<vscode.Diagnostic[]> {
  if (!shouldScan(doc.uri)) return [];
  const content = doc.getText();
  const rel = vscode.workspace.asRelativePath(doc.uri);
  const diags: vscode.Diagnostic[] = [];

  if (settings.enabledScanners.has("secrets")) {
    try {
      const findings = await scanText(content, rel);
      for (const f of findings) {
        if ((f.confidence ?? 100) < settings.minConfidence) continue;
        const line = Math.max(0, (f.line ?? 1) - 1);
        const col = Math.max(0, (f.column ?? 1) - 1);
        const lineText = doc.lineAt(Math.min(line, doc.lineCount - 1)).text;
        const endCol = Math.min(lineText.length, col + Math.max(4, f.match?.length ?? 8));
        const range = new vscode.Range(line, col, line, endCol);
        const diag = new vscode.Diagnostic(
          range,
          `${f.type}: ${f.description}${f.confidence !== undefined ? ` (conf ${f.confidence})` : ""}`,
          severityToDiagnosticSeverity(f.severity),
        );
        diag.source = "ironward";
        diag.code = { value: f.type, target: vscode.Uri.parse(`https://github.com/rayentr/ironward#${f.type}`) };
        diags.push(diag);
      }
    } catch (err) {
      log().appendLine(`scan-secrets failed on ${rel}: ${(err as Error).message}`);
    }
  }

  if (settings.enabledScanners.has("code")) {
    try {
      const findings = scanCodeRules(content);
      for (const f of findings) {
        const line = Math.max(0, f.line - 1);
        const col = Math.max(0, (f.column ?? 1) - 1);
        const lineText = doc.lineAt(Math.min(line, doc.lineCount - 1)).text;
        const endCol = Math.min(lineText.length, col + 20);
        const range = new vscode.Range(line, col, line, endCol);
        const diag = new vscode.Diagnostic(
          range,
          `${f.title} (${f.ruleId})`,
          severityToDiagnosticSeverity(f.severity),
        );
        diag.source = "ironward";
        diag.code = { value: f.ruleId, target: vscode.Uri.parse(`https://github.com/rayentr/ironward#${f.ruleId}`) };
        diags.push(diag);
      }
    } catch (err) {
      log().appendLine(`scan-code failed on ${rel}: ${(err as Error).message}`);
    }
  }

  // Sort by severity desc, then line.
  diags.sort((a, b) => {
    const s = (b.severity as number) - (a.severity as number);
    return s !== 0 ? s : a.range.start.line - b.range.start.line;
  });
  return diags;
}

async function applyDiagnostics(doc: vscode.TextDocument, settings: Settings): Promise<void> {
  if (!diagnostics) return;
  const diags = await scanDocument(doc, settings);
  diagnostics.set(doc.uri, diags);
  updateStatusBar();
}

// ──────────────────────────────────────────────────────────────
// Status bar
// ──────────────────────────────────────────────────────────────
function updateStatusBar(): void {
  if (!statusBar || !diagnostics) return;
  const settings = readSettings();
  if (!settings.statusBar) { statusBar.hide(); return; }
  let total = 0;
  let critHigh = 0;
  diagnostics.forEach((_uri, list) => {
    total += list.length;
    for (const d of list) {
      if (d.severity === vscode.DiagnosticSeverity.Error) critHigh++;
    }
  });
  if (total === 0) {
    statusBar.text = "$(shield) Ironward: clean";
    statusBar.tooltip = "Ironward — no findings in scanned files";
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = `$(shield) Ironward: ${total}`;
    statusBar.tooltip = `${total} Ironward findings across the workspace (${critHigh} error-level)`;
    statusBar.backgroundColor = critHigh > 0
      ? new vscode.ThemeColor("statusBarItem.errorBackground")
      : new vscode.ThemeColor("statusBarItem.warningBackground");
  }
  statusBar.show();
}

// ──────────────────────────────────────────────────────────────
// Commands
// ──────────────────────────────────────────────────────────────
async function scanCurrentFile(): Promise<void> {
  const ed = vscode.window.activeTextEditor;
  if (!ed) { vscode.window.showInformationMessage("Ironward: no active editor."); return; }
  const settings = readSettings();
  await applyDiagnostics(ed.document, settings);
  vscode.window.showInformationMessage(`Ironward: scanned ${vscode.workspace.asRelativePath(ed.document.uri)}`);
}

async function scanWorkspace(): Promise<void> {
  const settings = readSettings();
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: "Ironward scan", cancellable: true },
    async (progress, token) => {
      const includes = "**/*.{js,jsx,ts,tsx,mjs,cjs,py,rb,php,go,java,kt,rs,sh,yml,yaml,toml,env,conf,ini,json,sql,tf}";
      const excludes = "**/{node_modules,.git,dist,build,.next,.turbo,.venv,venv,__pycache__,target,vendor,coverage}/**";
      const uris = await vscode.workspace.findFiles(includes, excludes, 5000, token);
      let i = 0;
      for (const uri of uris) {
        if (token.isCancellationRequested) break;
        progress.report({ message: `${++i}/${uris.length} ${vscode.workspace.asRelativePath(uri)}` });
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          await applyDiagnostics(doc, settings);
        } catch {
          /* skip */
        }
      }
      vscode.window.showInformationMessage(`Ironward: scanned ${i} files.`);
    },
  );
}

function clearFindings(): void {
  diagnostics?.clear();
  updateStatusBar();
}

// ──────────────────────────────────────────────────────────────
// Quick-fix: add `// ironward-ignore` to the line with the finding.
// ──────────────────────────────────────────────────────────────
class IronwardCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    doc: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.ProviderResult<Array<vscode.CodeAction>> {
    const actions: vscode.CodeAction[] = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== "ironward") continue;

      const line = doc.lineAt(diag.range.start.line);
      const suppressAction = new vscode.CodeAction(
        `Ironward: suppress this finding (// ironward-ignore)`,
        vscode.CodeActionKind.QuickFix,
      );
      suppressAction.diagnostics = [diag];
      const edit = new vscode.WorkspaceEdit();
      const insertPos = new vscode.Position(line.lineNumber, line.text.length);
      const commentSyntax = inferCommentSyntax(doc.languageId);
      edit.insert(doc.uri, insertPos, ` ${commentSyntax} ironward-ignore`);
      suppressAction.edit = edit;
      actions.push(suppressAction);

      if (diag.code && typeof diag.code === "object" && "target" in diag.code) {
        const openDocs = new vscode.CodeAction(
          `Ironward: open docs for ${typeof diag.code.value === "string" ? diag.code.value : "rule"}`,
          vscode.CodeActionKind.QuickFix,
        );
        openDocs.diagnostics = [diag];
        openDocs.command = {
          command: "vscode.open",
          title: "Open",
          arguments: [diag.code.target],
        };
        actions.push(openDocs);
      }
    }
    return actions;
  }
}

function inferCommentSyntax(languageId: string): string {
  switch (languageId) {
    case "python":
    case "ruby":
    case "shellscript":
    case "bash":
    case "sh":
    case "zsh":
    case "yaml":
    case "dockerfile":
    case "toml":
    case "ini":
    case "perl":
      return "#";
    case "sql":
      return "--";
    default:
      return "//";
  }
}

// ──────────────────────────────────────────────────────────────
// Activation
// ──────────────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection(DIAG_COLL_NAME);
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "ironward.openOutput";
  context.subscriptions.push(diagnostics, statusBar);

  updateStatusBar();
  log().appendLine(`Ironward extension activated.`);

  context.subscriptions.push(
    vscode.commands.registerCommand("ironward.scanWorkspace", () => scanWorkspace()),
    vscode.commands.registerCommand("ironward.scanCurrentFile", () => scanCurrentFile()),
    vscode.commands.registerCommand("ironward.clearFindings", () => clearFindings()),
    vscode.commands.registerCommand("ironward.openOutput", () => log().show()),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const settings = readSettings();
      if (!settings.scanOnSave) return;
      await applyDiagnostics(doc, settings);
    }),
    vscode.workspace.onDidOpenTextDocument(async (doc) => {
      const settings = readSettings();
      if (!settings.scanOnOpen) return;
      await applyDiagnostics(doc, settings);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnostics?.delete(doc.uri);
      updateStatusBar();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("ironward")) updateStatusBar();
    }),
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new IronwardCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );

  const settings = readSettings();
  if (settings.scanOnOpen) {
    for (const ed of vscode.window.visibleTextEditors) {
      void applyDiagnostics(ed.document, settings);
    }
  }
}

export function deactivate(): void {
  diagnostics?.dispose();
  statusBar?.dispose();
  output?.dispose();
}
