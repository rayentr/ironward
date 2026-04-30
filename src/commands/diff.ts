import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { isGitRepo } from "../engines/git-diff.js";
import { scanCodeRules, type CodeFinding } from "../engines/code-rules.js";
import { scanText } from "../engines/secret-engine.js";

const execAsync = promisify(execFile);

interface DiffFinding {
  path: string;
  line: number;
  ruleId: string;
  severity: string;
  title: string;
}

function fingerprint(f: { path: string; line: number; ruleId: string }): string {
  return `${f.path}|${f.line}|${f.ruleId}`;
}

async function git(args: string[], cwd: string): Promise<{ stdout: string; ok: boolean }> {
  try {
    const { stdout } = await execAsync("git", args, { cwd, maxBuffer: 10 * 1024 * 1024 });
    return { stdout, ok: true };
  } catch {
    return { stdout: "", ok: false };
  }
}

async function changedFilesSince(ref: string, cwd: string): Promise<{ added: string[]; modified: string[]; deleted: string[] }> {
  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  // git diff --name-status <ref>...HEAD shows status letters per file.
  const { stdout, ok } = await git(["diff", "--name-status", `${ref}...HEAD`], cwd);
  if (!ok) return { added, modified, deleted };
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // Format: "M\tpath" or "A\tpath" or "D\tpath" or "R100\told\tnew"
    const parts = trimmed.split("\t");
    const status = parts[0][0];
    if (status === "A") added.push(parts[1]);
    else if (status === "M" || status === "T") modified.push(parts[1]);
    else if (status === "D") deleted.push(parts[1]);
    else if (status === "R" && parts.length === 3) modified.push(parts[2]);
  }
  return { added, modified, deleted };
}

async function fileAtRef(ref: string, path: string, cwd: string): Promise<string | null> {
  const { stdout, ok } = await git(["show", `${ref}:${path}`], cwd);
  return ok ? stdout : null;
}

async function fileOnDisk(path: string): Promise<string | null> {
  try { return await readFile(path, "utf8"); } catch { return null; }
}

async function scanContentForFindings(content: string, path: string): Promise<DiffFinding[]> {
  const code: CodeFinding[] = scanCodeRules(content);
  const codeFindings: DiffFinding[] = code.map((c) => ({
    path,
    line: c.line,
    ruleId: c.ruleId,
    severity: c.severity,
    title: c.title,
  }));
  const secrets = await scanText(content, path);
  const secretFindings: DiffFinding[] = (secrets ?? []).map((s: any) => ({
    path,
    line: s.line ?? 1,
    ruleId: s.id ?? s.ruleId ?? "secret",
    severity: s.severity ?? "high",
    title: s.title ?? s.id ?? "Secret detected",
  }));
  return [...codeFindings, ...secretFindings];
}

function formatLine(f: DiffFinding): string {
  return `[${f.severity.toUpperCase()}] ${f.path}:L${f.line}  ${f.title}  (${f.ruleId})`;
}

function pickFlag(rest: string[], flag: string): string | undefined {
  const eq = rest.find((a) => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = rest.indexOf(flag);
  if (i >= 0 && i + 1 < rest.length) return rest[i + 1];
  return undefined;
}

export async function runDiff(rest: string[]): Promise<number> {
  const ref = rest.find((a) => !a.startsWith("--"));
  if (!ref) {
    console.error("Usage: ironward diff <git-ref>");
    console.error("       ironward diff main");
    console.error("       ironward diff HEAD~3");
    return 2;
  }
  const cwd = process.cwd();
  if (!(await isGitRepo(cwd))) {
    console.error("ironward diff: not in a git repository.");
    return 2;
  }
  // Validate the ref resolves
  const refCheck = await git(["rev-parse", "--verify", `${ref}^{commit}`], cwd);
  if (!refCheck.ok) {
    console.error(`ironward diff: invalid git ref "${ref}".`);
    return 2;
  }

  const { added, modified, deleted } = await changedFilesSince(ref, cwd);
  const changedFiles = [...added, ...modified];
  const totalChanged = added.length + modified.length + deleted.length;

  console.log(`Changes since ${ref} (${totalChanged} file${totalChanged === 1 ? "" : "s"} changed)`);
  console.log("");

  // Scan each changed file at HEAD (current state) and at the base ref to compute the delta.
  const newFindings: DiffFinding[] = [];
  const resolvedFindings: DiffFinding[] = [];

  // For added files: anything detected at HEAD is "new".
  for (const rel of added) {
    const abs = resolve(cwd, rel);
    const head = await fileOnDisk(abs);
    if (head == null) continue;
    const headFind = await scanContentForFindings(head, rel);
    for (const f of headFind) newFindings.push(f);
  }

  // For modified files: compute set difference (HEAD findings minus base-ref findings).
  for (const rel of modified) {
    const abs = resolve(cwd, rel);
    const head = await fileOnDisk(abs);
    const base = await fileAtRef(ref, rel, cwd);
    if (head == null) continue;
    const headFind = await scanContentForFindings(head, rel);
    const baseFind = base != null ? await scanContentForFindings(base, rel) : [];
    const baseFps = new Set(baseFind.map(fingerprint));
    const headFps = new Set(headFind.map(fingerprint));
    for (const f of headFind) if (!baseFps.has(fingerprint(f))) newFindings.push(f);
    for (const f of baseFind) if (!headFps.has(fingerprint(f))) resolvedFindings.push(f);
  }

  // For deleted files: every finding at the base ref is now resolved.
  for (const rel of deleted) {
    const base = await fileAtRef(ref, rel, cwd);
    if (base == null) continue;
    const baseFind = await scanContentForFindings(base, rel);
    for (const f of baseFind) resolvedFindings.push(f);
  }

  const sortBySev = (a: DiffFinding, b: DiffFinding): number => {
    const order = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(a.severity) - order.indexOf(b.severity) || a.path.localeCompare(b.path) || a.line - b.line;
  };
  newFindings.sort(sortBySev);
  resolvedFindings.sort(sortBySev);

  if (newFindings.length === 0 && resolvedFindings.length === 0) {
    console.log("No new or resolved security findings in the diff.");
    if (changedFiles.length === 0 && deleted.length === 0) {
      console.log(`(${ref} matches HEAD — nothing changed.)`);
    }
    return 0;
  }

  if (newFindings.length > 0) {
    console.log(`NEW findings (${newFindings.length}):`);
    for (const f of newFindings) console.log(`  ${formatLine(f)}`);
  }
  if (resolvedFindings.length > 0) {
    if (newFindings.length > 0) console.log("");
    console.log(`Resolved findings (${resolvedFindings.length}):`);
    for (const f of resolvedFindings) {
      const isDeleted = deleted.includes(f.path);
      console.log(`  ${formatLine(f)}${isDeleted ? "  (file deleted)" : ""}`);
    }
  }

  const critOrHigh = newFindings.some((f) => f.severity === "critical" || f.severity === "high");
  // Suppress unused-var lint
  void cwd; void relative;
  return critOrHigh ? 1 : 0;
}
