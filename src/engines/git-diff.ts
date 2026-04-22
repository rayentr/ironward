import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";

const execAsync = promisify(execFile);

export type GitScope =
  | { kind: "staged" }
  | { kind: "changed" }
  | { kind: "since"; ref: string };

async function git(args: string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execAsync("git", args, { cwd, maxBuffer: 10 * 1024 * 1024 });
    return stdout;
  } catch (err) {
    throw new Error(`git ${args.join(" ")} failed: ${(err as Error).message.split("\n")[0]}`);
  }
}

export async function isGitRepo(cwd: string): Promise<boolean> {
  try {
    await execAsync("git", ["rev-parse", "--is-inside-work-tree"], { cwd });
    return true;
  } catch {
    return false;
  }
}

/**
 * Return the list of files affected by the given scope, as absolute paths.
 * Only includes files that exist on disk (excludes deletions).
 */
export async function filesForScope(scope: GitScope, cwd: string): Promise<string[]> {
  let args: string[];
  switch (scope.kind) {
    case "staged":
      args = ["diff", "--name-only", "--cached", "--diff-filter=ACMRTUXB"];
      break;
    case "changed":
      // Uncommitted changes in working tree (tracked files only).
      args = ["diff", "--name-only", "--diff-filter=ACMRTUXB"];
      break;
    case "since":
      args = ["diff", "--name-only", `${scope.ref}...HEAD`, "--diff-filter=ACMRTUXB"];
      break;
  }
  const stdout = await git(args, cwd);
  const rel = stdout.split("\n").map((s) => s.trim()).filter(Boolean);
  return rel.map((r) => resolve(cwd, r));
}

export function parseScopeFromArgs(args: string[]): { scope: GitScope | null; rest: string[] } {
  const rest: string[] = [];
  let scope: GitScope | null = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--staged") { scope = { kind: "staged" }; continue; }
    if (a === "--changed") { scope = { kind: "changed" }; continue; }
    if (a === "--since") {
      const v = args[i + 1];
      if (!v) throw new Error("--since requires a git ref (branch or commit).");
      scope = { kind: "since", ref: v };
      i++;
      continue;
    }
    if (a.startsWith("--since=")) {
      scope = { kind: "since", ref: a.slice("--since=".length) };
      continue;
    }
    rest.push(a);
  }
  return { scope, rest };
}
