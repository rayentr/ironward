import { stat, readFile, writeFile, unlink, chmod, mkdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

const HOOK_MARKER = "# >>> ironward pre-commit (managed; do not edit this block) >>>";
const HOOK_END_MARKER = "# <<< ironward pre-commit <<<";

const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}
# Block commits that introduce critical/high security findings.
# To bypass in an emergency: \`git commit --no-verify\`.
# Managed by: ironward install-hooks

if ! command -v ironward >/dev/null 2>&1; then
  # If ironward isn't on PATH, fall back to npx. If that fails, don't block.
  if ! command -v npx >/dev/null 2>&1; then
    echo "ironward pre-commit: ironward not found on PATH and npx unavailable — skipping." >&2
    exit 0
  fi
  IRONWARD="npx -y ironward@latest"
else
  IRONWARD="ironward"
fi

# Scan only staged files. Exit 2 from ironward means critical/high findings present.
$IRONWARD scan-secrets --staged || STATUS=$?
if [ "\${STATUS:-0}" = "2" ]; then
  echo "ironward: blocked commit — critical/high secrets staged." >&2
  echo "  Fix the findings, or re-run with \\\`git commit --no-verify\\\` to bypass." >&2
  exit 1
fi
unset STATUS

$IRONWARD scan-code --staged || STATUS=$?
if [ "\${STATUS:-0}" = "2" ]; then
  echo "ironward: blocked commit — critical/high code issues staged." >&2
  echo "  Fix the findings, or re-run with \\\`git commit --no-verify\\\` to bypass." >&2
  exit 1
fi

${HOOK_END_MARKER}
`;

interface RepoInfo { gitDir: string; workTree: string }

async function repoInfo(cwd: string): Promise<RepoInfo | null> {
  try {
    const gitDirOut = execFileSync("git", ["rev-parse", "--git-dir"], { cwd, encoding: "utf8" }).trim();
    const gitDir = resolve(cwd, gitDirOut);
    const workTreeOut = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd, encoding: "utf8" }).trim();
    return { gitDir, workTree: workTreeOut };
  } catch {
    return null;
  }
}

async function resolveHooksDir(info: RepoInfo): Promise<string> {
  // core.hooksPath is resolved relative to the working-tree root (not .git).
  try {
    const custom = execFileSync("git", ["config", "--get", "core.hooksPath"], { cwd: info.workTree, encoding: "utf8" }).trim();
    if (custom) return resolve(info.workTree, custom);
  } catch {
    /* not set — use default */
  }
  return join(info.gitDir, "hooks");
}

export async function runInstallHooks(cwd: string = process.cwd()): Promise<number> {
  const info = await repoInfo(cwd);
  if (!info) {
    console.error("ironward install-hooks: not inside a git repository.");
    return 2;
  }
  const hooksDir = await resolveHooksDir(info);
  await mkdir(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, "pre-commit");

  // If a pre-commit hook already exists, preserve it.
  let existing = "";
  try { existing = await readFile(hookPath, "utf8"); } catch { /* none yet */ }

  if (existing && existing.includes(HOOK_MARKER)) {
    console.log(`✓ pre-commit hook already has Ironward section — updating to latest.`);
    const before = existing.split(HOOK_MARKER)[0].trimEnd();
    const after = existing.includes(HOOK_END_MARKER)
      ? existing.split(HOOK_END_MARKER).slice(1).join(HOOK_END_MARKER).replace(/^\n+/, "")
      : "";
    const merged = [before, HOOK_SCRIPT.replace(/^#!\/bin\/sh\n/, "")].filter(Boolean).join("\n\n") +
      (after ? "\n\n" + after : "") + "\n";
    const full = before.startsWith("#!") ? merged : `#!/bin/sh\n${merged}`;
    await writeFile(hookPath, full, "utf8");
  } else if (existing) {
    console.log(`ℹ  Existing pre-commit hook found — appending Ironward block.`);
    const appended = existing.trimEnd() + "\n\n" + HOOK_SCRIPT.replace(/^#!\/bin\/sh\n/, "") + "\n";
    await writeFile(hookPath, appended, "utf8");
  } else {
    await writeFile(hookPath, HOOK_SCRIPT, "utf8");
  }

  await chmod(hookPath, 0o755);
  console.log(`Installed Ironward pre-commit hook at ${hookPath}`);
  console.log(`It will block commits with critical/high secret or code findings.`);
  console.log(`Bypass once with: git commit --no-verify`);
  console.log(`Uninstall with:  ironward uninstall-hooks`);
  return 0;
}

export async function runUninstallHooks(cwd: string = process.cwd()): Promise<number> {
  const info = await repoInfo(cwd);
  if (!info) {
    console.error("ironward uninstall-hooks: not inside a git repository.");
    return 2;
  }
  const hooksDir = await resolveHooksDir(info);
  const hookPath = join(hooksDir, "pre-commit");

  let existing = "";
  try { existing = await readFile(hookPath, "utf8"); } catch {
    console.log("No pre-commit hook installed.");
    return 0;
  }

  if (!existing.includes(HOOK_MARKER)) {
    console.log("pre-commit hook exists but has no Ironward block — leaving it alone.");
    return 0;
  }

  const before = existing.split(HOOK_MARKER)[0].trimEnd();
  const after = existing.includes(HOOK_END_MARKER)
    ? existing.split(HOOK_END_MARKER).slice(1).join(HOOK_END_MARKER).replace(/^\n+/, "")
    : "";
  const remaining = [before, after].filter(Boolean).join("\n\n").trim();

  // If the hook is now just a shebang (or empty), remove the file entirely.
  const isOnlyShebang = remaining === "" || /^#!\s*\/bin\/sh\s*$/.test(remaining);
  if (isOnlyShebang) {
    try { await unlink(hookPath); } catch { /* best-effort */ }
    console.log(`Removed Ironward pre-commit hook (${hookPath} deleted).`);
  } else {
    const restored = remaining.startsWith("#!") ? remaining + "\n" : `#!/bin/sh\n${remaining}\n`;
    await writeFile(hookPath, restored, "utf8");
    console.log(`Removed Ironward block from ${hookPath} (other hook content preserved).`);
  }
  return 0;
}
