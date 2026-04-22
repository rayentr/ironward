import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { runInstallHooks, runUninstallHooks } = await import("../src/commands/hooks.ts");

function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "ironward-hooks-"));
  execFileSync("git", ["init", "-q"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "t@t.t"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "t"], { cwd: dir });
  return dir;
}

test("install-hooks creates executable pre-commit", async () => {
  const dir = makeRepo();
  try {
    const code = await runInstallHooks(dir);
    assert.equal(code, 0);
    const hookPath = join(dir, ".git", "hooks", "pre-commit");
    assert.ok(existsSync(hookPath));
    const content = readFileSync(hookPath, "utf8");
    assert.match(content, /ironward/);
    assert.match(content, /scan-secrets/);
    assert.match(content, /scan-code/);
    assert.match(content, /ironward pre-commit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install-hooks preserves a pre-existing pre-commit", async () => {
  const dir = makeRepo();
  try {
    const hookPath = join(dir, ".git", "hooks", "pre-commit");
    writeFileSync(hookPath, "#!/bin/sh\necho 'my custom hook'\n", "utf8");
    chmodSync(hookPath, 0o755);
    await runInstallHooks(dir);
    const content = readFileSync(hookPath, "utf8");
    assert.match(content, /my custom hook/);
    assert.match(content, /ironward/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install-hooks is idempotent (re-installing updates in-place)", async () => {
  const dir = makeRepo();
  try {
    await runInstallHooks(dir);
    await runInstallHooks(dir);
    const content = readFileSync(join(dir, ".git", "hooks", "pre-commit"), "utf8");
    // Ironward block should appear exactly once.
    const matches = content.match(/# >>> ironward pre-commit/g) ?? [];
    assert.equal(matches.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("uninstall-hooks removes the Ironward block while keeping custom hook content", async () => {
  const dir = makeRepo();
  try {
    const hookPath = join(dir, ".git", "hooks", "pre-commit");
    writeFileSync(hookPath, "#!/bin/sh\necho 'my custom hook'\n", "utf8");
    chmodSync(hookPath, 0o755);
    await runInstallHooks(dir);
    await runUninstallHooks(dir);
    const content = readFileSync(hookPath, "utf8");
    assert.doesNotMatch(content, /ironward/);
    assert.match(content, /my custom hook/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("uninstall-hooks deletes the file if only Ironward was there", async () => {
  const dir = makeRepo();
  try {
    await runInstallHooks(dir);
    await runUninstallHooks(dir);
    assert.equal(existsSync(join(dir, ".git", "hooks", "pre-commit")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install-hooks respects core.hooksPath (e.g. husky)", async () => {
  const dir = makeRepo();
  try {
    const customDir = join(dir, ".husky");
    mkdirSync(customDir, { recursive: true });
    execFileSync("git", ["config", "core.hooksPath", ".husky"], { cwd: dir });
    await runInstallHooks(dir);
    assert.ok(existsSync(join(customDir, "pre-commit")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install-hooks outside a git repo exits 2", async () => {
  const dir = mkdtempSync(join(tmpdir(), "not-a-repo-"));
  try {
    const code = await runInstallHooks(dir);
    assert.equal(code, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
