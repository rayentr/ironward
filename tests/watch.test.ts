import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { runWatch } = await import("../src/commands/watch.ts");

test("watch starts, can be aborted, and returns 0 when no blockers were seen", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ironward-watch-"));
  try {
    writeFileSync(join(dir, "safe.js"), "export const x = 1;\n", "utf8");

    const controller = new AbortController();
    // Abort immediately after ready — we just verify the command lifecycle.
    const exit = runWatch({
      root: dir,
      signal: controller.signal,
      onReady: () => controller.abort(),
      debounceMs: 10,
    });
    const code = await exit;
    assert.equal(code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("watch exits 2 when the path is not a directory", async () => {
  const code = await runWatch({ root: "/this/path/definitely/does/not/exist/at/all" });
  assert.equal(code, 2);
});
