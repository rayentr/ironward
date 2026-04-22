import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const scratch = mkdtempSync(join(tmpdir(), "ironward-cache-test-"));
process.env.HOME = scratch;
process.env.USERPROFILE = scratch;

const { ScanCache, sha256 } = await import("../src/engines/scan-cache.ts");

test("sha256 returns a hex string", () => {
  const h = sha256("hello");
  assert.match(h, /^[a-f0-9]{64}$/);
});

test("ScanCache.load returns an empty cache when no file exists", async () => {
  const c = await ScanCache.load();
  assert.deepEqual(c.stats(), { files: 0, entries: 0 });
});

test("ScanCache.store / lookup round-trip with matching hash", async () => {
  const c = await ScanCache.load();
  c.store("/tmp/foo.js", "scan_for_secrets", "deadbeef", [{ type: "aws_access_key", line: 1 }]);
  const hit = c.lookup<{ type: string; line: number }>("/tmp/foo.js", "scan_for_secrets", "deadbeef");
  assert.ok(hit);
  assert.equal(hit![0].type, "aws_access_key");
});

test("ScanCache.lookup returns null when hash differs", async () => {
  const c = await ScanCache.load();
  c.store("/tmp/foo.js", "scan_for_secrets", "deadbeef", [{ type: "aws_access_key" }]);
  const miss = c.lookup("/tmp/foo.js", "scan_for_secrets", "cafebabe");
  assert.equal(miss, null);
});

test("ScanCache.lookup separates entries by tool", async () => {
  const c = await ScanCache.load();
  c.store("/tmp/foo.js", "scan_for_secrets", "h1", [{ secrets: true }]);
  c.store("/tmp/foo.js", "scan_code", "h1", [{ code: true }]);
  const secrets = c.lookup<any>("/tmp/foo.js", "scan_for_secrets", "h1");
  const code = c.lookup<any>("/tmp/foo.js", "scan_code", "h1");
  assert.ok((secrets as any)![0].secrets);
  assert.ok((code as any)![0].code);
});

test("ScanCache.save + reload preserves entries", async () => {
  const c1 = await ScanCache.load();
  c1.store("/tmp/persist.js", "scan_for_secrets", "abc123", [{ a: 1 }]);
  await c1.save();

  const c2 = await ScanCache.load();
  const hit = c2.lookup<any>("/tmp/persist.js", "scan_for_secrets", "abc123");
  assert.ok(hit);
  assert.equal((hit as any)[0].a, 1);
});

test("ScanCache.prune removes dropped files", async () => {
  const c = await ScanCache.load();
  c.store("/tmp/keep.js", "scan_for_secrets", "h", []);
  c.store("/tmp/gone.js", "scan_for_secrets", "h", []);
  c.prune(new Set(["/tmp/keep.js"]));
  const gone = c.lookup("/tmp/gone.js", "scan_for_secrets", "h");
  const keep = c.lookup("/tmp/keep.js", "scan_for_secrets", "h");
  assert.equal(gone, null);
  assert.ok(keep);
});

test("IRONWARD_NO_CACHE disables the cache entirely", async () => {
  process.env.IRONWARD_NO_CACHE = "1";
  try {
    const c = await ScanCache.load();
    c.store("/tmp/nocache.js", "scan_for_secrets", "h", [{ x: 1 }]);
    const miss = c.lookup("/tmp/nocache.js", "scan_for_secrets", "h");
    assert.equal(miss, null);
  } finally {
    delete process.env.IRONWARD_NO_CACHE;
  }
});

process.on("exit", () => {
  try { rmSync(scratch, { recursive: true, force: true }); } catch {}
});
