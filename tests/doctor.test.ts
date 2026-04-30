import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

// The doctor command does live network probes (Ollama at localhost:11434, file system
// checks). We only verify the formatting / exit behaviour here — not the actual host state.
//
// To keep tests deterministic, we invoke the built CLI as a subprocess with custom
// IRONWARD_CONFIG_PATH and HOME pointed at a tmp dir. This isolates from any real config.

test("doctor: prints the version banner and an Overall: line", async () => {
  const home = await mkdtemp(join(tmpdir(), "iw-doctor-"));
  try {
    const cliPath = join(process.cwd(), "dist", "bin.js");
    const result = spawnSync("node", [cliPath, "doctor"], {
      env: {
        ...process.env,
        HOME: home,
        IRONWARD_CONFIG_PATH: join(home, "config.json"),
      },
      encoding: "utf8",
      timeout: 10000,
    });
    assert.match(result.stdout, /Ironward v[\d.]+ — System Check/);
    assert.match(result.stdout, /Overall:/);
    assert.match(result.stdout, /Offline tools/);
    assert.match(result.stdout, /AI tools/);
    assert.match(result.stdout, /Local AI \(Ollama\)/);
    assert.match(result.stdout, /Integrations/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("doctor: marks integrations not configured when config is empty", async () => {
  const home = await mkdtemp(join(tmpdir(), "iw-doctor-"));
  try {
    await writeFile(join(home, "config.json"), "{}");
    const cliPath = join(process.cwd(), "dist", "bin.js");
    const result = spawnSync("node", [cliPath, "doctor"], {
      env: {
        ...process.env,
        HOME: home,
        IRONWARD_CONFIG_PATH: join(home, "config.json"),
      },
      encoding: "utf8",
      timeout: 10000,
    });
    assert.match(result.stdout, /Slack: Not configured/);
    assert.match(result.stdout, /Linear: Not configured/);
    assert.match(result.stdout, /Jira: Not configured/);
    assert.match(result.stdout, /Email: Not configured/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
