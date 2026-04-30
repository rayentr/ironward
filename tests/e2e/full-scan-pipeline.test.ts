import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const cliPath = join(process.cwd(), "dist", "bin.js");

function run(args: string[], cwd: string): { code: number; stdout: string; stderr: string } {
  const r = spawnSync("node", [cliPath, ...args], { cwd, encoding: "utf8", timeout: 30000 });
  return { code: r.status ?? 1, stdout: r.stdout, stderr: r.stderr };
}

async function makeProject(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "iw-e2e-"));
  await mkdir(join(root, "src", "api"), { recursive: true });
  await mkdir(join(root, "src", "lib"), { recursive: true });

  // Vulnerability 1: SSRF in fetch handler
  await writeFile(
    join(root, "src", "api", "proxy.ts"),
    `import express from 'express';
const app = express();
app.get('/api/proxy', async (req, res) => {
  const data = await fetch(req.body.url);
  res.json(await data.json());
});
`,
  );

  // Vulnerability 2: hardcoded AWS key (a clearly synthetic one)
  await writeFile(
    join(root, "src", "lib", "config.ts"),
    `export const AWS_ACCESS_KEY = "AKIA2E0A8F3B244C9986";\n`,
  );

  // Vulnerability 3: jwt alg none
  await writeFile(
    join(root, "src", "lib", "auth.ts"),
    `import jwt from 'jsonwebtoken';
export function verify(token: string, secret: string) {
  const opts = { alg: 'none' as const };
  return jwt.verify(token, secret, opts);
}
`,
  );

  // Vulnerability 4: SQL string concat with req.body
  await writeFile(
    join(root, "src", "api", "users.ts"),
    `import express from 'express';
const app = express();
app.post('/api/users', async (req, res) => {
  const sql = "SELECT * FROM users WHERE id = " + req.body.id;
  const rows = await db.query(sql);
  res.json(rows);
});
`,
  );

  // Vulnerability 5: weak crypto (MD5)
  await writeFile(
    join(root, "src", "lib", "hash.ts"),
    `import { createHash } from 'crypto';
export const sign = (s: string) => createHash('md5').update(s).digest('hex');
`,
  );

  // Clean file (must NOT produce findings)
  await writeFile(
    join(root, "src", "lib", "math.ts"),
    `export const sum = (a: number, b: number): number => a + b;\nexport const mul = (a: number, b: number): number => a * b;\n`,
  );

  return root;
}

test("e2e: full pipeline detects all 5 intentional vulnerabilities", async () => {
  // WHY: this is the headline regression test for the whole pipeline. If any of the 5
  // canonical vulnerabilities slip through after a refactor, the suite fails loudly.
  const root = await makeProject();
  try {
    const r = run(["scan", "."], root);
    assert.notEqual(r.code, 0, `expected non-zero exit on findings, got ${r.code}`);
    assert.match(r.stdout, /AKIA/i, "expected AWS key finding to surface");
    // ssrf-fetch
    assert.match(r.stdout, /ssrf|fetch/i, "expected SSRF finding");
    // jwt-alg-none
    assert.match(r.stdout, /alg.*none|jwt-alg-none/i, "expected JWT alg:none finding");
    // sql-string-concat
    assert.match(r.stdout, /sql-string-concat|SQL/i, "expected SQL injection finding");
    // md5-hash
    assert.match(r.stdout, /md5/i, "expected MD5 finding");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --format json output is valid JSON with findings array", async () => {
  // WHY: external tools and CI rely on the JSON shape. Lock in that scan-code emits
  // valid JSON with a `files[].findings[]` structure.
  const root = await makeProject();
  try {
    const r = run(["scan-code", "src", "--format", "json"], root);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.tool, "scan_code");
    assert.ok(Array.isArray(parsed.files), "expected files array");
    const allFindings = parsed.files.flatMap((f: any) => f.findings ?? []);
    assert.ok(allFindings.length >= 4, `expected ≥4 code findings across the project, got ${allFindings.length}`);
    for (const f of allFindings) {
      assert.equal(typeof f.ruleId, "string");
      assert.equal(typeof f.line, "number");
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --format sarif emits valid SARIF 2.1.0 with rules + results", async () => {
  // WHY: GitHub's Security tab consumes SARIF — the structure is contractually fixed.
  const root = await makeProject();
  try {
    const r = run(["scan-code", "src", "--format", "sarif"], root);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.version, "2.1.0");
    assert.ok(Array.isArray(parsed.runs) && parsed.runs.length === 1);
    const run0 = parsed.runs[0];
    assert.equal(run0.tool.driver.name, "Ironward");
    assert.ok(Array.isArray(run0.tool.driver.rules), "rules array present");
    assert.ok(Array.isArray(run0.results), "results array present");
    assert.ok(run0.results.length >= 4);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --exploit attaches PoC + CVSS to each code finding", async () => {
  // WHY: locks in the Phase 2 exploit attachment — every finding under --exploit must
  // carry the structured exploit object.
  const root = await makeProject();
  try {
    const r = run(["scan-code", "src", "--exploit", "--format", "json"], root);
    const parsed = JSON.parse(r.stdout);
    const allFindings = parsed.files.flatMap((f: any) => f.findings ?? []);
    const withExploit = allFindings.filter((f: any) => f.exploit);
    assert.ok(withExploit.length >= 4, `expected ≥4 findings with exploit, got ${withExploit.length}`);
    for (const f of withExploit) {
      assert.match(f.exploit.cvssVector, /^CVSS:3\.1\//);
      assert.ok(f.exploit.cvss >= 0 && f.exploit.cvss <= 10);
      assert.match(f.exploit.cwe, /^CWE-\d+/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: clean directory exits 0 with no findings", async () => {
  // WHY: regression guard against a rule that fires on safe code. A truly clean project
  // must produce zero findings and exit 0.
  const root = await mkdtemp(join(tmpdir(), "iw-e2e-clean-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src", "math.ts"),
      `export const sum = (a: number, b: number): number => a + b;\n`);
    const r = run(["scan-code", "src"], root);
    assert.equal(r.code, 0, `expected exit 0 on clean code, got ${r.code} | stdout: ${r.stdout}`);
    assert.match(r.stdout, /no issues|0 findings/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: package.json with known malware fires the supply-chain MALWARE finding", async () => {
  // WHY: locks in the bundled malware DB end-to-end through scan-deps.
  const root = await mkdtemp(join(tmpdir(), "iw-e2e-deps-"));
  try {
    await writeFile(join(root, "package.json"),
      JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { "event-stream": "3.3.6" } }));
    const r = run(["scan-deps", "package.json"], root);
    assert.match(r.stdout, /MALWARE|event-stream/i);
    assert.notEqual(r.code, 0, `expected non-zero exit on critical malware, got ${r.code}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
