import { getDb } from "../src/lib/db";

const db = getDb();

const scans: Array<{
  tool: string;
  started_at: string;
  duration_ms: number;
  repo: string;
  target: string;
  findings: Array<{
    fingerprint: string;
    severity: string;
    title: string;
    description: string;
    path: string;
    line: number | null;
    status?: string;
    pr_url?: string;
  }>;
}> = [
  {
    tool: "scan_for_secrets",
    started_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    duration_ms: 182,
    repo: "rayentr/myapp",
    target: "src/",
    findings: [
      {
        fingerprint: "aws:src/auth.ts:14",
        severity: "critical",
        title: "AWS access key in auth.ts",
        description: "Hardcoded AKIA* access key committed to repo.",
        path: "src/auth.ts",
        line: 14,
        status: "fixed",
        pr_url: "https://github.com/rayentr/myapp/pull/81",
      },
      {
        fingerprint: "stripe:src/config.ts:7",
        severity: "critical",
        title: "Stripe live secret in config.ts",
        description: "sk_live_* key in plaintext.",
        path: "src/config.ts",
        line: 7,
        status: "open",
      },
    ],
  },
  {
    tool: "scan_idor",
    started_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    duration_ms: 1850,
    repo: "rayentr/myapp",
    target: "src/routes/invoice.ts",
    findings: [
      {
        fingerprint: "idor:src/routes/invoice.ts:12",
        severity: "high",
        title: "Missing ownership check on GET /api/invoice/:id",
        description: "Resource fetched by ID from request without verifying the requester owns it.",
        path: "src/routes/invoice.ts",
        line: 12,
        status: "open",
      },
    ],
  },
  {
    tool: "scan_deps",
    started_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    duration_ms: 4210,
    repo: "rayentr/api-server",
    target: "package.json",
    findings: [
      {
        fingerprint: "dep:lodash@4.17.15:GHSA-p6mc",
        severity: "critical",
        title: "Prototype pollution in lodash@4.17.15 (GHSA-p6mc-m468-83gw)",
        description: "Upgrade to 4.17.21+.",
        path: "package.json",
        line: null,
        status: "open",
      },
      {
        fingerprint: "dep:express@4.17.1:CVE-2024-29041",
        severity: "medium",
        title: "Open redirect in express@4.17.1",
        description: "Upgrade to 4.19.2+.",
        path: "package.json",
        line: null,
        status: "open",
      },
    ],
  },
  {
    tool: "scan_xss",
    started_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
    duration_ms: 1200,
    repo: "rayentr/landing",
    target: "src/",
    findings: [],
  },
];

const insertScan = db.prepare(
  `INSERT INTO scans (tool, started_at, duration_ms, repo, target,
    findings_count, critical_count, high_count, medium_count, low_count, is_demo)
   VALUES (@tool, @started_at, @duration_ms, @repo, @target,
    @findings_count, @critical_count, @high_count, @medium_count, @low_count, 1)`,
);

const insertFinding = db.prepare(
  `INSERT INTO findings
     (scan_id, fingerprint, tool, severity, title, description, path, line, status,
      first_seen_at, last_seen_at, pr_url)
   VALUES (@scan_id, @fingerprint, @tool, @severity, @title, @description, @path, @line, @status,
      @first_seen_at, @last_seen_at, @pr_url)`,
);

// Only wipe pre-existing demo rows so real recorded scans are preserved.
const demoScanIds = db.prepare("SELECT id FROM scans WHERE is_demo = 1").all() as Array<{ id: number }>;
if (demoScanIds.length) {
  const ids = demoScanIds.map((r) => r.id);
  const ph = ids.map(() => "?").join(",");
  db.prepare(`DELETE FROM findings WHERE scan_id IN (${ph})`).run(...ids);
  db.prepare(`DELETE FROM scans WHERE id IN (${ph})`).run(...ids);
}

for (const s of scans) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of s.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const scanRes = insertScan.run({
    tool: s.tool,
    started_at: s.started_at,
    duration_ms: s.duration_ms,
    repo: s.repo,
    target: s.target,
    findings_count: s.findings.length,
    critical_count: counts.critical ?? 0,
    high_count: counts.high ?? 0,
    medium_count: counts.medium ?? 0,
    low_count: counts.low ?? 0,
  });
  const scanId = Number(scanRes.lastInsertRowid);
  for (const f of s.findings) {
    insertFinding.run({
      scan_id: scanId,
      fingerprint: f.fingerprint,
      tool: s.tool,
      severity: f.severity,
      title: f.title,
      description: f.description,
      path: f.path,
      line: f.line,
      status: f.status ?? "open",
      first_seen_at: s.started_at,
      last_seen_at: s.started_at,
      pr_url: f.pr_url ?? null,
    });
  }
}

const total = (db.prepare("SELECT COUNT(*) AS n FROM findings").get() as { n: number }).n;
console.log(`Seeded ${scans.length} scans and ${total} findings.`);
