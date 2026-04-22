import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

interface IngestFinding {
  fingerprint: string;
  severity: string;
  title: string;
  description?: string;
  path?: string;
  line?: number | null;
  status?: string;
  pr_url?: string;
}

interface IngestBody {
  tool: string;
  started_at?: string;
  duration_ms?: number;
  repo?: string | null;
  target?: string | null;
  findings: IngestFinding[];
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => null)) as IngestBody | null;
  if (!body || !body.tool || !Array.isArray(body.findings)) {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  const db = getDb();
  const now = new Date().toISOString();
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of body.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const scanRes = db
    .prepare(
      `INSERT INTO scans (tool, started_at, duration_ms, repo, target,
         findings_count, critical_count, high_count, medium_count, low_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      body.tool,
      body.started_at ?? now,
      body.duration_ms ?? null,
      body.repo ?? null,
      body.target ?? null,
      body.findings.length,
      counts.critical ?? 0,
      counts.high ?? 0,
      counts.medium ?? 0,
      counts.low ?? 0,
    );
  const scanId = Number(scanRes.lastInsertRowid);

  const findStmt = db.prepare(
    `SELECT id, first_seen_at FROM findings WHERE fingerprint = ? ORDER BY id DESC LIMIT 1`,
  );
  const insertStmt = db.prepare(
    `INSERT INTO findings
       (scan_id, fingerprint, tool, severity, title, description, path, line, status,
        first_seen_at, last_seen_at, pr_url)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const f of body.findings) {
    const prev = findStmt.get(f.fingerprint) as { id: number; first_seen_at: string } | undefined;
    insertStmt.run(
      scanId,
      f.fingerprint,
      body.tool,
      f.severity,
      f.title,
      f.description ?? null,
      f.path ?? null,
      f.line ?? null,
      f.status ?? "open",
      prev?.first_seen_at ?? body.started_at ?? now,
      now,
      f.pr_url ?? null,
    );
  }

  return NextResponse.json({ ok: true, scanId, ingested: body.findings.length });
}

export async function GET() {
  return NextResponse.json({ ok: true, message: "POST a scan payload here." });
}
