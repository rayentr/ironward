import { getDb } from "./db";

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface OverviewStats {
  totalScans: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixed: number;
  open: number;
  dismissed: number;
}

export function overviewStats(): OverviewStats {
  const db = getDb();
  const totalScans = (db.prepare("SELECT COUNT(*) AS n FROM scans").get() as { n: number }).n;
  const totalFindings = (db.prepare("SELECT COUNT(*) AS n FROM findings").get() as { n: number }).n;
  const sev = db
    .prepare(
      "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity",
    )
    .all() as Array<{ severity: string; n: number }>;
  const status = db
    .prepare("SELECT status, COUNT(*) AS n FROM findings GROUP BY status")
    .all() as Array<{ status: string; n: number }>;
  const byStatus = Object.fromEntries(status.map((r) => [r.status, r.n])) as Record<string, number>;
  const bySev = Object.fromEntries(sev.map((r) => [r.severity, r.n])) as Record<string, number>;
  return {
    totalScans,
    totalFindings,
    critical: bySev.critical ?? 0,
    high: bySev.high ?? 0,
    medium: bySev.medium ?? 0,
    low: bySev.low ?? 0,
    fixed: byStatus.fixed ?? 0,
    open: byStatus.open ?? 0,
    dismissed: byStatus.dismissed ?? 0,
  };
}

export interface FindingRow {
  id: number;
  scanId: number;
  tool: string;
  severity: string;
  title: string;
  description: string | null;
  path: string | null;
  line: number | null;
  status: string;
  firstSeenAt: string;
  lastSeenAt: string;
  prUrl: string | null;
  repo: string | null;
}

export function recentFindings(limit = 25): FindingRow[] {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT
         f.id,
         f.scan_id AS scanId,
         f.tool,
         f.severity,
         f.title,
         f.description,
         f.path,
         f.line,
         f.status,
         f.first_seen_at AS firstSeenAt,
         f.last_seen_at AS lastSeenAt,
         f.pr_url AS prUrl,
         s.repo AS repo
       FROM findings f
       JOIN scans s ON s.id = f.scan_id
       ORDER BY f.last_seen_at DESC
       LIMIT ?`,
    )
    .all(limit);
  return rows as FindingRow[];
}

export function allFindings(filter: { status?: string; severity?: string } = {}): FindingRow[] {
  const db = getDb();
  const clauses: string[] = [];
  const values: string[] = [];
  if (filter.status) { clauses.push("f.status = ?"); values.push(filter.status); }
  if (filter.severity) { clauses.push("f.severity = ?"); values.push(filter.severity); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  return db
    .prepare(
      `SELECT f.id, f.scan_id AS scanId, f.tool, f.severity, f.title, f.description,
              f.path, f.line, f.status,
              f.first_seen_at AS firstSeenAt, f.last_seen_at AS lastSeenAt, f.pr_url AS prUrl,
              s.repo AS repo
       FROM findings f JOIN scans s ON s.id = f.scan_id
       ${where}
       ORDER BY
         CASE f.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 ELSE 5 END,
         f.last_seen_at DESC`,
    )
    .all(...values) as FindingRow[];
}

export interface RepoSummary {
  repo: string;
  scansCount: number;
  lastScanAt: string;
  openFindings: number;
  critical: number;
  high: number;
  score: number;
}

export function repoSummaries(): RepoSummary[] {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT
         COALESCE(s.repo, '(unknown)') AS repo,
         COUNT(DISTINCT s.id) AS scansCount,
         MAX(s.started_at) AS lastScanAt,
         SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS openFindings,
         SUM(CASE WHEN f.status = 'open' AND f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN f.status = 'open' AND f.severity = 'high' THEN 1 ELSE 0 END) AS high
       FROM scans s
       LEFT JOIN findings f ON f.scan_id = s.id
       GROUP BY s.repo
       ORDER BY MAX(s.started_at) DESC`,
    )
    .all() as Array<Omit<RepoSummary, "score"> & { critical: number; high: number }>;
  return rows.map((r) => ({ ...r, score: computeScore(r.critical ?? 0, r.high ?? 0, r.openFindings ?? 0) }));
}

function computeScore(critical: number, high: number, open: number): number {
  const penalty = critical * 20 + high * 10 + Math.max(0, open - critical - high) * 2;
  return Math.max(0, Math.min(100, 100 - penalty));
}
