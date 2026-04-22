import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const DEFAULT_PATH = join(homedir(), ".ironward", "ironward.db");

export function dbPath(): string {
  return process.env.IRONWARD_DB ?? DEFAULT_PATH;
}

let instance: Database.Database | null = null;

export function getDb(): Database.Database {
  if (instance) return instance;
  const p = dbPath();
  mkdirSync(dirname(p), { recursive: true });
  const db = new Database(p);
  db.pragma("journal_mode = WAL");
  migrate(db);
  instance = db;
  return db;
}

function hasColumn(db: Database.Database, table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((r) => r.name === column);
}

function migrate(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tool TEXT NOT NULL,
      started_at TEXT NOT NULL,
      duration_ms INTEGER,
      repo TEXT,
      target TEXT,
      findings_count INTEGER NOT NULL DEFAULT 0,
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo);
    CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool);

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      fingerprint TEXT NOT NULL,
      tool TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      path TEXT,
      line INTEGER,
      status TEXT NOT NULL DEFAULT 'open',
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      pr_url TEXT,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
    CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
  `);
  if (!hasColumn(db, "scans", "is_demo")) {
    db.exec(`ALTER TABLE scans ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0`);
  }
}

export interface WipeResult {
  scansDeleted: number;
  findingsDeleted: number;
}

export function wipe(opts: { demoOnly?: boolean } = {}): WipeResult {
  const db = getDb();
  const where = opts.demoOnly ? "WHERE is_demo = 1" : "";
  const deleteTx = db.transaction(() => {
    const scanIdsRows = db.prepare(`SELECT id FROM scans ${where}`).all() as Array<{ id: number }>;
    const scanIds = scanIdsRows.map((r) => r.id);
    if (scanIds.length === 0) return { scansDeleted: 0, findingsDeleted: 0 };
    const placeholders = scanIds.map(() => "?").join(",");
    const findingsRes = db.prepare(`DELETE FROM findings WHERE scan_id IN (${placeholders})`).run(...scanIds);
    const scansRes = db.prepare(`DELETE FROM scans WHERE id IN (${placeholders})`).run(...scanIds);
    return {
      scansDeleted: Number(scansRes.changes ?? 0),
      findingsDeleted: Number(findingsRes.changes ?? 0),
    };
  });
  return deleteTx();
}

export function demoRowCount(): number {
  const db = getDb();
  const row = db.prepare("SELECT COUNT(*) AS n FROM scans WHERE is_demo = 1").get() as { n: number };
  return row.n;
}
