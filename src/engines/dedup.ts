import { createHash } from "node:crypto";

export interface LocationRef {
  path: string;
  line: number;
  column: number;
}

export interface FindingLike {
  type: string;
  match: string;
  line: number;
  column: number;
  duplicates?: LocationRef[];
  path?: string;
}

function valueHash(type: string, match: string): string {
  return createHash("sha256").update(type + ":" + match).digest("hex").slice(0, 16);
}

/**
 * Collapse findings that share the exact same secret value across files.
 * The first occurrence keeps full details; subsequent occurrences become
 * `duplicates` entries on that canonical finding.
 */
export function dedupByValue<T extends FindingLike>(
  findings: Array<{ path: string; finding: T }>,
): Array<{ path: string; finding: T }> {
  const canonical = new Map<string, { path: string; finding: T }>();
  const out: Array<{ path: string; finding: T }> = [];
  for (const entry of findings) {
    const h = valueHash(entry.finding.type, entry.finding.match);
    const existing = canonical.get(h);
    if (!existing) {
      canonical.set(h, entry);
      out.push(entry);
      continue;
    }
    const ref: LocationRef = {
      path: entry.path,
      line: entry.finding.line,
      column: entry.finding.column,
    };
    existing.finding.duplicates = existing.finding.duplicates ?? [];
    existing.finding.duplicates.push(ref);
  }
  return out;
}
