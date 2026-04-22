export type OsvEcosystem = "npm" | "PyPI" | "RubyGems" | "Go" | "Maven" | "NuGet" | "crates.io" | "Packagist";

export interface OsvQueryRequest {
  package: { name: string; ecosystem: OsvEcosystem };
  version?: string;
}

export interface OsvSeverity {
  type: string;
  score: string;
}

export interface OsvAffectedRange {
  type?: string;
  events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

export interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
  published?: string;
  modified?: string;
}

export interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

export type Fetcher = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

const OSV_ENDPOINT = "https://api.osv.dev/v1/query";

export class OsvClient {
  constructor(private fetchImpl: Fetcher = defaultFetch) {}

  async query(req: OsvQueryRequest): Promise<OsvVuln[]> {
    const res = await this.fetchImpl(OSV_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`OSV query failed: ${res.status}`);
    const data = (await res.json()) as OsvQueryResponse;
    return data.vulns ?? [];
  }
}

async function defaultFetch(
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) {
  const res = await fetch(url, init);
  return {
    ok: res.ok,
    status: res.status,
    json: () => res.json() as Promise<unknown>,
  };
}

export function highestSeverity(vuln: OsvVuln): "critical" | "high" | "medium" | "low" | "unknown" {
  if (!vuln.severity || vuln.severity.length === 0) return "unknown";
  let best = 0;
  for (const s of vuln.severity) {
    const num = parseCvssBaseScore(s.score);
    if (num > best) best = num;
  }
  if (best >= 9.0) return "critical";
  if (best >= 7.0) return "high";
  if (best >= 4.0) return "medium";
  if (best > 0) return "low";
  return "unknown";
}

function parseCvssBaseScore(cvssVector: string): number {
  const m = cvssVector.match(/\bCVSS:[0-9.]+/);
  if (!m) {
    const asNum = Number(cvssVector);
    return Number.isFinite(asNum) ? asNum : 0;
  }
  const env = cvssVector.match(/\/E:([HFUPNX])/i);
  const base = cvssVector.match(/\/BASE:([0-9.]+)/i);
  if (base) return Number(base[1]) || 0;
  void env;
  return 0;
}

export function fixedVersions(vuln: OsvVuln, ecosystem: OsvEcosystem, pkgName: string): string[] {
  const fixes: string[] = [];
  for (const aff of vuln.affected ?? []) {
    if (aff.package && aff.package.name && aff.package.name.toLowerCase() !== pkgName.toLowerCase()) continue;
    if (aff.package && aff.package.ecosystem && aff.package.ecosystem !== ecosystem) continue;
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) fixes.push(ev.fixed);
      }
    }
  }
  return [...new Set(fixes)].sort();
}
