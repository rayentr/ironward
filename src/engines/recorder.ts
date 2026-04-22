import { createHash } from "node:crypto";

export interface RecorderFinding {
  fingerprint: string;
  severity: string;
  title: string;
  description?: string;
  path?: string;
  line?: number | null;
  status?: "open" | "fixed" | "dismissed";
  pr_url?: string;
}

export interface RecorderPayload {
  tool: string;
  repo?: string | null;
  target?: string | null;
  started_at?: string;
  duration_ms?: number;
  findings: RecorderFinding[];
}

function fingerprint(tool: string, path: string | undefined, line: number | null | undefined, key: string): string {
  return createHash("sha256")
    .update(`${tool}|${path ?? ""}|${line ?? ""}|${key}`)
    .digest("hex")
    .slice(0, 16);
}

export function fingerprintFor(tool: string, path: string | undefined, line: number | null | undefined, key: string): string {
  return fingerprint(tool, path, line, key);
}

function getEndpoint(): string | null {
  const explicit = process.env.IRONWARD_DASHBOARD_URL;
  if (explicit) return explicit.replace(/\/$/, "") + "/api/ingest";
  if (process.env.IRONWARD_RECORD === "1") return "http://localhost:3737/api/ingest";
  return null;
}

export async function record(payload: RecorderPayload): Promise<{ ok: boolean; error?: string }> {
  const endpoint = getEndpoint();
  if (!endpoint) return { ok: false, error: "no dashboard endpoint configured (set IRONWARD_RECORD=1 or IRONWARD_DASHBOARD_URL)" };
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export function isRecordingEnabled(): boolean {
  return getEndpoint() !== null;
}
