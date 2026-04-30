/**
 * Local HTTP API server for Ironward — separate from the MCP server.
 *
 * Binds to 127.0.0.1 by default. The CORS allow-* header is set for the
 * dashboard's convenience and is only safe BECAUSE the server binds to
 * loopback; do NOT change the bind address without revisiting CORS.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { createRequire } from "node:module";
import type { NormalizedFinding } from "../engines/sarif.js";
import {
  computeSecurityScore,
  colorForScore,
  renderBadgeSvg,
  type BadgeColor,
} from "./badge.js";

let cachedVersion: string | undefined;
function readVersion(): string {
  if (cachedVersion) return cachedVersion;
  try {
    const req = createRequire(import.meta.url);
    const pkg = req("../../package.json") as { version?: string };
    cachedVersion = pkg.version ?? "0.0.0";
  } catch {
    cachedVersion = "0.0.0";
  }
  return cachedVersion;
}

export interface ApiStore {
  health(): Promise<{ ok: true }>;
  findings(filter?: { severity?: string; repo?: string }): Promise<NormalizedFinding[]>;
  repos(): Promise<string[]>;
  score(): Promise<number>;
  triggerScan(repo?: string): Promise<{ ok: boolean; jobId?: string; error?: string }>;
  config(): Promise<unknown>; // already-redacted (caller's responsibility)
  badgeSvg(): Promise<string>;
}

export interface ApiServerOpts {
  port: number;
  host?: string;
  store?: ApiStore;
}

export class InMemoryStore implements ApiStore {
  private _findings: NormalizedFinding[];
  private _repos: string[];

  constructor(initial?: { findings?: NormalizedFinding[]; repos?: string[] }) {
    this._findings = initial?.findings ?? [];
    this._repos = initial?.repos ?? [];
  }

  set(findings: NormalizedFinding[], repos?: string[]): void {
    this._findings = findings;
    if (repos) this._repos = repos;
  }

  async health(): Promise<{ ok: true }> {
    return { ok: true };
  }

  async findings(filter?: { severity?: string; repo?: string }): Promise<NormalizedFinding[]> {
    let out = this._findings.slice();
    if (filter?.severity) {
      const sev = filter.severity;
      out = out.filter((f) => f.severity === sev);
    }
    if (filter?.repo) {
      const r = filter.repo;
      out = out.filter((f) => f.file.includes(r));
    }
    return out;
  }

  async repos(): Promise<string[]> {
    return this._repos.slice();
  }

  async score(): Promise<number> {
    return computeSecurityScore(this._findings);
  }

  async triggerScan(_repo?: string): Promise<{ ok: boolean; jobId?: string; error?: string }> {
    void _repo;
    return { ok: true, jobId: `mem-${Date.now()}` };
  }

  async config(): Promise<unknown> {
    return {};
  }

  async badgeSvg(): Promise<string> {
    return renderBadgeSvg(await this.score());
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload).toString(),
    "access-control-allow-origin": "*",  // ironward-ignore
  });
  res.end(payload);
}

function sendSvg(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "content-type": "image/svg+xml; charset=utf-8",
    "content-length": Buffer.byteLength(body).toString(),
    "access-control-allow-origin": "*",  // ironward-ignore
  });
  res.end(body);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      chunks.push(c);
      total += c.length;
      if (total > 1_000_000) {
        req.destroy();
      }
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolve(undefined);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        resolve(undefined);
      }
    });
    req.on("error", () => resolve(undefined));
  });
}

export function createApiServer(opts: ApiServerOpts): Server {
  const store: ApiStore = opts.store ?? new InMemoryStore();

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    // Preflight CORS
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",  // ironward-ignore
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type",
      });
      res.end();
      return;
    }

    const rawUrl = req.url ?? "/";
    // URL needs a base; the value we pass doesn't escape the loopback.
    const url = new URL(rawUrl, "http://127.0.0.1");
    const pathname = url.pathname;
    const method = (req.method ?? "GET").toUpperCase();

    try {
      if (method === "GET" && pathname === "/api/health") {
        sendJson(res, 200, { ok: true, version: readVersion() });
        return;
      }

      if (method === "GET" && pathname === "/api/findings") {
        const sev = url.searchParams.get("severity") ?? undefined;
        const repo = url.searchParams.get("repo") ?? undefined;
        const list = await store.findings({ severity: sev, repo });
        sendJson(res, 200, list);
        return;
      }

      if (method === "GET" && pathname === "/api/findings/critical") {
        const list = await store.findings({ severity: "critical" });
        sendJson(res, 200, list);
        return;
      }

      if (method === "GET" && pathname === "/api/repos") {
        sendJson(res, 200, await store.repos());
        return;
      }

      if (method === "GET" && pathname === "/api/score") {
        const score = await store.score();
        const color: BadgeColor = colorForScore(score);
        sendJson(res, 200, { score, color });
        return;
      }

      if (method === "POST" && pathname === "/api/scan") {
        const body = (await readJsonBody(req)) as { repo?: string } | undefined;
        const result = await store.triggerScan(body?.repo);
        sendJson(res, result.ok ? 200 : 500, result);
        return;
      }

      if (method === "GET" && pathname === "/api/config") {
        sendJson(res, 200, await store.config());
        return;
      }

      if (method === "GET" && pathname === "/api/badge.svg") {
        sendSvg(res, 200, await store.badgeSvg());
        return;
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 500, {
        error: err instanceof Error ? err.message : "internal error",
      });
    }
  };

  return createServer((req, res) => {
    handler(req, res).catch(() => {
      try {
        sendJson(res, 500, { error: "internal error" });
      } catch {
        // response may already be sent
      }
    });
  });
}

/** Start and resolve when listening. */
export async function startApiServer(
  opts: ApiServerOpts,
): Promise<{ server: Server; port: number; close: () => Promise<void> }> {
  const server = createApiServer(opts);
  const host = opts.host ?? "127.0.0.1";

  await new Promise<void>((resolve, reject) => {
    const onError = (e: Error): void => {
      server.removeListener("listening", onListening);
      reject(e);
    };
    const onListening = (): void => {
      server.removeListener("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(opts.port, host);
  });

  const addr = server.address();
  const actualPort = typeof addr === "object" && addr ? addr.port : opts.port;

  const close = (): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });

  return { server, port: actualPort, close };
}
