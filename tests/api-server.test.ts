import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import {
  startApiServer,
  InMemoryStore,
  type ApiStore,
} from "../src/integrations/api-server.ts";
import type { NormalizedFinding } from "../src/engines/sarif.ts";

function f(
  severity: NormalizedFinding["severity"],
  i = 0,
  file = `src/file${i}.ts`,
): NormalizedFinding {
  return {
    ruleId: `r-${severity}-${i}`,
    severity,
    title: `Issue ${i}`,
    description: "x",
    file,
    line: i + 1,
    tool: "scan_code",
  };
}

interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function get(host: string, port: number, path: string): Promise<RawResponse> {
  return doRequest(host, port, path, "GET");
}

function doRequest(
  host: string,
  port: number,
  path: string,
  method: string,
  body?: string,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host,
        port,
        path,
        method,
        headers: body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body).toString() } : {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const sample: NormalizedFinding[] = [
  f("critical", 1, "src/auth.ts"),
  f("high", 2, "src/render.ts"),
  f("medium", 3, "src/crypto.ts"),
];

test("/api/health returns 200 and { ok: true }", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/health");
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.ok, true);
  assert.ok(typeof body.version === "string");
});

test("/api/findings returns a JSON array", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/findings");
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.ok(Array.isArray(body));
  assert.equal(body.length, 3);
});

test("/api/findings?severity=critical filters", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/findings?severity=critical");
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body) as NormalizedFinding[];
  assert.equal(body.length, 1);
  assert.equal(body[0].severity, "critical");
});

test("/api/score returns { score, color } with score in [0,100]", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/score");
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body) as { score: number; color: string };
  assert.equal(typeof body.score, "number");
  assert.ok(body.score >= 0 && body.score <= 100);
  assert.ok(["brightgreen", "green", "yellow", "orange", "red"].includes(body.color));
});

test("/api/badge.svg returns 200 with image/svg+xml and body starting with <svg", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/badge.svg");
  assert.equal(res.status, 200);
  const ct = String(res.headers["content-type"] ?? "");
  assert.ok(ct.includes("image/svg+xml"), `expected image/svg+xml content-type, got: ${ct}`);
  assert.ok(res.body.startsWith("<svg"));
});

test("Unknown path returns 404", async (t) => {
  const { port, close } = await startApiServer({
    port: 0,
    store: new InMemoryStore({ findings: sample }),
  });
  t.after(async () => { await close(); });

  const res = await get("127.0.0.1", port, "/api/does-not-exist");
  assert.equal(res.status, 404);
  const body = JSON.parse(res.body);
  assert.equal(body.error, "not found");
});

test("POST /api/scan calls store.triggerScan once", async (t) => {
  let calls = 0;
  let receivedRepo: string | undefined;
  const spyStore: ApiStore = {
    health: async () => ({ ok: true }),
    findings: async () => sample,
    repos: async () => [],
    score: async () => 90,
    triggerScan: async (repo) => {
      calls++;
      receivedRepo = repo;
      return { ok: true, jobId: "spy-1" };
    },
    config: async () => ({}),
    badgeSvg: async () => "<svg></svg>",
  };

  const { port, close } = await startApiServer({ port: 0, store: spyStore });
  t.after(async () => { await close(); });

  const res = await doRequest("127.0.0.1", port, "/api/scan", "POST", JSON.stringify({ repo: "acme/widgets" }));
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.ok, true);
  assert.equal(body.jobId, "spy-1");
  assert.equal(calls, 1);
  assert.equal(receivedRepo, "acme/widgets");
});
