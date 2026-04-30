import { test } from "node:test";
import assert from "node:assert/strict";
import { WEBSOCKET_RULES } from "../src/rules/websocket.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = WEBSOCKET_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    return true;
  }
  return false;
}

// WHY: a connection handler that does not even mention `origin` is the canonical
// vulnerable shape — must fire.
test("ws-no-origin-check: connection handler with no origin reference is flagged", () => {
  const code = `
    const wss = new WebSocketServer({ port: 8080 });
    wss.on('connection', (ws, req) => {
      ws.send('hi');
    });
  `;
  assert.equal(fire(code, "ws-no-origin-check"), true);
});

// WHY: when the handler does check req.headers.origin, the rule must NOT fire.
test("ws-no-origin-check: handler that checks origin is NOT flagged", () => {
  const code = `
    wss.on('connection', (ws, req) => {
      const origin = req.headers.origin;
      if (origin !== 'https://app.example.com') return ws.close();
    });
  `;
  assert.equal(fire(code, "ws-no-origin-check"), false);
});

// WHY: lock metadata so CLI exit codes / OWASP reports stay correct.
test("ws-no-origin-check: metadata is well-formed", () => {
  const r = WEBSOCKET_RULES.find((x) => x.id === "ws-no-origin-check")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: a connection handler that immediately wires up `message` without any auth
// keyword in scope is the textbook unauth WebSocket.
test("ws-no-auth-on-connect: connect+message without auth is flagged", () => {
  const code = `
    wss.on('connection', (ws, req) => {
      ws.on('message', (data) => {
        process(data);
      });
    });
  `;
  assert.equal(fire(code, "ws-no-auth-on-connect"), true);
});

// WHY: presence of a token / verify call between connection and message must
// suppress the finding.
test("ws-no-auth-on-connect: handler that verifies a JWT first is NOT flagged", () => {
  const code = `
    wss.on('connection', (ws, req) => {
      const token = req.url.split('token=')[1];
      const user = verifyJwt(token);
      if (!user) return ws.close();
      ws.on('message', (data) => process(data));
    });
  `;
  assert.equal(fire(code, "ws-no-auth-on-connect"), false);
});

// WHY: severity drift would silently downgrade an auth bypass — guard it.
test("ws-no-auth-on-connect: metadata is well-formed", () => {
  const r = WEBSOCKET_RULES.find((x) => x.id === "ws-no-auth-on-connect")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: classic broadcast leak — every client gets every other user's data.
test("ws-broadcast-includes-user-data: forEach with user.email is flagged", () => {
  const code = `
    wss.clients.forEach(client => {
      client.send(JSON.stringify({ name: user.email }));
    });
  `;
  assert.equal(fire(code, "ws-broadcast-includes-user-data"), true);
});

// WHY: a generic broadcast (no user.* in the body) is fine and must not flag.
test("ws-broadcast-includes-user-data: forEach broadcasting a static ping is NOT flagged", () => {
  const code = `
    wss.clients.forEach(client => {
      client.send('ping');
    });
  `;
  assert.equal(fire(code, "ws-broadcast-includes-user-data"), false);
});

// WHY: keep severity locked at high — broadcast leaks are not low.
test("ws-broadcast-includes-user-data: metadata is well-formed", () => {
  const r = WEBSOCKET_RULES.find((x) => x.id === "ws-broadcast-includes-user-data")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: JSON.parse of attacker-controlled frames without try/catch crashes the
// handler and skips schema validation.
test("ws-message-no-validation: message handler with bare JSON.parse is flagged", () => {
  const code = `
    ws.on('message', (data) => {
      const msg = JSON.parse(data);
      handle(msg);
    });
  `;
  assert.equal(fire(code, "ws-message-no-validation"), true);
});

// WHY: try/catch around the parse is the documented mitigation; must not flag.
test("ws-message-no-validation: try/catch around JSON.parse is NOT flagged", () => {
  const code = `
    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data);
        handle(msg);
      } catch (e) { ws.send('bad json'); }
    });
  `;
  assert.equal(fire(code, "ws-message-no-validation"), false);
});

// WHY: medium severity is the right tier — DoS but not RCE.
test("ws-message-no-validation: metadata is well-formed", () => {
  const r = WEBSOCKET_RULES.find((x) => x.id === "ws-message-no-validation")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: eval inside a message handler is the most direct RCE shape we can detect.
test("ws-eval-in-handler: eval() inside ws.on('message') is flagged", () => {
  const code = `
    ws.on('message', (data) => {
      eval(data.toString());
    });
  `;
  assert.equal(fire(code, "ws-eval-in-handler"), true);
});

// WHY: a benign handler that does NOT call eval / new Function must stay clean.
test("ws-eval-in-handler: handler with only JSON.parse is NOT flagged", () => {
  const code = `
    ws.on('message', (data) => {
      const obj = JSON.parse(data);
    });
  `;
  assert.equal(fire(code, "ws-eval-in-handler"), false);
});

// WHY: severity must remain critical — direct RCE.
test("ws-eval-in-handler: metadata is well-formed (critical)", () => {
  const r = WEBSOCKET_RULES.find((x) => x.id === "ws-eval-in-handler")!;
  assert.equal(r.severity, "critical");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
