import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("auth: flags jwt.sign without expiresIn", () => {
  const code = `jwt.sign({ sub: userId }, secret);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-sign-no-expires-in"));
});

test("auth: flags express-session with short literal secret", () => {
  const code = `app.use(session({ secret: "shh" }));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "express-session-short-secret"));
});

test("auth: flags express-session missing cookie config", () => {
  const code = `app.use(session({ secret: "averylongsecretthatisover32charsxxxx" }));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "express-session-missing-cookie-secure"));
});

test("auth: flags plaintext password compare", () => {
  const code = `if (user.password === req.body.password) { login(); }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "auth-plaintext-password-compare"));
});

test("auth: flags passport.authenticate without state option", () => {
  const code = `passport.authenticate("google", { scope: ["profile"] });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "oauth-passport-no-state-option"));
});

test("auth: flags OAuth callback reading req.query.code without state validation", () => {
  const code = `const code = req.query.code; const tokens = await exchange(code);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "oauth-callback-no-state-validation"));
});

test("auth: flags jwt.verify without algorithms allowlist", () => {
  const code = `const payload = jwt.verify(token, secret);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "jwt-verify-no-algorithms-option"));
});

test("auth: flags session id appended to URL", () => {
  const code = `const link = "https://example.com/page?sessionid=abc123def";`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "session-id-in-url-query"));
});

test("auth: does NOT flag jwt.sign with expiresIn", () => {
  const code = `jwt.sign({ sub: userId }, secret, { expiresIn: "15m" });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "jwt-sign-no-expires-in"));
});

test("auth: does NOT flag passport.authenticate with state: true", () => {
  const code = `passport.authenticate("google", { scope: ["profile"], state: true });`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "oauth-passport-no-state-option"));
});
