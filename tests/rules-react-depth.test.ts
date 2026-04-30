import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: lock in that localStorage.setItem('token', ...) fires the
// react-localstorage-token rule — the canonical XSS-exposure pattern.
test("react-depth: localStorage.setItem('token', ...) is flagged", () => {
  const code = `localStorage.setItem('token', t);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "react-localstorage-token");
  assert.ok(finding, "expected react-localstorage-token");
  assert.equal(finding.severity, "high");
});

// WHY: document the gap — the rule only matches setItem, not getItem.
// If a future regression switches scope, this test will surface it.
test("react-depth: localStorage.getItem('token') is NOT flagged (documented gap)", () => {
  const code = `const t = localStorage.getItem('token');`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — react-localstorage-token regex only matches setItem.
  // getItem of a token name still leaks via XSS contextually but isn't
  // the write site. Document the gap; do not fail.
  assert.ok(!f.some((x) => x.ruleId === "react-localstorage-token"));
});

// WHY: jwt key name should fire (regex includes "jwt" alternative).
test("react-depth: localStorage.setItem('jwt', ...) is flagged", () => {
  const code = `localStorage.setItem('jwt', t);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-localstorage-token"));
});

// WHY: refreshToken key should fire — refresh\w* is in the regex alternation.
test("react-depth: localStorage.setItem('refreshToken', ...) is flagged", () => {
  const code = `localStorage.setItem('refreshToken', t);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-localstorage-token"));
});

// WHY: access_token starts with "auth"? No — starts with "access". The
// rule alternation is token|jwt|session|auth|refresh, so 'access_token'
// should NOT match react-localstorage-token. Document.
test("react-depth: localStorage.setItem('access_token', ...) is NOT flagged (documented gap)", () => {
  const code = `localStorage.setItem('access_token', t);`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — react-localstorage-token alternation does not
  // include "access". The 'access_token' name is a real-world variant that
  // slips past. Captured here for future tightening.
  assert.ok(!f.some((x) => x.ruleId === "react-localstorage-token"));
});

// WHY: JSX form of dangerouslySetInnerHTML must fire, this is the
// canonical XSS sink in React.
test("react-depth: JSX dangerouslySetInnerHTML with req.body is flagged", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: req.body.html }} />`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "react-dangerously-set-no-dompurify");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: React.createElement form is functionally equivalent but the regex
// requires the JSX `={{ __html: ...}}` shape — document the gap.
test("react-depth: React.createElement with dangerouslySetInnerHTML is NOT flagged (documented gap)", () => {
  const code = `React.createElement('div', { dangerouslySetInnerHTML: { __html: req.body.html }});`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — rule regex requires `={{ __html: ... }}`
  // (JSX prop syntax). The createElement object-literal form slips past.
  assert.ok(!f.some((x) => x.ruleId === "react-dangerously-set-no-dompurify"));
});

// WHY: the named-secret regex matches `const [<name>, ...` for password,
// token, secret, apiKey, jwt — useState('password') as a string arg is a
// different shape and should NOT trigger react-usestate-named-secret.
test("react-depth: useState('password') string arg does NOT match named-secret regex (documented)", () => {
  const code = `const initial = useState('password');`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — react-usestate-named-secret looks for the
  // destructured const-array pattern `const [password, ...`. Plain
  // useState('password') does not match.
  assert.ok(!f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: the destructured form for password is the high-signal hit and
// must continue to fire.
test("react-depth: const [password, setPassword] = useState() is flagged", () => {
  const code = `const [password, setPassword] = useState('');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: token name in destructured useState should fire.
test("react-depth: const [token, setToken] = useState() is flagged", () => {
  const code = `const [token, setToken] = useState();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: secret name in destructured useState should fire.
test("react-depth: const [secret, setSecret] = useState() is flagged", () => {
  const code = `const [secret, setSecret] = useState(null);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: apiKey is in the regex alternation.
test("react-depth: const [apiKey, setApiKey] = useState() is flagged", () => {
  const code = `const [apiKey, setApiKey] = useState('');`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: a generic state name like userName must NOT trigger the rule —
// false positives here would be very noisy.
test("react-depth: const [userName, setUserName] = useState() is NOT flagged", () => {
  const code = `const [userName, setUserName] = useState('');`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: count / isOpen are common UI state — must stay quiet.
test("react-depth: useState('count') / useState('isOpen') do NOT flag", () => {
  const code = `
    const [count, setCount] = useState(0);
    const [isOpen, setIsOpen] = useState(false);
  `;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

// WHY: console.log of password identifier must fire (the workhorse pattern).
test("react-depth: console.log(password) is flagged", () => {
  const code = ["console.log(password);"].join("");
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-console-log-state-secret"));
});

// WHY: react rule regex specifically is `console.log` only — debug/info
// are not in the alternation. Document the gap.
test("react-depth: console.debug(token) is NOT flagged by react rule (documented)", () => {
  const code = `console.debug(token);`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — react-console-log-state-secret regex hardcodes
  // `console.log`. console.debug/info slip past. There IS a separate global
  // console-log-secret rule that may catch some shapes; this assertion is
  // scoped to the react-specific rule.
  assert.ok(!f.some((x) => x.ruleId === "react-console-log-state-secret"));
});

// WHY: confirm console.log of jwt also fires (alternation is password|token|secret|jwt|apiKey).
test("react-depth: console.log(jwt) is flagged", () => {
  const code = ["console.log(jwt);"].join("");
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-console-log-state-secret"));
});

// WHY: every react rule must carry an OWASP tag in A\d{1,2}:202Y form so
// the SARIF output stays consistent (note: A10:2021 — SSRF — is two-digit).
test("react-depth: every react rule has OWASP AN:202Y tag", () => {
  const reactRules = CODE_RULES.filter((r) => r.category === "react");
  assert.ok(reactRules.length >= 10);
  for (const r of reactRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{1,2}:202\d\b/, `${r.id} owasp not in AN:202Y form`);
  }
});

// WHY: the dangerouslySetInnerHTML rule is the only critical-severity
// react rule; lock in its severity.
test("react-depth: react-dangerously-set-no-dompurify carries severity=critical", () => {
  const r = ruleById("react-dangerously-set-no-dompurify");
  assert.ok(r);
  assert.equal(r.severity, "critical");
  assert.ok(r.confidence != null && r.confidence >= 60);
});
