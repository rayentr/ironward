import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("react: flags localStorage.setItem with token key", () => {
  const code = `localStorage.setItem("token", value);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-localstorage-token"));
});

test("react: flags localStorage.setItem with jwt key", () => {
  const code = `localStorage.setItem("jwt_user", value);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-localstorage-token"));
});

test("react: flags sessionStorage.setItem with auth key", () => {
  const code = `sessionStorage.setItem("auth", value);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-sessionstorage-token"));
});

test("react: flags useState variable named password", () => {
  const code = `const [password, setPassword] = useState("");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-usestate-named-secret"));
});

test("react: flags dangerouslySetInnerHTML without DOMPurify", () => {
  const code = `<div dangerouslySetInnerHTML={{ __html: rawHtml }} />`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-dangerously-set-no-dompurify"));
});

test("react: flags window.location assigned from user input", () => {
  const code = `window.location = user.target;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "react-window-location-user"));
});

test("react: does NOT flag localStorage.setItem for non-secret key", () => {
  const code = `localStorage.setItem("theme", "dark");`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "react-localstorage-token"));
});
