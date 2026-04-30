import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("python: flags eval() with f-string or request input", () => {
  const code = `result = eval(f"some {user_input}")`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-eval-user-input"));
});

test("python: flags marshal.loads on user data", () => {
  const code = `data = marshal.loads(request.data)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-marshal-loads"));
});

test("python: flags SQL via f-string", () => {
  const code = `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-sql-fstring"));
});

test("python: flags os.system with request input", () => {
  const code = `os.system(request.args.get("cmd"))`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-os-system-user"));
});

test("python: flags hardcoded Flask SECRET_KEY", () => {
  const code = `app.config["SECRET_KEY"] = "dev"\nSECRET_KEY = "changeme"`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-flask-secret-hardcoded"));
});

test("python: flags requests.get with verify=False", () => {
  const code = `r = requests.get("https://internal.example.com", verify=False)`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-requests-verify-false"));
});

test("python: flags importlib.import_module with user input", () => {
  const code = `mod = importlib.import_module(request.args.get("name"))`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-importlib-user-module"));
});

test("python: flags Django ALLOWED_HOSTS = ['*']", () => {
  const code = `ALLOWED_HOSTS = ["*"]`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "py-django-allowed-hosts-wildcard"));
});

test("python: does NOT flag parameterized SQL", () => {
  const code = `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-sql-fstring"));
});

test("python: does NOT flag requests.get with verify=True", () => {
  const code = `r = requests.get("https://api.example.com", verify=True)`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "py-requests-verify-false"));
});
