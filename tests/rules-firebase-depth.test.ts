import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// =============================================================================
// Firestore allow ... if true (rule: firebase-rules-allow-true)
// =============================================================================

// WHY: combined read+write form is the most-shipped insecure default.
test("firebase-depth: allow read, write: if true is flagged", () => {
  const code = `match /docs/{d} { allow read, write: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

// WHY: read-only allow-true must also fire — the rule covers single-action.
test("firebase-depth: allow read: if true is flagged", () => {
  const code = `match /docs/{d} { allow read: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

// WHY: write-only allow-true must fire — anyone can overwrite anything.
test("firebase-depth: allow write: if true is flagged", () => {
  const code = `match /docs/{d} { allow write: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

// =============================================================================
// Bare auth check (rule: firebase-rules-auth-not-null)
// =============================================================================

// WHY: rules that only check auth!=null grant access to every signed-in user
// — must fire so devs add an ownership predicate.
test("firebase-depth: allow read: if request.auth != null is flagged", () => {
  const code = `match /docs/{d} { allow read: if request.auth != null; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-auth-not-null"));
});

// =============================================================================
// Proper ownership check (negative)
// =============================================================================

// WHY: an ownership predicate must NOT trip either of the dangerous-allow rules.
// This is the canonical safe pattern.
test("firebase-depth: allow read: if request.auth.uid == resource.data.ownerId is NOT flagged", () => {
  const code = `match /docs/{d} { allow read: if request.auth.uid == resource.data.ownerId; }`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "firebase-rules-auth-not-null"));
  assert.ok(!f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

// =============================================================================
// firebase-admin in client (rules: firebase-admin-import-browser-file,
// firebase-admin-in-client)
// =============================================================================

// WHY: ESM import form must fire the browser-file rule.
test("firebase-depth: import 'firebase-admin' (ESM) is flagged", () => {
  const code = `import admin from 'firebase-admin';`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-admin-import-browser-file"));
});

// WHY: CommonJS require form is the other half — document the gap if it isn't
// covered, since the regex is import-shaped.
test("firebase-depth: require('firebase-admin') CJS form is NOT flagged (documented gap)", () => {
  const code = `const admin = require('firebase-admin');`;
  const f = scanCodeRules(code);
  // TODO: actual behavior — firebase-admin-import-browser-file regex matches
  // `import ... from 'firebase-admin'` only. CJS require() variant slips past.
  // Add a require-form rule if this matters.
  assert.ok(!f.some((x) => x.ruleId === "firebase-admin-import-browser-file"));
});

// WHY: 'use client' + import is the explicit Next.js client-component case
// that must fire the in-client rule.
test("firebase-depth: 'use client' + firebase-admin import fires in-client rule", () => {
  const code = `'use client'
import { getApps } from 'firebase-admin/app';`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-admin-in-client"));
});

// =============================================================================
// Storage public (rule: firebase-storage-allow-write-true)
// =============================================================================

// WHY: storage match with allow write:true is the worst-case storage rule —
// any uploader can host arbitrary content under your bucket.
test("firebase-depth: match /{allPaths=**} { allow write: if true; } is flagged", () => {
  const code = `match /b/{allPaths=**} { allow write: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-storage-allow-write-true"));
});

// =============================================================================
// Anonymous sign-in (rule: firebase-anonymous-signin)
// =============================================================================

// WHY: signInAnonymously satisfies request.auth!=null without a real user —
// dangerous when paired with weak rules. Must fire.
test("firebase-depth: signInAnonymously() is flagged", () => {
  const code = `await signInAnonymously(auth);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-anonymous-signin"));
});

// =============================================================================
// Severity assertions for the critical firebase rules
// =============================================================================

// WHY: the two critical-by-design firebase rules must carry severity=critical
// so totals/exit codes don't silently drift.
test("firebase-depth: critical-severity firebase rules really are critical", () => {
  const ids = [
    "firebase-rules-allow-true",
    "firebase-storage-allow-write-true",
    "firebase-admin-in-client",
    "firebase-admin-import-browser-file",
    "firebase-admin-init-in-client",
    "firebase-service-account-public-env",
    "firebase-rtdb-read-true",
    "firebase-rtdb-write-true",
    "firebase-create-custom-token-client",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every firebase-category rule must carry an OWASP A0X:202Y tag — keeps
// SARIF and reporting output consistent.
test("firebase-depth: every firebase rule has an OWASP A0X:202Y tag", () => {
  const fbRules = CODE_RULES.filter((r) => r.category === "firebase");
  assert.ok(fbRules.length >= 10);
  for (const r of fbRules) {
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A0\d:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});
