import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules } from "../src/engines/code-rules.ts";

test("firebase: flags allow read, write: if true", () => {
  const code = `match /users/{u} { allow read, write: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

test("firebase: flags allow read: if request.auth != null (no ownership)", () => {
  const code = `match /docs/{d} { allow read: if request.auth != null; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rules-auth-not-null"));
});

test("firebase: flags storage allow write: if true", () => {
  const code = `match /b/{file} { allow write: if true; }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-storage-allow-write-true"));
});

test("firebase: flags firebase-admin imported in 'use client' file", () => {
  const code = `'use client'
import { getApps } from 'firebase-admin/app';`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-admin-in-client"));
});

test("firebase: flags any firebase-admin import (browser-targeted check)", () => {
  const code = `import admin from 'firebase-admin';`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-admin-import-browser-file"));
});

test("firebase: flags NEXT_PUBLIC_ service account env", () => {
  const code = `const p = process.env.NEXT_PUBLIC_FIREBASE_SERVICE_ACCOUNT_PATH;`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-service-account-public-env"));
});

test("firebase: flags RTDB .read: true", () => {
  const code = `{ "rules": { "users": { ".read": "true" } } }`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-rtdb-read-true"));
});

test("firebase: flags signInAnonymously call", () => {
  const code = `await signInAnonymously(auth);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "firebase-anonymous-signin"));
});

test("firebase: does NOT flag allow read with ownership check", () => {
  const code = `allow read: if request.auth.uid == resource.data.userId;`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "firebase-rules-auth-not-null"));
  assert.ok(!f.some((x) => x.ruleId === "firebase-rules-allow-true"));
});

test("firebase: does NOT flag a server-only firebase client SDK import", () => {
  const code = `import { initializeApp } from 'firebase/app';`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "firebase-admin-import-browser-file"));
});
