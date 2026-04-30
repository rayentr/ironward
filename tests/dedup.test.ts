import { test } from "node:test";
import assert from "node:assert/strict";
import { dedupByValue } from "../src/engines/dedup.ts";

type F = { type: string; match: string; line: number; column: number; duplicates?: Array<{ path: string; line: number; column: number }> };

test("dedupByValue collapses same-value findings across files", () => {
  const in_ = [
    { path: "a.js", finding: { type: "aws_access_key", match: "AKIA1234567890ABCDEF", line: 10, column: 1 } as F },
    { path: "b.js", finding: { type: "aws_access_key", match: "AKIA1234567890ABCDEF", line: 20, column: 1 } as F },
    { path: "c.js", finding: { type: "aws_access_key", match: "AKIA1234567890ABCDEF", line: 30, column: 1 } as F }, 
  ];
  const out = dedupByValue(in_);
  assert.equal(out.length, 1);
  assert.equal(out[0].path, "a.js");
  assert.equal(out[0].finding.duplicates?.length, 2);
});

test("dedupByValue keeps distinct values separate", () => {
  const in_ = [
    { path: "a.js", finding: { type: "aws_access_key", match: "AKIA11111111111", line: 1, column: 1 } as F },
    { path: "b.js", finding: { type: "aws_access_key", match: "AKIA22222222222", line: 1, column: 1 } as F },
  ];
  const out = dedupByValue(in_);
  assert.equal(out.length, 2);
});

test("dedupByValue does NOT merge same value from different types", () => {
  const in_ = [
    { path: "a.js", finding: { type: "aws_access_key", match: "samevalue1234567890", line: 1, column: 1 } as F },
    { path: "b.js", finding: { type: "generic_secret_assignment", match: "samevalue1234567890", line: 1, column: 1 } as F },
  ];
  const out = dedupByValue(in_);
  assert.equal(out.length, 2);
});
