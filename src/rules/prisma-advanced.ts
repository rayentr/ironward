import type { CodeRule } from "../engines/code-rules.js";

export const PRISMA_ADVANCED_RULES: CodeRule[] = [
  {
    id: "prisma-deletemany-no-where",
    severity: "critical",
    category: "prisma-drizzle" as any,
    confidence: 95,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "deleteMany() with no where clause (deletes every row)",
    re: /\.deleteMany\s*\(\s*(?:\)|\{\s*\}\s*\))/g,
    rationale: "deleteMany() or deleteMany({}) with no where clause wipes the entire table. A single bad call is catastrophic and uncoverable without backups.",
    fix: "Always pass a where clause: prisma.user.deleteMany({ where: { id: someId } }). For destructive bulk ops, gate by an explicit admin check.",
  },
  {
    id: "prisma-updatemany-no-where",
    severity: "critical",
    category: "prisma-drizzle" as any,
    confidence: 90,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "updateMany({ data: ... }) with no where clause (updates every row)",
    re: /\.updateMany\s*\(\s*\{[\s\S]{0,300}?\bdata\s*:[\s\S]{0,300}?\}\s*\)/g,
    negativePattern: /where\s*:/,
    rationale: "updateMany without a where clause rewrites every row in the table — a common cause of catastrophic data corruption (e.g. resetting all passwords or roles).",
    fix: "Always pair updateMany with a specific where clause. For admin bulk ops, log the affected ids before committing.",
  },
  {
    id: "prisma-nested-connect-user-input",
    severity: "high",
    category: "prisma-drizzle" as any,
    confidence: 85,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "Nested connect: { id: req.body.x } — IDOR via Prisma relation",  // ironward-ignore
    re: /connect\s*:\s*\{\s*id\s*:\s*(?:req|request|body|input)\s*\.\s*\w+/g,
    rationale: "Connecting a relation by an id taken straight from the request body lets an attacker attach their record to anyone else's (classic IDOR via Prisma).",
    fix: "Validate ownership before the connect: load the target id, check it belongs to the caller, then pass the verified id into connect.",
  },
  {
    id: "prisma-select-password",
    severity: "high",
    category: "prisma-drizzle" as any,
    confidence: 95,
    owasp: "A03:2021 Sensitive Data Exposure",
    languages: ["javascript", "typescript"],
    title: "Prisma select: { password: true } returns password hash",  // ironward-ignore
    re: /select\s*:\s*\{[^}]*\bpassword\s*:\s*true/g,
    rationale: "Selecting the password column pulls the hash into application memory and, very often, into the JSON response. The hash is then crackable offline.",
    fix: "Omit password from select. Read the hash only inside the auth code path that needs it (e.g. login), and never include it in responses.",
  },
  {
    id: "prisma-include-password",
    severity: "high",
    category: "prisma-drizzle" as any,
    confidence: 90,
    owasp: "A03:2021 Sensitive Data Exposure",
    languages: ["javascript", "typescript"],
    title: "Prisma include: { password: true } pulls the password hash via relation",  // ironward-ignore
    re: /include\s*:\s*\{[^}]*\bpassword\s*:\s*true/g,
    rationale: "Include with password: true loads the password column on a related record — same exposure as select, often in code paths that forget to strip it later.",
    fix: "Use include only for safe relations. For password verification, query the user table directly with a tight select and discard the hash before returning.",
  },
  // prisma-findmany-no-take moved to prisma.ts (deduped during 3.0.0 wiring)
];
