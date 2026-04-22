// Clean code — scan_code should produce zero findings.

import { randomBytes, randomUUID, createHash } from "node:crypto";
import express from "express";
import helmet from "helmet";
import cors from "cors";

const app = express();
app.use(helmet());
app.use(cors({ origin: ["https://app.example.com", "https://admin.example.com"] }));

function resetToken(): string {
  return randomBytes(32).toString("base64url");
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

app.post("/login", require("express-rate-limit")({ windowMs: 60_000, max: 10 }), async (req, res) => {
  const id = randomUUID();
  res.json({ id });
});
