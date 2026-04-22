// SSRF, open redirect, prototype pollution, CORS wildcard, weak JWT.

import express from "express";
import _ from "lodash";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
// NO helmet() call anywhere below.
app.use(cors({ origin: "*" }));

app.get("/proxy", async (req, res) => {
  // SSRF: attacker controls the URL our server fetches.
  const resp = await fetch(req.query.url);
  res.send(await resp.text());
});

app.get("/go", (req, res) => {
  // Open redirect.
  res.redirect(req.query.to);
});

app.post("/settings", (req, res) => {
  // Prototype pollution: merge of untrusted body.
  const settings = {};
  _.merge(settings, req.body);
  res.json(settings);
});

function issueToken(userId: string): string {
  // Critically weak JWT secret.
  return jwt.sign({ uid: userId }, "secret", { expiresIn: "30d" });
}

function decodeToken(token: string) {
  return jwt.verify(token, "secret", { algorithms: ["HS256", "none"] });
}

const header = { alg: "none", typ: "JWT" };
