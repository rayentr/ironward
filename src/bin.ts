#!/usr/bin/env node
import { runCli } from "./cli.js";

runCli(process.argv).then(
  (code) => {
    if (typeof code === "number" && code !== 0) process.exit(code);
  },
  (err) => {
    console.error("ironward fatal:", err instanceof Error ? err.message : err);
    process.exit(1);
  },
);
