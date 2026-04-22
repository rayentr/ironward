import { scanText as scanSecretsText } from "./secret-engine.js";
import { findSqlSuspects } from "./sql-prefilter.js";
import { findXssSuspects } from "./xss-prefilter.js";
import { findIdorSuspects } from "./idor-prefilter.js";
import type { FileInput, FixFinding, Validator } from "../tools/fix-and-pr.js";

export const defaultValidator: Validator = {
  async validate(files: FileInput[], finding: FixFinding) {
    const tool = finding.tool;
    const residual: string[] = [];

    for (const f of files) {
      if (tool === "scan_for_secrets") {
        const findings = await scanSecretsText(f.content, f.path);
        for (const x of findings) {
          if (x.severity === "critical" || x.severity === "high") {
            residual.push(`${f.path}:${x.line} still flags ${x.type}`);
          }
        }
      } else if (tool === "scan_sqli") {
        for (const s of findSqlSuspects(f.content)) {
          residual.push(`${f.path}:${s.line} still SQL suspect — ${s.reason}`);
        }
      } else if (tool === "scan_xss") {
        for (const s of findXssSuspects(f.content)) {
          residual.push(`${f.path}:${s.line} still XSS suspect — ${s.reason}`);
        }
      } else if (tool === "scan_idor") {
        for (const s of findIdorSuspects(f.content)) {
          residual.push(`${f.path}:${s.line} still IDOR suspect — ${s.reason}`);
        }
      }
    }

    return { passed: residual.length === 0, residual };
  },
};
