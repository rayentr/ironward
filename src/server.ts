import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runScanSecrets, formatReport } from "./tools/scan-secrets.js";
import { runScanAuth, formatAuthReport, DEFAULT_AUTH_MODEL } from "./tools/scan-auth.js";
import { runScanSqli, formatSqliReport, DEFAULT_SQLI_MODEL } from "./tools/scan-sqli.js";
import { runScanXss, formatXssReport, DEFAULT_XSS_MODEL } from "./tools/scan-xss.js";
import { runScanIdor, formatIdorReport, DEFAULT_IDOR_MODEL } from "./tools/scan-idor.js";
import { runScanUrl, formatUrlReport } from "./tools/scan-url.js";
import { runScanCode, formatCodeReport } from "./tools/scan-code.js";
import { runScanDeps, formatDepsReport } from "./tools/scan-deps.js";
import { runFixAndPr, formatFixReport, DEFAULT_FIX_MODEL } from "./tools/fix-and-pr.js";
import { defaultValidator } from "./engines/fix-validator.js";
import { MissingApiKeyError } from "./engines/claude-client.js";
import { MissingGitHubTokenError } from "./engines/github-client.js";

const server = new McpServer(
  { name: "ironward", version: "1.1.0" },
  { capabilities: { tools: {} } },
);

const scanInputShape = {
  files: z
    .array(z.object({ path: z.string(), content: z.string() }))
    .optional()
    .describe("Array of files with inline content. Use this when the caller has the file text already."),
  paths: z
    .array(z.string())
    .optional()
    .describe("Absolute filesystem paths to read and scan. Use for on-disk scans."),
  content: z
    .string()
    .optional()
    .describe("Raw code snippet to scan. Use when there is no file context."),
  context: z
    .enum(["pre-commit", "on-save", "on-demand"])
    .optional()
    .describe("Invocation context. 'pre-commit' blocks on critical/high findings."),
};

server.registerTool(
  "scan_for_secrets",
  {
    title: "Scan for secrets",
    description:
      "Scan code for hardcoded secrets, API keys, tokens, private keys, and connection strings. " +
      "Runs fully offline using 24+ pattern families plus Shannon entropy analysis. " +
      "Returns findings with line numbers, severity, and remediation guidance. " +
      "Provide one of: files (inline), paths (on-disk), or content (snippet).",
    inputSchema: scanInputShape,
  },
  async (args) => {
    const result = await runScanSecrets(args);
    return {
      content: [
        { type: "text", text: formatReport(result) },
        {
          type: "text",
          text: "```json\n" + JSON.stringify(result, null, 2) + "\n```",
        },
      ],
      isError: result.summary.blocked,
    };
  },
);

const authInputShape = {
  code: z
    .string()
    .describe("The source code to analyze. Pass a full file or a self-contained function."),
  language: z
    .string()
    .optional()
    .describe("Language tag (e.g. 'typescript', 'python', 'go'). Improves analysis quality."),
  path: z
    .string()
    .optional()
    .describe("Optional file path for context in the report."),
  model: z
    .string()
    .optional()
    .describe(`Anthropic model ID. Defaults to ${DEFAULT_AUTH_MODEL}.`),
};

server.registerTool(
  "scan_auth_logic",
  {
    title: "Scan authentication and authorization logic",
    description:
      "Deep analysis of auth/authz defects using Claude Opus. Catches backwards checks, missing " +
      "ownership checks, privilege escalation, bypassable middleware, JWT validation gaps, " +
      "unsafe sessions, and password-reset flaws. Requires ANTHROPIC_API_KEY. " +
      "Out of scope: SQLi/XSS/secrets — those have dedicated tools.",
    inputSchema: authInputShape,
  },
  async (args) => {
    try {
      const result = await runScanAuth(args);
      return {
        content: [
          { type: "text", text: formatAuthReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      const message = err instanceof MissingApiKeyError ? err.message : (err as Error).message;
      return {
        content: [{ type: "text", text: `scan_auth_logic failed: ${message}` }],
        isError: true,
      };
    }
  },
);

const sqliInputShape = {
  code: z.string().describe("Source code to analyze."),
  language: z.string().optional().describe("Language tag (e.g. 'typescript', 'python'). Improves analysis quality."),
  path: z.string().optional().describe("Optional file path for context."),
  model: z.string().optional().describe(`Anthropic model ID. Defaults to ${DEFAULT_SQLI_MODEL}.`),
};

server.registerTool(
  "scan_sqli",
  {
    title: "Scan for SQL injection and unsafe query construction",
    description:
      "Detects SQL injection, ORM raw() misuse, second-order injection, and unsafe dynamic queries. " +
      "Uses a regex pre-filter to identify suspected query-construction sites, then Claude Sonnet confirms. " +
      "Skips the model entirely when no query-construction patterns are present. " +
      "Requires ANTHROPIC_API_KEY only when the pre-filter finds suspects.",
    inputSchema: sqliInputShape,
  },
  async (args) => {
    try {
      const result = await runScanSqli(args);
      return {
        content: [
          { type: "text", text: formatSqliReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      const message = err instanceof MissingApiKeyError ? err.message : (err as Error).message;
      return {
        content: [{ type: "text", text: `scan_sqli failed: ${message}` }],
        isError: true,
      };
    }
  },
);

const xssInputShape = {
  code: z.string().describe("Source code to analyze."),
  language: z.string().optional().describe("Language tag (e.g. 'typescript', 'jsx', 'vue', 'php')."),
  path: z.string().optional().describe("Optional file path for context."),
  model: z.string().optional().describe(`Anthropic model ID. Defaults to ${DEFAULT_XSS_MODEL}.`),
};

server.registerTool(
  "scan_xss",
  {
    title: "Scan for cross-site scripting (XSS)",
    description:
      "Detects reflected / stored / DOM XSS, framework-specific bypasses (dangerouslySetInnerHTML, v-html, Angular bypassSecurityTrust*, Svelte {@html}), " +
      "and template-engine injection (EJS <%- %>, Handlebars {{{ }}}, Jinja |safe). Uses a 25-rule cross-framework pre-filter and Claude Sonnet to confirm. " +
      "Files with no dangerous sinks skip the model entirely. Requires ANTHROPIC_API_KEY when the pre-filter finds suspects.",
    inputSchema: xssInputShape,
  },
  async (args) => {
    try {
      const result = await runScanXss(args);
      return {
        content: [
          { type: "text", text: formatXssReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      const message = err instanceof MissingApiKeyError ? err.message : (err as Error).message;
      return {
        content: [{ type: "text", text: `scan_xss failed: ${message}` }],
        isError: true,
      };
    }
  },
);

const idorInputShape = {
  code: z.string().describe("Source code to analyze."),
  language: z.string().optional().describe("Language tag (e.g. 'typescript', 'python', 'go')."),
  path: z.string().optional().describe("Optional file path for context."),
  model: z.string().optional().describe(`Anthropic model ID. Defaults to ${DEFAULT_IDOR_MODEL}.`),
};

server.registerTool(
  "scan_idor",
  {
    title: "Scan for broken access control (IDOR, mass assignment, unprotected admin)",
    description:
      "Deep analysis of broken access control — the #1 OWASP vulnerability. Detects missing ownership checks, " +
      "horizontal privilege escalation, mass assignment via req.body spread, predictable sequential IDs, " +
      "unprotected admin routes, and authorization decisions made on client-controlled role flags. Uses Claude Opus " +
      "for multi-step reasoning over the full request flow. Requires ANTHROPIC_API_KEY when the pre-filter " +
      "finds suspects.",
    inputSchema: idorInputShape,
  },
  async (args) => {
    try {
      const result = await runScanIdor(args);
      return {
        content: [
          { type: "text", text: formatIdorReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      const message = err instanceof MissingApiKeyError ? err.message : (err as Error).message;
      return {
        content: [{ type: "text", text: `scan_idor failed: ${message}` }],
        isError: true,
      };
    }
  },
);

const urlInputShape = {
  url: z.string().describe("Target URL to scan. Must be http(s)://…"),
  probeExposedFiles: z
    .boolean()
    .optional()
    .describe("Probe a small list of common dev/build files (.env, .git/config, .DS_Store). Default true."),
  probeErrors: z
    .boolean()
    .optional()
    .describe("Make one 404-style probe to detect stack-trace leakage. Default true."),
};

server.registerTool(
  "scan_url",
  {
    title: "Scan a deployed URL for runtime misconfigurations",
    description:
      "Audits a live HTTP(S) endpoint for missing security headers, weak CSP, insecure cookie flags, " +
      "overly permissive CORS, TLS enforcement, leaked stack traces, and a short allowlisted set of commonly-exposed " +
      "dev/build files (.env, .git/config, .DS_Store, firebase.json, .vscode). Network-only; no Claude call. " +
      "Only scan sites you own or are authorized to test.",
    inputSchema: urlInputShape,
  },
  async (args) => {
    try {
      const result = await runScanUrl(args);
      return {
        content: [
          { type: "text", text: formatUrlReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `scan_url failed: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

const codeInputShape = {
  files: z
    .array(z.object({ path: z.string(), content: z.string() }))
    .optional()
    .describe("Inline files to analyze."),
  paths: z.array(z.string()).optional().describe("Filesystem paths to read and scan."),
  content: z.string().optional().describe("Raw source snippet."),
};

server.registerTool(
  "scan_code",
  {
    title: "Static code analysis (offline, no AI)",
    description:
      "Pure pattern-based static analysis. 27 rules covering eval/exec with user input, SSRF, open redirects, " +
      "prototype pollution, weak crypto (MD5/SHA-1/DES/RC4), insecure random in secret contexts, hardcoded weak " +
      "JWT secrets, JWT alg=none, SQL string concatenation, CORS wildcards, missing rate limiting on auth " +
      "routes, stray debugger statements, secrets in console.log, and commented-out credentials. Zero API calls, " + // ironward-ignore
      "zero cost, instant.",
    inputSchema: codeInputShape,
  },
  async (args) => {
    const result = await runScanCode(args);
    return {
      content: [
        { type: "text", text: formatCodeReport(result) },
        { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
      ],
      isError: false,
    };
  },
);

const depsInputShape = {
  paths: z
    .array(z.string())
    .optional()
    .describe("Absolute paths to manifest files (package.json, requirements.txt, Pipfile.lock)."),
  manifests: z
    .array(z.object({ path: z.string(), content: z.string() }))
    .optional()
    .describe("Inline manifests: [{ path, content }]."),
};

server.registerTool(
  "scan_deps",
  {
    title: "Scan dependencies for known vulnerabilities",
    description:
      "Parses package.json / requirements.txt / Pipfile.lock and queries OSV.dev for CVEs. " +
      "Returns findings sorted by exploitability (CVSS base score), with CVE aliases, affected " +
      "ranges, fixed versions, and reference URLs. Offline parsing; a single HTTPS call per " +
      "unique dependency to api.osv.dev. Requires outbound network.",
    inputSchema: depsInputShape,
  },
  async (args) => {
    try {
      const result = await runScanDeps(args);
      return {
        content: [
          { type: "text", text: formatDepsReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `scan_deps failed: ${(err as Error).message}` }],
        isError: true,
      };
    }
  },
);

const fixInputShape = {
  repo: z.string().describe("GitHub repo slug, 'owner/repo'."),
  filePath: z
    .string()
    .optional()
    .describe("Single-file mode: path to the file to fix (legacy, still supported)."),
  fileContent: z
    .string()
    .optional()
    .describe("Single-file mode: current file contents. If omitted, fetched from GitHub."),
  files: z
    .array(z.object({ path: z.string(), content: z.string().optional() }))
    .optional()
    .describe(
      "Multi-file mode: [{ path, content? }]. Preferred for fixes that span multiple files (e.g. middleware + route). If content is omitted, the file is fetched from GitHub.",
    ),
  finding: z
    .object({
      name: z.string(),
      description: z.string().optional(),
      exploit: z.string().optional(),
      fix: z.string().optional(),
      severity: z.string().optional(),
      line: z.number().nullable().optional(),
      tool: z.string().optional(),
    })
    .describe("A finding from any Ironward scanner."),
  language: z.string().optional(),
  branchName: z.string().optional().describe("Branch to create. Auto-generated if omitted."),
  baseBranch: z.string().optional().describe("Base branch. Defaults to the repo's default branch."),
  commitMessage: z.string().optional(),
  model: z.string().optional().describe(`Anthropic model. Defaults to ${DEFAULT_FIX_MODEL}.`),
  dryRun: z
    .boolean()
    .optional()
    .describe("If true, propose the fix without creating a branch or PR. Defaults to false."),
  skipValidation: z
    .boolean()
    .optional()
    .describe("If true, skip the self-validation loop (re-running the scanner on the fix). Default false."),
  maxValidationAttempts: z
    .number()
    .int()
    .min(1)
    .max(3)
    .optional()
    .describe("Max fix + validate attempts before giving up. Default 2."),
};

server.registerTool(
  "fix_and_pr",
  {
    title: "Fix a finding (multi-file + self-validation) and open a pull request",
    description:
      "Given a finding from any Ironward scanner, uses Claude Opus to produce a minimal, surgical fix — potentially " +
      "across multiple files — validates the fix by re-running the relevant scanner, and opens a pull request. " +
      "Set `dryRun: true` to preview. Requires ANTHROPIC_API_KEY and (unless `dryRun` with inline content) " +
      "GITHUB_TOKEN with `repo` scope. PR body includes OWASP reference, exploit scenario, and validation status.",
    inputSchema: fixInputShape,
  },
  async (args) => {
    try {
      const result = await runFixAndPr(args, { validator: defaultValidator });
      return {
        content: [
          { type: "text", text: formatFixReport(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
        isError: false,
      };
    } catch (err) {
      const message =
        err instanceof MissingApiKeyError || err instanceof MissingGitHubTokenError
          ? err.message
          : (err as Error).message;
      return {
        content: [{ type: "text", text: `fix_and_pr failed: ${message}` }],
        isError: true,
      };
    }
  },
);

export async function startServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

export { server };
