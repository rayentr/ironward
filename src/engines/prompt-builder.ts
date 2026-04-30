import { type ModelProfile, truncateCodeForModel } from "./model-profiles.js";

export interface PromptInput {
  tool: string;
  code: string;
  filePath?: string;
  extraContext?: Record<string, string>;
}

export interface BuiltPrompt {
  system: string;
  user: string;
}

interface ToolSpec {
  role: string;
  goal: string;
  jsonSchema: string;
  jsonTemplate: string;
}

const TOOL_SPECS: Record<string, ToolSpec> = {
  scan_auth_logic: {
    role: "an expert application-security auditor focused on authentication and authorization",
    goal: "Find authentication and authorization vulnerabilities (broken auth, missing checks, privilege escalation).",
    jsonSchema: `{ "findings": [ { "title": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "description": string, "fix": string } ] }`,
    jsonTemplate: `{"findings":[{"title":"...","severity":"high","line":1,"description":"...","fix":"..."}]}`,
  },
  scan_sqli: {
    role: "an expert SQL injection auditor",
    goal: "Find SQL injection vulnerabilities (string concatenation in queries, unsafe ORM usage, raw queries with user input).",
    jsonSchema: `{ "findings": [ { "title": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "sink": string, "tainted_input": string, "fix": string } ] }`,
    jsonTemplate: `{"findings":[{"title":"...","severity":"high","line":1,"sink":"db.query","tainted_input":"req.body.x","fix":"..."}]}`,
  },
  scan_xss: {
    role: "an expert XSS / DOM-injection auditor",
    goal: "Find cross-site scripting vulnerabilities (unescaped output, dangerouslySetInnerHTML, document.write with user input).",
    jsonSchema: `{ "findings": [ { "title": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "sink": string, "fix": string } ] }`,
    jsonTemplate: `{"findings":[{"title":"...","severity":"high","line":1,"sink":"innerHTML","fix":"..."}]}`,
  },
  scan_idor: {
    role: "an expert IDOR / broken-object-level-authorization auditor",
    goal: "Find IDOR vulnerabilities (object access without ownership checks, predictable IDs, missing tenant scoping).",
    jsonSchema: `{ "findings": [ { "title": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "object": string, "missing_check": string, "fix": string } ] }`,
    jsonTemplate: `{"findings":[{"title":"...","severity":"high","line":1,"object":"order","missing_check":"owner==user","fix":"..."}]}`,
  },
  fix_and_pr: {
    role: "an expert security fix author",
    goal: "Produce a minimal, safe code patch for the given vulnerability.",
    jsonSchema: `{ "patch": string, "explanation": string, "risk": "low"|"medium"|"high" }`,
    jsonTemplate: `{"patch":"...","explanation":"...","risk":"low"}`,
  },
};

const FALLBACK_SPEC: ToolSpec = {
  role: "an expert security auditor",
  goal: "Identify security vulnerabilities in the provided code.",
  jsonSchema: `{ "findings": [ { "title": string, "severity": string, "line": number, "description": string } ] }`,
  jsonTemplate: `{"findings":[{"title":"...","severity":"high","line":1,"description":"..."}]}`,
};

function specFor(tool: string): ToolSpec {
  return TOOL_SPECS[tool] ?? FALLBACK_SPEC;
}

export function jsonSchemaInstructionFor(tool: string): string {
  const spec = specFor(tool);
  return [
    "STRICT OUTPUT REQUIREMENT:",
    "- Return ONLY a single JSON object. No prose. No markdown fences.",
    "- The JSON MUST conform to this schema:",
    spec.jsonSchema,
    "- If you find no issues, return: {\"findings\":[]}",
  ].join("\n");
}

function buildOpusSystem(spec: ToolSpec): string {
  return [
    `You are ${spec.role}.`,
    "",
    `Goal: ${spec.goal}`,
    "",
    "Approach:",
    "1. Identify the trust boundaries — where untrusted input enters and where sensitive operations occur.",
    "2. Trace data flow from sources (request bodies, URL params, headers) to sinks.",
    "3. For each suspected issue, reason about exploitability: who can trigger it, what is the impact, what is the precondition.",
    "4. Prefer high-confidence findings. Note nuance (e.g. framework-default protections).",
    "5. Provide an actionable fix for each finding.",
    "",
    "Output schema:",
    spec.jsonSchema,
    "",
    "Return ONLY the JSON object, no markdown fences.",
  ].join("\n");
}

function buildSonnetSystem(spec: ToolSpec): string {
  return [
    `You are ${spec.role}. ${spec.goal}`,
    "",
    "- Trace untrusted input to dangerous sinks.",
    "- Report only high-confidence findings.",
    "- Each finding needs: title, severity, line, description, fix.",
    "",
    "JSON schema:",
    spec.jsonSchema,
    "",
    "Return ONLY the JSON object.",
  ].join("\n");
}

function buildHaikuSystem(spec: ToolSpec): string {
  return [
    `Task: ${spec.goal}`,
    "",
    "Output format (literal template — fill in the values):",
    spec.jsonTemplate,
    "",
    "Return ONLY this JSON, no other text.",
  ].join("\n");
}

function buildSystem(profile: ModelProfile, spec: ToolSpec): string {
  switch (profile.tier) {
    case "opus":
      return buildOpusSystem(spec);
    case "sonnet":
      return buildSonnetSystem(spec);
    case "haiku":
      return buildHaikuSystem(spec);
  }
}

export function buildPrompt(profile: ModelProfile, input: PromptInput): BuiltPrompt {
  const spec = specFor(input.tool);
  let system = buildSystem(profile, spec);
  if (profile.jsonReliability === "low") {
    system = `${system}\n\n${jsonSchemaInstructionFor(input.tool)}`;
  }

  const code = truncateCodeForModel(input.code, profile);
  const userParts: string[] = [];
  if (input.filePath) {
    userParts.push(`File: ${input.filePath}`);
  }
  if (input.extraContext) {
    for (const [k, v] of Object.entries(input.extraContext)) {
      userParts.push(`${k}: ${v}`);
    }
  }
  userParts.push("");
  userParts.push("Code to analyze:");
  userParts.push("```");
  userParts.push(code);
  userParts.push("```");

  return { system, user: userParts.join("\n") };
}
